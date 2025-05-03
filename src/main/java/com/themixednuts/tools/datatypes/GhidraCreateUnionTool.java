package com.themixednuts.tools.datatypes;

import java.util.Map;
import java.util.Optional;
import java.util.ArrayList;
import java.util.List;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import reactor.core.publisher.Mono;

import ghidra.program.model.data.*;
import ghidra.framework.plugintool.PluginTool;
import com.themixednuts.tools.ToolCategory;

@GhidraMcpTool(key = "Create Union", category = ToolCategory.DATATYPES, description = "Creates a new union data type.", mcpName = "create_union", mcpDescription = "Defines a new union data type, optionally pre-populated with members.")
public class GhidraCreateUnionTool implements IGhidraMcpSpecification {

	private record ResolvedMember(String name, DataType dataType, String comment) {
	}

	@Override
	public AsyncToolSpecification specification(PluginTool tool) {
		GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
		if (annotation == null) {
			Msg.error(this, "Missing @GhidraMcpTool annotation on " + this.getClass().getSimpleName());
			return null;
		}
		JsonSchema schemaObject = schema();
		Optional<String> schemaStringOpt = schemaObject.toJsonString(mapper);
		if (schemaStringOpt.isEmpty()) {
			Msg.error(this, "Failed to serialize schema for tool '" + annotation.mcpName() + "'. Tool will be disabled.");
			return null;
		}
		String schemaJson = schemaStringOpt.get();

		return new AsyncToolSpecification(
				new Tool(annotation.mcpName(), annotation.mcpDescription(), schemaJson),
				(ex, args) -> execute(ex, args, tool));
	}

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();

		schemaRoot.property("fileName",
				JsonSchemaBuilder.string(mapper)
						.description("The file name of the Ghidra tool window to target"));

		schemaRoot.property("unionPath",
				JsonSchemaBuilder.string(mapper)
						.description("The full path for the new union (e.g., /MyCategory/MyUnion)"));

		// Schema for a single member definition
		IObjectSchemaBuilder memberSchema = JsonSchemaBuilder.object(mapper)
				.description("Definition for a single union member.")
				.property("memberName",
						JsonSchemaBuilder.string(mapper)
								.description("Name for the new member."))
				.property("memberTypePath",
						JsonSchemaBuilder.string(mapper)
								.description("Full path or name of the member's data type (e.g., 'dword', '/MyStruct')."))
				.property("comment",
						JsonSchemaBuilder.string(mapper)
								.description("Optional comment for the new member."))
				.requiredProperty("memberName")
				.requiredProperty("memberTypePath");

		// Optional members array property
		schemaRoot.property("members",
				JsonSchemaBuilder.array(mapper)
						.items(memberSchema)
						.description("Optional list of members to add to the new union."));

		schemaRoot.requiredProperty("fileName")
				.requiredProperty("unionPath");

		return schemaRoot.build();
	}

	@Override
	public Mono<CallToolResult> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).flatMap(program -> {
			String unionPathString = getRequiredStringArgument(args, "unionPath");
			Optional<ArrayNode> membersOpt = getOptionalArrayNodeArgument(args, "members");

			CategoryPath categoryPath; // Not final here
			final String unionName; // Final for lambda
			CategoryPath fullPath = new CategoryPath(unionPathString);
			unionName = fullPath.getName();
			categoryPath = fullPath.getParent();
			if (categoryPath == null) {
				categoryPath = CategoryPath.ROOT;
			}
			if (unionName.isBlank()) {
				return createErrorResult("Invalid union path: Name cannot be blank.");
			}

			final DataTypeManager dtm = program.getDataTypeManager(); // Final for lambda

			// Check if data type already exists
			if (dtm.getDataType(unionPathString) != null) {
				return createErrorResult("Data type already exists at path: " + unionPathString);
			}

			// Resolve members (outside transaction)
			final List<ResolvedMember> resolvedMembers = new ArrayList<>(); // Final for lambda
			if (membersOpt.isPresent()) {
				ArrayNode membersArray = membersOpt.get();
				for (JsonNode memberNode : membersArray) {
					if (!memberNode.isObject()) {
						return createErrorResult("Invalid member definition: Expected an object.");
					}
					String memberName = getRequiredStringArgument(memberNode, "memberName");
					String memberTypePath = getRequiredStringArgument(memberNode, "memberTypePath");
					String comment = getOptionalStringArgument(memberNode, "comment").orElse(null);

					DataType memberDataType = dtm.getDataType(memberTypePath);
					if (memberDataType == null) {
						return createErrorResult(
								"Data type not found for member '" + memberName + "': " + memberTypePath);
					}
					resolvedMembers.add(new ResolvedMember(memberName, memberDataType.clone(dtm), comment));
				}
			}

			// Ensure category exists (can be done outside tx)
			dtm.createCategory(categoryPath);

			// --- Execute modification in transaction ---
			final String finalUnionPathString = unionPathString; // Capture for message
			final CategoryPath finalCategoryPath = categoryPath; // Capture for lambda
			return executeInTransaction(program, "MCP - Create Union", () -> {
				UnionDataType newUnion = new UnionDataType(finalCategoryPath, unionName, dtm);

				// Add resolved members
				for (ResolvedMember member : resolvedMembers) {
					newUnion.add(member.dataType(), member.name(), member.comment());
				}

				// Add the new union to the manager
				DataType addedType = dtm.addDataType(newUnion, DataTypeConflictHandler.DEFAULT_HANDLER);

				if (addedType != null) {
					return createSuccessResult("Union '" + finalUnionPathString + "' created successfully.");
				} else {
					return createErrorResult(
							"Failed to add union '" + finalUnionPathString + "' after creation (unexpected conflict?).");
				}
			});

		}).onErrorResume(e -> {
			return createErrorResult(e);
		});
	}

}