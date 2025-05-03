package com.themixednuts.tools.datatypes;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;
import com.themixednuts.tools.ToolCategory;

import ghidra.program.model.data.*;
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import ghidra.framework.plugintool.PluginTool;

@GhidraMcpTool(key = "Create Struct", category = ToolCategory.DATATYPES, description = "Creates a new struct data type.", mcpName = "create_struct", mcpDescription = "Defines a new struct data type, optionally pre-populated with members.")
public class GhidraCreateStructTool implements IGhidraMcpSpecification {

	// Simple record to hold resolved member details
	private record ResolvedStructMember(String name, DataType dataType, int size, Optional<Integer> offset,
			String comment) {
	}

	public GhidraCreateStructTool() {
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

		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The file name of the Ghidra tool window to target"));

		schemaRoot.property(ARG_STRUCT_PATH,
				JsonSchemaBuilder.string(mapper)
						.description("The full path for the new struct (e.g., /MyCategory/MyStruct)"));

		// Schema for a single member definition
		IObjectSchemaBuilder memberSchema = JsonSchemaBuilder.object(mapper)
				.description("Definition for a single struct member.")
				.property(ARG_NAME,
						JsonSchemaBuilder.string(mapper)
								.description("Name for the new member."))
				.property(ARG_DATA_TYPE_PATH,
						JsonSchemaBuilder.string(mapper)
								.description(
										"Full path or name of the member's data type (e.g., /Category/TypeName, or built-in like 'int', 'char*')."))
				.property(ARG_SIZE,
						JsonSchemaBuilder.integer(mapper)
								.description(
										"Optional explicit size for the member. If omitted, the default size of the member type is used.")
								.minimum(1))
				.property(ARG_OFFSET,
						JsonSchemaBuilder.integer(mapper)
								.description(
										"Optional offset within the struct to insert the member. If omitted, adds to the end.")
								.minimum(0))
				.property(ARG_COMMENT,
						JsonSchemaBuilder.string(mapper)
								.description("Optional comment for the new member."))
				.requiredProperty(ARG_NAME)
				.requiredProperty(ARG_DATA_TYPE_PATH);

		// Optional members array property
		schemaRoot.property("members",
				JsonSchemaBuilder.array(mapper)
						.items(memberSchema)
						.description("Optional list of members to add to the new struct."));

		schemaRoot.requiredProperty(ARG_FILE_NAME)
				.requiredProperty(ARG_STRUCT_PATH);

		return schemaRoot.build();
	}

	@Override
	public Mono<CallToolResult> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).flatMap(program -> {
			// Setup: Parse args, resolve path, check existence, ensure category, resolve
			// members
			// Argument parsing errors caught by onErrorResume
			String structPathString = getRequiredStringArgument(args, ARG_STRUCT_PATH);
			Optional<ArrayNode> membersOpt = getOptionalArrayNodeArgument(args, "members");

			CategoryPath categoryPath; // Not final here
			final String structName; // Final for lambda
			try {
				CategoryPath fullPath = new CategoryPath(structPathString);
				structName = fullPath.getName();
				categoryPath = fullPath.getParent();
				if (categoryPath == null) {
					categoryPath = CategoryPath.ROOT; // Default to root if only name is given
				}
				if (structName.isBlank()) {
					return createErrorResult("Invalid struct path: Name cannot be blank.");
				}
			} catch (IllegalArgumentException e) {
				return createErrorResult("Invalid struct path format: " + structPathString);
			}

			final DataTypeManager dtm = program.getDataTypeManager(); // Final for lambda

			// Check if data type already exists
			if (dtm.getDataType(structPathString) != null) {
				return createErrorResult("Data type already exists at path: " + structPathString);
			}

			// Resolve members (outside transaction)
			final List<ResolvedStructMember> resolvedMembers = new ArrayList<>(); // Final for lambda
			if (membersOpt.isPresent()) {
				ArrayNode membersArray = membersOpt.get();
				for (JsonNode memberNode : membersArray) {
					if (!memberNode.isObject()) {
						return createErrorResult("Invalid member definition: Expected an object.");
					}
					String memberName = getRequiredStringArgument(memberNode, ARG_NAME);
					String memberTypePath = getRequiredStringArgument(memberNode, ARG_DATA_TYPE_PATH);
					Optional<Integer> memberSizeOpt = getOptionalIntArgument(memberNode, ARG_SIZE);
					Optional<Integer> offsetOpt = getOptionalIntArgument(memberNode, ARG_OFFSET);
					String comment = getOptionalStringArgument(memberNode, ARG_COMMENT).orElse(null);

					DataType memberDataType = dtm.getDataType(memberTypePath);
					if (memberDataType == null) {
						return createErrorResult(
								"Data type not found for member '" + memberName + "': " + memberTypePath);
					}

					int size = memberSizeOpt.orElse(memberDataType.getLength());
					if (size <= 0) {
						size = memberDataType.getLength(); // Try default again if explicit size was invalid
						if (size <= 0) {
							return createErrorResult("Cannot determine valid size for member '" + memberName
									+ "' with type " + memberTypePath + ". Provide explicit size.");
						}
					}
					resolvedMembers
							.add(new ResolvedStructMember(memberName, memberDataType.clone(dtm), size, offsetOpt, comment));
				}
			}

			// Ensure category exists (can be done outside tx)
			dtm.createCategory(categoryPath);

			// --- Execute modification in transaction ---
			final String finalStructPathString = structPathString; // Capture for message
			final CategoryPath finalCategoryPath = categoryPath; // Capture for lambda
			return executeInTransaction(program, "MCP - Create Struct", () -> {
				// Inner Callable logic:
				// Create the new empty structure
				StructureDataType newStruct = new StructureDataType(finalCategoryPath, structName, 0, dtm);

				// Add resolved members
				for (ResolvedStructMember member : resolvedMembers) {
					try {
						if (member.offset().isPresent()) {
							newStruct.insertAtOffset(member.offset().get(), member.dataType(), member.size(), member.name(),
									member.comment());
						} else {
							newStruct.add(member.dataType(), member.size(), member.name(), member.comment());
						}
					} catch (IllegalArgumentException e) {
						// Handle specific error from add/insert
						return createErrorResult("Failed to add member '" + member.name() + "' to struct: " + e.getMessage());
					}
				}

				// Add the new structure to the manager
				DataType addedType = dtm.addDataType(newStruct, DataTypeConflictHandler.DEFAULT_HANDLER);

				if (addedType != null) {
					return createSuccessResult("Struct '" + finalStructPathString + "' created successfully.");
				} else {
					return createErrorResult(
							"Failed to add struct '" + finalStructPathString + "' after creation (unexpected conflict?).");
				}
			}); // End of Callable for executeInTransaction

		}).onErrorResume(e -> {
			// Catch errors from getProgram, setup (incl. arg parsing), or transaction
			// execution
			// Logging handled by createErrorResult
			return createErrorResult(e);
		});
	}
}