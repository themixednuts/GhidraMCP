package com.themixednuts.tools.datatypes;

import java.util.Map;
import java.util.Optional;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;
import com.themixednuts.tools.ToolCategory;

import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import reactor.core.publisher.Mono;
import ghidra.program.model.data.*;
import ghidra.framework.plugintool.PluginTool;

@GhidraMcpTool(name = "Add Union Member", mcpName = "add_union_member", category = ToolCategory.DATATYPES, description = "Adds a new member to an existing union data type.", mcpDescription = "Adds a new field (member) to an existing union data type.")
public class GhidraCreateUnionMemberTool implements IGhidraMcpSpecification {

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

		schemaRoot.property(ARG_UNION_PATH,
				JsonSchemaBuilder.string(mapper)
						.description("The full path of the union to add the member to (e.g., /MyCategory/MyUnion)"));

		schemaRoot.property(ARG_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name for the new member."));

		schemaRoot.property(ARG_DATA_TYPE_PATH,
				JsonSchemaBuilder.string(mapper)
						.description("Full path or name of the member's data type (e.g., 'dword', '/MyStruct')."));

		schemaRoot.property(ARG_COMMENT,
				JsonSchemaBuilder.string(mapper)
						.description("Optional comment for the new member."));

		schemaRoot.requiredProperty(ARG_FILE_NAME)
				.requiredProperty(ARG_UNION_PATH)
				.requiredProperty(ARG_NAME)
				.requiredProperty(ARG_DATA_TYPE_PATH);

		return schemaRoot.build();
	}

	@Override
	public Mono<CallToolResult> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).flatMap(program -> {
			String unionPathString = getRequiredStringArgument(args, ARG_UNION_PATH);
			final String memberName = getRequiredStringArgument(args, ARG_NAME);
			String memberTypePath = getRequiredStringArgument(args, ARG_DATA_TYPE_PATH);
			final String comment = getOptionalStringArgument(args, ARG_COMMENT).orElse(null);

			DataTypeManager dtm = program.getDataTypeManager();
			DataType dt = dtm.getDataType(unionPathString);

			if (dt == null) {
				return createErrorResult("Union not found at path: " + unionPathString);
			}
			if (!(dt instanceof Union)) {
				return createErrorResult("Data type at path is not a Union: " + unionPathString);
			}
			final Union unionDt = (Union) dt;

			final DataType memberDataType = dtm.getDataType(memberTypePath);
			if (memberDataType == null) {
				return createErrorResult("Member data type not found: " + memberTypePath);
			}

			final String finalUnionPathString = unionPathString;
			return executeInTransaction(program, "MCP - Add Union Member", () -> {
				DataTypeComponent addedComponent = unionDt.add(memberDataType, memberName, comment);

				if (addedComponent != null) {
					return createSuccessResult(
							"Member '" + memberName + "' added successfully to union " + finalUnionPathString + ".");
				} else {
					return createErrorResult("Failed to add member '" + memberName + "' to union " + finalUnionPathString
							+ ". Name/type conflict or other issue?");
				}
			});
		}).onErrorResume(e -> createErrorResult(e));
	}
}