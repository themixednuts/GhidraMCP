package com.themixednuts.tools.datatypes;

import java.util.Map;
import java.util.Optional;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;
import com.themixednuts.tools.ToolCategory;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Structure;
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import reactor.core.publisher.Mono;

@GhidraMcpTool(key = "Add Struct Member", category = ToolCategory.DATATYPES, description = "Adds a member to an existing structure.", mcpName = "add_struct_member", mcpDescription = "Adds a new field (member) to an existing struct data type at a specified offset.")
public class GhidraAddStructMemberTool implements IGhidraMcpSpecification {

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
		schemaRoot.property("structPath",
				JsonSchemaBuilder.string(mapper)
						.description("The full path of the structure to modify (e.g., /MyCategory/MyStruct)"));
		schemaRoot.property("memberName",
				JsonSchemaBuilder.string(mapper)
						.description("Name for the new member."));
		schemaRoot.property("memberTypePath",
				JsonSchemaBuilder.string(mapper)
						.description("Full path or name of the member's data type (e.g., 'dword', '/MyOtherStruct')."));
		schemaRoot.property("offset",
				JsonSchemaBuilder.integer(mapper)
						.description("Optional offset for the new member within the struct. If omitted, the member is appended."));
		schemaRoot.property("comment",
				JsonSchemaBuilder.string(mapper)
						.description("Optional comment for the new member."));

		schemaRoot.requiredProperty("fileName")
				.requiredProperty("structPath")
				.requiredProperty("memberName")
				.requiredProperty("memberTypePath");

		return schemaRoot.build();
	}

	@Override
	public Mono<CallToolResult> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).flatMap(program -> {
			String structPathString = getRequiredStringArgument(args, "structPath");
			final String memberName = getRequiredStringArgument(args, "memberName");
			String memberTypePath = getRequiredStringArgument(args, "memberTypePath");
			final Optional<Integer> offsetOpt = getOptionalIntArgument(args, "offset");
			final Optional<String> commentOpt = getOptionalStringArgument(args, "comment");

			DataTypeManager dtm = program.getDataTypeManager();
			DataType dt = dtm.getDataType(structPathString);

			if (dt == null) {
				return createErrorResult("Structure not found at path: " + structPathString);
			}
			if (!(dt instanceof Structure)) {
				return createErrorResult("Data type at path is not a Structure: " + structPathString);
			}
			final Structure struct = (Structure) dt;

			final DataType memberDataType = dtm.getDataType(memberTypePath);
			if (memberDataType == null) {
				return createErrorResult("Data type not found for member: " + memberTypePath);
			}

			final int memberSize = memberDataType.getLength();
			if (memberSize <= 0) {
				return createErrorResult("Cannot add member with dynamically sized type: " + memberTypePath);
			}

			final String finalStructPathString = structPathString;
			return executeInTransaction(program, "MCP - Add Struct Member", () -> {
				// Inner Callable logic (just the modification):
				if (offsetOpt.isPresent()) {
					int offset = offsetOpt.get();
					struct.insert(offset, memberDataType, memberSize, memberName, commentOpt.orElse(null));
				} else {
					struct.add(memberDataType, memberName, commentOpt.orElse(null));
				}
				return createSuccessResult(
						"Member '" + memberName + "' added to structure '" + finalStructPathString + "'.");
			});
		}).onErrorResume(e -> createErrorResult(e));
	}
}