package com.themixednuts.tools.datatypes;

import java.util.Map;
import java.util.Optional;

import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
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

@GhidraMcpTool(key = "Delete Struct Member", category = "Data Types", description = "Enable the MCP tool to delete a struct member.", mcpName = "delete_struct_member", mcpDescription = "Deletes a member from a struct, identified by its offset.")
public class GhidraDeleteStructMemberTool implements IGhidraMcpSpecification {

	@Override
	public AsyncToolSpecification specification(PluginTool tool) {
		GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
		if (annotation == null) {
			Msg.error(this, "Missing @GhidraMcpTool annotation on " + this.getClass().getSimpleName());
			return null;
		}
		JsonSchema schemaObject = schema();
		Optional<String> schemaStringOpt = parseSchema(schemaObject);
		if (schemaStringOpt.isEmpty()) {
			Msg.error(this, "Failed to generate schema for tool '" + annotation.mcpName() + "'. Tool will be disabled.");
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
						.description("The full path of the struct containing the member (e.g., /MyCategory/MyStruct)"));

		schemaRoot.property("memberOffset",
				JsonSchemaBuilder.integer(mapper)
						.description("The offset (in bytes) of the member to delete.")
						.minimum(0)); // Offset cannot be negative

		schemaRoot.requiredProperty("fileName")
				.requiredProperty("structPath")
				.requiredProperty("memberOffset");

		return schemaRoot.build();
	}

	@Override
	public Mono<CallToolResult> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).flatMap(program -> {
			String structPathString = getRequiredStringArgument(args, "structPath");
			final Integer memberOffset = getRequiredIntArgument(args, "memberOffset"); // Final for lambda

			if (memberOffset < 0) {
				return createErrorResult("Invalid memberOffset: Cannot be negative.");
			}

			DataTypeManager dtm = program.getDataTypeManager();
			DataType dt = dtm.getDataType(structPathString);

			if (dt == null) {
				return createErrorResult("Struct not found at path: " + structPathString);
			}
			if (!(dt instanceof Structure)) {
				return createErrorResult("Data type at path is not a Structure: " + structPathString);
			}
			final Structure structDt = (Structure) dt; // Final for lambda

			DataTypeComponent component = structDt.getComponentAt(memberOffset);
			if (component == null) {
				return createErrorResult("No struct member found starting exactly at offset: " + memberOffset);
			}

			return executeInTransaction(program, "MCP - Delete Struct Member", () -> {
				structDt.deleteAtOffset(memberOffset);
				return createSuccessResult("Struct member at offset " + memberOffset + " deleted successfully.");
			});

		}).onErrorResume(e -> {
			return createErrorResult(e);
		});
	}

}