package com.themixednuts.tools.datatypes;

import java.util.Map;
import java.util.Optional;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.framework.plugintool.PluginTool;
import ghidra.util.Msg;
import ghidra.program.model.data.*;

import io.modelcontextprotocol.server.McpAsyncServerExchange;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;

import reactor.core.publisher.Mono;

@GhidraMcpTool(key = "Add Enum Entry", category = "Data Types", description = "Enable the MCP tool to add an entry to an existing enum.", mcpName = "add_enum_entry", mcpDescription = "Adds a new name/value pair entry to an existing enum.")
public class GhidraAddEnumEntryTool implements IGhidraMcpSpecification {

	@Override
	public AsyncToolSpecification specification(PluginTool tool) {
		GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
		if (annotation == null) {
			Msg.error(this, "Missing @GhidraMcpTool annotation on " + this.getClass().getSimpleName());
			return null;
		}

		Optional<String> schemaStringOpt = parseSchema(schema());
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
				JsonSchemaBuilder.string(mapper).description("The file name of the Ghidra tool window to target"));
		schemaRoot.property("enumPath", JsonSchemaBuilder.string(mapper)
				.description("The full path of the enum to add the entry to (e.g., /MyCategory/MyEnum)"));
		schemaRoot.property("entryName",
				JsonSchemaBuilder.string(mapper).description("The name for the new enum entry"));
		schemaRoot.property("entryValue",
				JsonSchemaBuilder.integer(mapper).description("The integer value for the new enum entry"));
		schemaRoot.property("entryComment",
				JsonSchemaBuilder.string(mapper).description("Optional comment for the new enum entry"));
		schemaRoot.requiredProperty("fileName").requiredProperty("enumPath").requiredProperty("entryName")
				.requiredProperty("entryValue");

		return schemaRoot.build();
	}

	@Override
	public Mono<CallToolResult> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).flatMap(program -> {
			String enumPathString = getRequiredStringArgument(args, "enumPath");
			String entryName = getRequiredStringArgument(args, "entryName");
			Long entryValue = getRequiredLongArgument(args, "entryValue");
			String entryComment = getOptionalStringArgument(args, "entryComment").orElse(null);

			DataTypeManager dtm = program.getDataTypeManager();
			DataType dt = dtm.getDataType(enumPathString);

			if (dt == null) {
				return createErrorResult("Enum not found at path: " + enumPathString);
			}
			if (!(dt instanceof EnumDataType)) {
				return createErrorResult("Data type at path is not an Enum: " + enumPathString);
			}

			final EnumDataType enumDt = (EnumDataType) dt;

			return executeInTransaction(program, "MCP - Add Enum Entry", () -> {
				enumDt.add(entryName, entryValue, entryComment);
				return createSuccessResult("Enum entry '" + entryName + "' added successfully to " + enumPathString + ".");
			});
		}).onErrorResume(e -> createErrorResult(e));
	}
}