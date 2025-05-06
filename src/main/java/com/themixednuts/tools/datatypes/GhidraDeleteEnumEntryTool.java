package com.themixednuts.tools.datatypes;

import java.util.Map;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;
import com.themixednuts.tools.ToolCategory;

import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.listing.Program;
import ghidra.framework.plugintool.PluginTool;

@GhidraMcpTool(name = "Delete Enum Entry", category = ToolCategory.DATATYPES, description = "Deletes an entry from an existing enum.", mcpName = "delete_enum_entry", mcpDescription = "Removes an entry (by name) from an existing enum data type.")
public class GhidraDeleteEnumEntryTool implements IGhidraMcpSpecification {

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();

		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The file name of the Ghidra tool window to target"));

		schemaRoot.property(ARG_ENUM_PATH,
				JsonSchemaBuilder.string(mapper)
						.description("The full path of the enum containing the entry (e.g., /MyCategory/MyEnum)"));

		schemaRoot.property(ARG_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the enum entry to delete."));

		schemaRoot.requiredProperty(ARG_FILE_NAME)
				.requiredProperty(ARG_ENUM_PATH)
				.requiredProperty(ARG_NAME);

		return schemaRoot.build();
	}

	private static record DeleteEnumEntryContext(
			Program program,
			EnumDataType enumDt,
			String entryName) {
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).map(program -> {
			String enumPathString = getRequiredStringArgument(args, ARG_ENUM_PATH);
			String entryName = getRequiredStringArgument(args, ARG_NAME);

			DataType dt = program.getDataTypeManager().getDataType(enumPathString);

			if (dt == null) {
				throw new IllegalArgumentException("Enum not found at path: " + enumPathString);
			}
			if (!(dt instanceof EnumDataType)) {
				throw new IllegalArgumentException("Data type at path is not an Enum: " + enumPathString);
			}
			EnumDataType enumDt = (EnumDataType) dt;

			if (!enumDt.contains(entryName)) {
				throw new IllegalArgumentException("Entry '" + entryName + "' not found in enum " + enumPathString);
			}

			return new DeleteEnumEntryContext(program, enumDt, entryName);
		}).flatMap(context -> {
			String finalEnumPathString = context.enumDt().getPathName();

			return executeInTransaction(context.program(), "MCP - Delete Enum Entry: " + context.entryName(), () -> {
				context.enumDt().remove(context.entryName());
				return "Enum entry '" + context.entryName() + "' deleted successfully from " + finalEnumPathString + ".";
			});
		});
	}

}