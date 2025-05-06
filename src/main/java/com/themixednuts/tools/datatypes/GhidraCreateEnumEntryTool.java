package com.themixednuts.tools.datatypes;

import java.util.Map;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.tools.ToolCategory;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Enum;
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Create Enum Entry", category = ToolCategory.DATATYPES, description = "Adds a new entry to an existing enumeration.", mcpName = "create_enum_entry", mcpDescription = "Add a new name-value pair to an existing enum data type.")
public class GhidraCreateEnumEntryTool implements IGhidraMcpSpecification {

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(ARG_FILE_NAME, JsonSchemaBuilder.string(mapper).description("The name of the program file."));
		schemaRoot.property(ARG_ENUM_PATH, JsonSchemaBuilder.string(mapper)
				.description("Full path of the target enum (e.g., '/MyEnums/StatusCodes')."));
		schemaRoot.property(ARG_NAME, JsonSchemaBuilder.string(mapper).description("Name for the new enum entry."));
		schemaRoot.property(ARG_VALUE,
				JsonSchemaBuilder.integer(mapper).description("Value for the new enum entry (long)."));

		schemaRoot.requiredProperty(ARG_FILE_NAME)
				.requiredProperty(ARG_ENUM_PATH)
				.requiredProperty(ARG_NAME)
				.requiredProperty(ARG_VALUE);

		return schemaRoot.build();
	}

	private static record CreateEnumEntryContext(
			Program program, Enum targetEnum,
			String entryName,
			long entryValue) {
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) { // Ensure
																																																								// signature
		return getProgram(args, tool)
				.map(program -> { // .map for sync setup
					String enumPathStr = getRequiredStringArgument(args, ARG_ENUM_PATH);
					String entryName = getRequiredStringArgument(args, ARG_NAME);
					long entryValue = getRequiredLongArgument(args, ARG_VALUE);

					DataType dt = program.getDataTypeManager().getDataType(enumPathStr);

					if (dt == null) {
						throw new IllegalArgumentException("Enum not found: " + enumPathStr);
					}
					if (!(dt instanceof Enum)) {
						throw new IllegalArgumentException("Data type is not an enum: " + enumPathStr);
					}
					Enum targetEnum = (Enum) dt;

					return new CreateEnumEntryContext(program, targetEnum, entryName, entryValue);
				})
				.flatMap(context -> {
					String finalEnumPathString = context.targetEnum().getPathName();
					return executeInTransaction(context.program(), "Create Enum Entry: " + context.entryName(), () -> {
						context.targetEnum().add(context.entryName(), context.entryValue());
						return "Enum entry '" + context.entryName() + "' added successfully to " + finalEnumPathString;
					});
				});
	}
}