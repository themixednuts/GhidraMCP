package com.themixednuts.tools.datatypes;

import java.util.List;
import java.util.Map;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;
import com.themixednuts.tools.ToolCategory;

import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.EnumDataType;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataTypeManager;

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

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool)
				.flatMap(program -> executeInTransaction(program, "Delete Enum Entry", () -> {
					GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
					String enumPathString = getRequiredStringArgument(args, ARG_ENUM_PATH);
					String entryName = getRequiredStringArgument(args, ARG_NAME);

					DataTypeManager dtm = program.getDataTypeManager();
					DataType dataType = dtm.getDataType(enumPathString);

					if (dataType == null) {
						GhidraMcpError error = GhidraMcpError.resourceNotFound()
								.errorCode(GhidraMcpError.ErrorCode.DATA_TYPE_NOT_FOUND)
								.message("Enum not found at path: " + enumPathString)
								.context(new GhidraMcpError.ErrorContext(
										annotation.mcpName(),
										"enum lookup",
										Map.of(ARG_ENUM_PATH, enumPathString, ARG_NAME, entryName),
										Map.of("enumPath", enumPathString),
										Map.of("enumFound", false)))
								.suggestions(List.of(
										new GhidraMcpError.ErrorSuggestion(
												GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
												"List available enums",
												"Check what enums exist in the data type manager",
												null,
												List.of(getMcpName(GhidraListDataTypesTool.class)))))
								.build();
						throw new GhidraMcpException(error);
					}

					if (!(dataType instanceof EnumDataType)) {
						GhidraMcpError error = GhidraMcpError.validation()
								.errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
								.message("Data type at path is not an Enum: " + enumPathString)
								.context(new GhidraMcpError.ErrorContext(
										annotation.mcpName(),
										"data type validation",
										Map.of(ARG_ENUM_PATH, enumPathString),
										Map.of("actualType", dataType.getClass().getSimpleName()),
										Map.of("expectedType", "Enum", "actualType", dataType.getClass().getSimpleName())))
								.suggestions(List.of(
										new GhidraMcpError.ErrorSuggestion(
												GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
												"Verify data type",
												"Check that the path points to an enum data type",
												null,
												List.of(getMcpName(GhidraGetDataTypeTool.class)))))
								.build();
						throw new GhidraMcpException(error);
					}

					EnumDataType enumDataType = (EnumDataType) dataType;
					long entryValue = enumDataType.getValue(entryName);

					if (entryValue == -1 && !enumDataType.contains(entryName)) {
						GhidraMcpError error = GhidraMcpError.resourceNotFound()
								.errorCode(GhidraMcpError.ErrorCode.DATA_TYPE_NOT_FOUND)
								.message("Entry '" + entryName + "' not found in enum " + enumPathString)
								.context(new GhidraMcpError.ErrorContext(
										annotation.mcpName(),
										"enum entry lookup",
										Map.of(ARG_ENUM_PATH, enumPathString, ARG_NAME, entryName),
										Map.of("entryName", entryName),
										Map.of("entryExists", false)))
								.suggestions(List.of(
										new GhidraMcpError.ErrorSuggestion(
												GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
												"List enum entries",
												"Check what entries exist in this enum",
												null,
												List.of(getMcpName(GhidraGetDataTypeTool.class)))))
								.build();
						throw new GhidraMcpException(error);
					}

					enumDataType.remove(entryName);
					return "Entry '" + entryName + "' removed from enum '" + enumPathString + "'.";
				}));
	}

}