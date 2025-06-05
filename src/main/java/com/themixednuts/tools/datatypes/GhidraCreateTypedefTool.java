package com.themixednuts.tools.datatypes;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.tools.ToolCategory;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.TypedefDataType;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Create Typedef", mcpName = "create_typedef", category = ToolCategory.DATATYPES, description = "Creates a new typedef data type.", mcpDescription = "Create a new typedef data type in a Ghidra program. Typedefs create aliases for existing data types with optional pointer and array notation.")
public class GhidraCreateTypedefTool implements IGhidraMcpSpecification {

	protected static final String ARG_BASE_TYPE_PATH = "baseTypePath"; // Already in IGhidraMcpSpecification, but specific
																																			// to this tool's schema

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();

		schemaRoot.property(ARG_FILE_NAME, JsonSchemaBuilder.string(mapper)
				.description("The file name of the Ghidra tool window to target."), true);
		schemaRoot.property(ARG_NAME, JsonSchemaBuilder.string(mapper)
				.description("Name for the new typedef (e.g., MyTypedef)."), true);
		schemaRoot.property(ARG_PATH, JsonSchemaBuilder.string(mapper)
				.description(
						"Optional category path for the new typedef (e.g., /MyCategory). If omitted, uses default/root path."));
		schemaRoot.property(ARG_BASE_TYPE_PATH, JsonSchemaBuilder.string(mapper)
				.description(
						"Path to a base data type (e.g., 'dword', '/MyCategory/MyStruct', 'int[5]', 'char *'). Array and pointer notations are supported."),
				true);
		schemaRoot.property(ARG_COMMENT, JsonSchemaBuilder.string(mapper)
				.description("Optional comment for the new typedef."));

		schemaRoot.requiredProperty(ARG_FILE_NAME);
		schemaRoot.requiredProperty(ARG_NAME);
		schemaRoot.requiredProperty(ARG_BASE_TYPE_PATH);

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool)
				.flatMap(program -> {
					String typedefName = getRequiredStringArgument(args, ARG_NAME);
					Optional<String> pathOpt = getOptionalStringArgument(args, ARG_PATH);
					CategoryPath categoryPath = pathOpt.map(CategoryPath::new).orElse(CategoryPath.ROOT);
					String baseTypePath = getRequiredStringArgument(args, ARG_BASE_TYPE_PATH);
					Optional<String> commentOpt = getOptionalStringArgument(args, ARG_COMMENT);
					String transactionName = "Create Typedef: " + typedefName;

					return executeInTransaction(program, transactionName, () -> {
						DataTypeManager dtm = program.getDataTypeManager();
						ensureCategoryExists(dtm, categoryPath);
						return createTypedefInternal(dtm, typedefName, categoryPath, commentOpt, baseTypePath);
					});
				});
	}

	private String createTypedefInternal(DataTypeManager dtm, String typedefName, CategoryPath categoryPath,
			Optional<String> commentOpt, String baseTypePath) {
		GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);

		DataType baseDt = dtm.getDataType(baseTypePath);
		if (baseDt == null) {
			GhidraMcpError error = GhidraMcpError.resourceNotFound()
					.errorCode(GhidraMcpError.ErrorCode.DATA_TYPE_NOT_FOUND)
					.message("Base data type not found for TYPEDEF: " + baseTypePath)
					.context(new GhidraMcpError.ErrorContext(
							annotation.mcpName(),
							"typedef creation",
							Map.of(ARG_BASE_TYPE_PATH, baseTypePath),
							Map.of("baseTypePath", baseTypePath),
							Map.of("baseDataTypeExists", false)))
					.suggestions(List.of(
							new GhidraMcpError.ErrorSuggestion(
									GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
									"Check base data type path",
									"Verify the base data type exists",
									List.of("'dword'", "'/MyCategory/MyStruct'", "'int[5]'"),
									null),
							new GhidraMcpError.ErrorSuggestion(
									GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
									"List available data types",
									"See what data types are available",
									null,
									List.of(getMcpName(GhidraListDataTypesTool.class)))))
					.build();
			throw new GhidraMcpException(error);
		}

		if (dtm.getDataType(categoryPath, typedefName) != null) {
			GhidraMcpError error = GhidraMcpError.validation()
					.errorCode(GhidraMcpError.ErrorCode.CONFLICTING_ARGUMENTS)
					.message("Data type already exists: " + categoryPath.getPath() + CategoryPath.DELIMITER_CHAR + typedefName)
					.context(new GhidraMcpError.ErrorContext(
							annotation.mcpName(),
							"typedef creation",
							Map.of(ARG_NAME, typedefName, ARG_PATH, categoryPath.getPath()),
							Map.of("proposedTypedefPath", categoryPath.getPath() + CategoryPath.DELIMITER_CHAR + typedefName),
							Map.of("dataTypeExists", true, "categoryPath", categoryPath.getPath(), "typedefName", typedefName)))
					.suggestions(List.of(
							new GhidraMcpError.ErrorSuggestion(
									GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
									"Choose a different typedef name",
									"Use a unique name for the typedef",
									null,
									null),
							new GhidraMcpError.ErrorSuggestion(
									GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
									"Check existing data types",
									"List existing data types to avoid conflicts",
									null,
									List.of(getMcpName(GhidraListDataTypesTool.class)))))
					.build();
			throw new GhidraMcpException(error);
		}

		TypedefDataType newTypedef = new TypedefDataType(categoryPath, typedefName, baseDt, dtm);
		DataType newDt = dtm.addDataType(newTypedef, DataTypeConflictHandler.REPLACE_HANDLER);
		if (newDt == null) {
			throw new RuntimeException("Failed to add typedef '" + typedefName + "' to data type manager.");
		}
		commentOpt.ifPresent(comment -> newDt.setDescription(comment));
		return "Typedef '" + newDt.getPathName() + "' created.";
	}

	private static void ensureCategoryExists(DataTypeManager dtm, CategoryPath categoryPath) {
		if (categoryPath == null || categoryPath.equals(CategoryPath.ROOT)) {
			return;
		}
		if (dtm.getCategory(categoryPath) == null) {
			ghidra.program.model.data.Category created = dtm.createCategory(categoryPath);
			if (created == null) {
				// Attempt to re-fetch in case of race condition
				if (dtm.getCategory(categoryPath) == null) {
					throw new RuntimeException("Failed to create or find category: " + categoryPath.getPath());
				}
			}
		}
	}
}