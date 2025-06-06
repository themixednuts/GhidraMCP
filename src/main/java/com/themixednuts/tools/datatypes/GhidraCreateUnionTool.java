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
import ghidra.program.model.data.UnionDataType;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Create Union", mcpName = "create_union", category = ToolCategory.DATATYPES, description = "Creates a new union data type.", mcpDescription = "Create a new union data type in a Ghidra program. Unions allow multiple data types to share the same memory location.")
public class GhidraCreateUnionTool implements IGhidraMcpSpecification {

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();

		schemaRoot.property(ARG_FILE_NAME, JsonSchemaBuilder.string(mapper)
				.description("The file name of the Ghidra tool window to target."), true);
		schemaRoot.property(ARG_NAME, JsonSchemaBuilder.string(mapper)
				.description("Name for the new union (e.g., MyUnion)."), true);
		schemaRoot.property(ARG_PATH, JsonSchemaBuilder.string(mapper)
				.description(
						"Optional category path for the new union (e.g., /MyCategory). If omitted, uses default/root path."));
		schemaRoot.property(ARG_COMMENT, JsonSchemaBuilder.string(mapper)
				.description("Optional comment for the new union."));

		schemaRoot.requiredProperty(ARG_FILE_NAME);
		schemaRoot.requiredProperty(ARG_NAME);

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool)
				.flatMap(program -> {
					String unionName = getRequiredStringArgument(args, ARG_NAME);
					Optional<String> pathOpt = getOptionalStringArgument(args, ARG_PATH);
					CategoryPath categoryPath = pathOpt.map(CategoryPath::new).orElse(CategoryPath.ROOT);
					Optional<String> commentOpt = getOptionalStringArgument(args, ARG_COMMENT);
					String transactionName = "Create Union: " + unionName;

					return executeInTransaction(program, transactionName, () -> {
						DataTypeManager dtm = program.getDataTypeManager();
						ensureCategoryExists(dtm, categoryPath);
						return createUnionInternal(dtm, unionName, categoryPath, commentOpt);
					});
				});
	}

	private String createUnionInternal(DataTypeManager dtm, String unionName, CategoryPath categoryPath,
			Optional<String> commentOpt) {
		GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);

		if (dtm.getDataType(categoryPath, unionName) != null) {
			GhidraMcpError error = GhidraMcpError.validation()
					.errorCode(GhidraMcpError.ErrorCode.CONFLICTING_ARGUMENTS)
					.message("Data type already exists: " + categoryPath.getPath() + CategoryPath.DELIMITER_CHAR + unionName)
					.context(new GhidraMcpError.ErrorContext(
							annotation.mcpName(),
							"union creation",
							Map.of(ARG_NAME, unionName, ARG_PATH, categoryPath.getPath()),
							Map.of("proposedUnionPath", categoryPath.getPath() + CategoryPath.DELIMITER_CHAR + unionName),
							Map.of("dataTypeExists", true, "categoryPath", categoryPath.getPath(), "unionName", unionName)))
					.suggestions(List.of(
							new GhidraMcpError.ErrorSuggestion(GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
									"Choose a different union name", null, null, null),
							new GhidraMcpError.ErrorSuggestion(GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
									"Use a different category path", null, null, null),
							new GhidraMcpError.ErrorSuggestion(GhidraMcpError.ErrorSuggestion.SuggestionType.USE_DIFFERENT_TOOL,
									"Check existing data types with list_data_types", null, null,
									List.of(getMcpName(GhidraListDataTypesTool.class)))))
					.build();
			throw new GhidraMcpException(error);
		}
		UnionDataType newUnion = new UnionDataType(categoryPath, unionName, dtm);
		DataType newDt = dtm.addDataType(newUnion, DataTypeConflictHandler.REPLACE_HANDLER);
		if (newDt == null) {
			throw new RuntimeException("Failed to add union '" + unionName + "' to data type manager.");
		}
		commentOpt.ifPresent(comment -> newDt.setDescription(comment));
		return "Union '" + newDt.getPathName() + "' created.";
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