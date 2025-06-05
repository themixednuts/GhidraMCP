package com.themixednuts.tools.datatypes;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

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
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Rename Data Type", category = ToolCategory.DATATYPES, description = "Renames an existing data type and/or moves it to a new category.", mcpName = "rename_data_type", mcpDescription = "Rename a data type and/or move it to a different category in a Ghidra program. Changes both the name and category path simultaneously.")
public class GhidraRenameDataTypeTool implements IGhidraMcpSpecification {

	public static final String ARG_NEW_DATATYPE_PATH = "newDataTypePath";

	private static record RenameContext(
			Program program,
			DataType dataType,
			CategoryPath newCategoryPath,
			String newSimpleName) {
	}

	/**
	 * Gets available data type paths for error suggestions.
	 */
	private List<String> getAvailableDataTypePaths(Program program) {
		List<String> paths = new ArrayList<>();
		Iterator<DataType> iterator = program.getDataTypeManager().getAllDataTypes();
		int count = 0;
		while (iterator.hasNext() && count < 50) { // Prevent overwhelming error messages
			paths.add(iterator.next().getPathName());
			count++;
		}
		return paths.stream().sorted().collect(Collectors.toList());
	}

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file."));
		schemaRoot.property(ARG_DATA_TYPE_PATH,
				JsonSchemaBuilder.string(mapper)
						.description("The current full path of the data type to rename/move (e.g., /MyCategory/MyType).")
						.pattern("^/.*"));
		schemaRoot.property(ARG_NEW_DATATYPE_PATH,
				JsonSchemaBuilder.string(mapper)
						.description(
								"The desired new full path for the data type (e.g., /NewCategory/NewName). This will set both the category and the simple name.")
						.pattern("^/.*"));

		schemaRoot.requiredProperty(ARG_FILE_NAME)
				.requiredProperty(ARG_DATA_TYPE_PATH)
				.requiredProperty(ARG_NEW_DATATYPE_PATH);

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool)
				.map(program -> { // .map for sync setup
					String oldPathString = getRequiredStringArgument(args, ARG_DATA_TYPE_PATH);
					String newFullDataTypePath = getRequiredStringArgument(args, ARG_NEW_DATATYPE_PATH);

					DataType dataType = program.getDataTypeManager().getDataType(oldPathString);

					if (dataType == null) {
						List<String> availablePaths = getAvailableDataTypePaths(program);

						GhidraMcpError error = GhidraMcpError.resourceNotFound()
								.errorCode(GhidraMcpError.ErrorCode.DATA_TYPE_NOT_FOUND)
								.message("Data type not found: " + oldPathString)
								.context(new GhidraMcpError.ErrorContext(
										getMcpName(),
										"data type lookup",
										Map.of(ARG_DATA_TYPE_PATH, oldPathString),
										Map.of("requestedPath", oldPathString, "pathExists", false),
										Map.of("totalDataTypes", availablePaths.size(), "searchedPath", oldPathString)))
								.suggestions(List.of(
										new GhidraMcpError.ErrorSuggestion(
												GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
												"List available data types",
												"Use tools to explore available data types",
												null,
												List.of("list_data_types", "list_categories")),
										new GhidraMcpError.ErrorSuggestion(
												GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
												"Use an existing data type path",
												"Select from available data types",
												availablePaths.isEmpty() ? List.of("/int", "/char")
														: availablePaths.subList(0, Math.min(10, availablePaths.size())),
												null)))
								.build();
						throw new GhidraMcpException(error);
					}

					CategoryPath newTargetFullPath = new CategoryPath(newFullDataTypePath);
					CategoryPath newTargetCategoryPath = newTargetFullPath.getParent();
					String newTargetSimpleName = newTargetFullPath.getName();

					if (newTargetSimpleName.isBlank()) {
						GhidraMcpError error = GhidraMcpError.validation()
								.errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
								.message("New data type name cannot be blank")
								.context(new GhidraMcpError.ErrorContext(
										getMcpName(),
										"name validation",
										Map.of(ARG_NEW_DATATYPE_PATH, newFullDataTypePath),
										Map.of("derivedName", newTargetSimpleName, "isBlank", true),
										Map.of("pathProvided", newFullDataTypePath, "nameValid", false)))
								.suggestions(List.of(
										new GhidraMcpError.ErrorSuggestion(
												GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
												"Provide a valid data type name",
												"Include a non-blank name in the path",
												List.of(
														"\"/MyCategory/MyValidName\"",
														"\"/MyCategory/MyStruct\"",
														"\"/MyEnum\""),
												null)))
								.build();
						throw new GhidraMcpException(error);
					}

					if (newTargetCategoryPath == null) {
						newTargetCategoryPath = CategoryPath.ROOT;
					}

					return new RenameContext(program, dataType, newTargetCategoryPath, newTargetSimpleName);
				})
				.flatMap(context -> { // .flatMap for transaction
					String oldPath = context.dataType().getPathName(); // Get old path before rename
					return executeInTransaction(context.program(), "Set Data Type Path: " + oldPath, () -> {
						context.dataType().setNameAndCategory(context.newCategoryPath(), context.newSimpleName());
						String finalPath = context.dataType().getPathName(); // Get path after rename/move
						return "Data type '" + oldPath + "' path set successfully to: " + finalPath;
					});
				});
	}
}