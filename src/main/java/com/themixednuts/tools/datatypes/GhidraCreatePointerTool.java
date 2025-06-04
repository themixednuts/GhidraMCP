package com.themixednuts.tools.datatypes;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.models.PointerDetails;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.tools.ToolCategory;
import com.themixednuts.utils.GhidraMcpTaskMonitor;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;
import com.themixednuts.utils.DataTypeUtils;

import com.themixednuts.tools.datatypes.GhidraListDataTypesTool;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.TypedefDataType;
import ghidra.util.exception.CancelledException;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Create Pointer Type", category = ToolCategory.DATATYPES, description = "Creates a new named pointer data type (typedef to a pointer).", mcpName = "create_pointer_type", mcpDescription = "Create a new named pointer data type in a Ghidra program. Defines a typedef that points to an existing data type with optional size specification.")
public class GhidraCreatePointerTool implements IGhidraMcpSpecification {

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();

		schemaRoot.property(ARG_FILE_NAME, JsonSchemaBuilder.string(mapper)
				.description("The file name of the Ghidra tool window to target."), true);
		schemaRoot.property(ARG_NAME, JsonSchemaBuilder.string(mapper)
				.description("The name for the new pointer type (e.g., MyStructPtr)."), true);
		schemaRoot.property(ARG_DATA_TYPE_PATH, JsonSchemaBuilder.string(mapper)
				.description("The full path of the data type this pointer will point to (e.g., /int, /MyStruct)."), true);
		schemaRoot.property(ARG_CATEGORY_PATH, JsonSchemaBuilder.string(mapper)
				.description(
						"Optional. Category path where the new pointer type will be created (e.g., /MyPointers). Defaults to the category of the base data type or root if not specified."),
				false);
		schemaRoot.property(ARG_LENGTH, JsonSchemaBuilder.integer(mapper)
				.description(
						"Optional. Pointer size in bytes. A positive value sets a specific size. Omit or provide -1 for Ghidra's default pointer size."),
				false);
		schemaRoot.property(ARG_COMMENT, JsonSchemaBuilder.string(mapper)
				.description("Optional. A description for the new pointer type."), false);

		schemaRoot.requiredProperty(ARG_FILE_NAME);
		schemaRoot.requiredProperty(ARG_NAME);
		schemaRoot.requiredProperty(ARG_DATA_TYPE_PATH);

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool)
				.flatMap(program -> {
					String name = getRequiredStringArgument(args, ARG_NAME);
					String baseDataTypePathArg = getRequiredStringArgument(args, ARG_DATA_TYPE_PATH);
					Optional<String> categoryPathOpt = getOptionalStringArgument(args, ARG_CATEGORY_PATH);
					Optional<String> descriptionOpt = getOptionalStringArgument(args, ARG_COMMENT);
					int pointerLength = getOptionalIntArgument(args, ARG_LENGTH).orElse(-1); // -1 for default length

					GhidraMcpTaskMonitor monitor = new GhidraMcpTaskMonitor(ex,
							this.getClass().getAnnotation(GhidraMcpTool.class).mcpName());
					String transactionName = "Create Pointer Type: " + name;

					return executeInTransaction(program, transactionName, () -> {
						GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
						DataTypeManager dtm = program.getDataTypeManager();
						DataType pointedToDt;

						try {
							pointedToDt = DataTypeUtils.parseDataTypeString(program, baseDataTypePathArg, tool);
						} catch (IllegalArgumentException e) {
							GhidraMcpError error = GhidraMcpError.resourceNotFound()
									.errorCode(GhidraMcpError.ErrorCode.DATA_TYPE_NOT_FOUND)
									.message(
											"Base data type not found or invalid at path: '" + baseDataTypePathArg + "'. " + e.getMessage())
									.context(new GhidraMcpError.ErrorContext(
											annotation.mcpName(),
											"base data type parsing",
											Map.of(ARG_DATA_TYPE_PATH, baseDataTypePathArg),
											Map.of("baseDataTypePath", baseDataTypePathArg),
											Map.of("parseError", e.getMessage())))
									.suggestions(List.of(
											new GhidraMcpError.ErrorSuggestion(
													GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
													"Check base data type path",
													"Verify the base data type exists and path is correct",
													List.of("'/int'", "'/MyStruct'", "'dword'"),
													null),
											new GhidraMcpError.ErrorSuggestion(
													GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
													"List available data types",
													"See what data types are available",
													null,
													List.of(getMcpName(GhidraListDataTypesTool.class)))))
									.build();
							throw new GhidraMcpException(error);
						} catch (InvalidDataTypeException e) {
							GhidraMcpError error = GhidraMcpError.validation()
									.errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
									.message("Invalid base data type format for path: '" + baseDataTypePathArg + "'. " + e.getMessage())
									.context(new GhidraMcpError.ErrorContext(
											annotation.mcpName(),
											"data type format validation",
											Map.of(ARG_DATA_TYPE_PATH, baseDataTypePathArg),
											Map.of("baseDataTypePath", baseDataTypePathArg),
											Map.of("formatError", e.getMessage())))
									.suggestions(List.of(
											new GhidraMcpError.ErrorSuggestion(
													GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
													"Check data type format",
													"Use correct data type path format",
													List.of("'/int'", "'dword'", "'/MyCategory/MyStruct'"),
													null),
											new GhidraMcpError.ErrorSuggestion(
													GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
													"List available data types",
													"See what data types are available",
													null,
													List.of(getMcpName(GhidraListDataTypesTool.class)))))
									.build();
							throw new GhidraMcpException(error);
						} catch (CancelledException e) {
							throw new RuntimeException("Parsing cancelled for base data type path '" + baseDataTypePathArg + "'.", e);
						} catch (RuntimeException e) {
							throw new RuntimeException(
									"Unexpected error parsing base data type path '" + baseDataTypePathArg + "': " + e.getMessage(), e);
						}

						// Get an anonymous PointerDataType instance (cached if possible)
						Pointer actualPointerDt = dtm.getPointer(pointedToDt, pointerLength);
						if (actualPointerDt == null) {
							// This should ideally not happen if pointedToDt is valid and dtm is functional
							throw new RuntimeException("Failed to create or retrieve pointer for data type: " + baseDataTypePathArg);
						}

						CategoryPath actualCategoryPath;
						if (categoryPathOpt.isPresent() && !categoryPathOpt.get().isBlank()) {
							actualCategoryPath = new CategoryPath(categoryPathOpt.get());
						} else {
							// Default to the category of the base type, or root if base type is at root
							actualCategoryPath = pointedToDt.getCategoryPath();
							if (actualCategoryPath == null || actualCategoryPath.isRoot()) {
								actualCategoryPath = CategoryPath.ROOT; // Fallback if needed, though usually name determines path if
																												// category is ROOT
							}
						}

						// Check if a type with this name already exists at the target category path
						DataType existingType = dtm.getDataType(actualCategoryPath, name);
						if (existingType != null) {
							GhidraMcpError error = GhidraMcpError.validation()
									.errorCode(GhidraMcpError.ErrorCode.CONFLICTING_ARGUMENTS)
									.message("Data type '" + name + "' already exists at category '" + actualCategoryPath + "'.")
									.context(new GhidraMcpError.ErrorContext(
											annotation.mcpName(),
											"pointer type creation",
											Map.of(ARG_NAME, name, ARG_CATEGORY_PATH, actualCategoryPath.getPath()),
											Map.of("proposedName", name, "categoryPath", actualCategoryPath.getPath()),
											Map.of("dataTypeExists", true, "existingType", existingType.getDisplayName())))
									.suggestions(List.of(
											new GhidraMcpError.ErrorSuggestion(
													GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
													"Choose a different name",
													"Use a unique name for the pointer type",
													null,
													null),
											new GhidraMcpError.ErrorSuggestion(
													GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
													"List data types to avoid conflicts",
													"List data types to avoid conflicts",
													null,
													List.of(getMcpName(GhidraListDataTypesTool.class)))))
									.build();
							throw new GhidraMcpException(error);
						}

						TypedefDataType newPointerTypedef = new TypedefDataType(actualCategoryPath, name, actualPointerDt, dtm);
						descriptionOpt.ifPresent(newPointerTypedef::setDescription);

						DataType resolvedType = dtm.addDataType(newPointerTypedef, null);
						monitor.incrementProgress(1);

						return new com.themixednuts.models.TypedefDetails((ghidra.program.model.data.TypeDef) resolvedType);
					});
				});
	}
}