package com.themixednuts.tools;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.DataTypeDeleteResult;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.Category;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.common.McpTransportContext;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Map;
import java.util.Optional;

@GhidraMcpTool(name = "Delete Data Type", description = "Delete data types (structs, enums, unions, typedefs, pointers, function definitions) and categories.", mcpName = "delete_data_type", mcpDescription = """
        <use_case>
        Deletes data types and categories from the program. Use this when you need to remove
        incorrect data type definitions, clean up unused types, or reorganize the data type
        manager. Handles both regular data types and category deletion.
        </use_case>

        <important_notes>
        - CRITICAL: If you plan to delete a data type and then create/recreate it, use ManageDataTypesTool with 'update' action instead to preserve existing references
        - Supports data type identification by ID or name + category path
        - For categories, provide the parent category path and the category name to delete
        - Category deletion requires the category to be empty
        - Data type deletion is permanent and cannot be undone without undo/redo
        - Some built-in data types may be protected and cannot be deleted
        - Deleting a data type may affect other types that reference it
        - Deleting and recreating will break all existing references to this type; use 'update' to preserve references
        </important_notes>

        <examples>
        Delete a data type by ID:
        {
          "fileName": "program.exe",
          "data_type_kind": "struct",
          "data_type_id": 12345
        }

        Delete a data type by name:
        {
          "fileName": "program.exe",
          "data_type_kind": "struct",
          "name": "MyStruct",
          "category_path": "/MyTypes"
        }

        Delete an empty category:
        {
          "fileName": "program.exe",
          "data_type_kind": "category",
          "name": "OldCategory",
          "category_path": "/MyTypes"
        }
        </examples>
        """)
public class DeleteDataTypeTool implements IGhidraMcpSpecification {

    public static final String ARG_DATA_TYPE_KIND = "data_type_kind";
    public static final String ARG_NAME = "name";
    public static final String ARG_CATEGORY_PATH = "category_path";
    public static final String ARG_DATA_TYPE_ID = "data_type_id";

    @Override
    public JsonSchema schema() {
        IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();

        schemaRoot.property(ARG_FILE_NAME,
                JsonSchemaBuilder.string(mapper)
                        .description("The name of the program file."));

        schemaRoot.property(ARG_DATA_TYPE_KIND, JsonSchemaBuilder.string(mapper)
                .enumValues("struct", "enum", "union", "typedef", "pointer", "function_definition", "category")
                .description("Type of data type to delete"));

        schemaRoot.property(ARG_NAME, JsonSchemaBuilder.string(mapper)
                .description("Name of the data type or category to delete"));

        schemaRoot.property(ARG_CATEGORY_PATH, JsonSchemaBuilder.string(mapper)
                .description(
                        "For non-category data types: full category path. For category operations: parent category path (default '/').")
                .defaultValue("/"));

        schemaRoot.property(ARG_DATA_TYPE_ID, JsonSchemaBuilder.integer(mapper)
                .description("Optional: Data type ID for direct lookup by internal ID"));

        schemaRoot.requiredProperty(ARG_FILE_NAME)
                .requiredProperty(ARG_DATA_TYPE_KIND)
                .requiredProperty(ARG_NAME);

        return schemaRoot.build();
    }

    @Override
    public Mono<? extends Object> execute(McpTransportContext context, Map<String, Object> args, PluginTool tool) {
        GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);

        return getProgram(args, tool).flatMap(program -> {
            String dataTypeKind = getRequiredStringArgument(args, ARG_DATA_TYPE_KIND);
            return handleDelete(program, args, annotation, dataTypeKind);
        });
    }

    private Mono<? extends Object> handleDelete(Program program,
            Map<String, Object> args,
            GhidraMcpTool annotation,
            String dataTypeKind) {
        return executeInTransaction(program, "MCP - Delete " + dataTypeKind, () -> {
            String name = getRequiredStringArgument(args, ARG_NAME);
            CategoryPath categoryPath = getOptionalStringArgument(args, ARG_CATEGORY_PATH)
                    .map(CategoryPath::new).orElse(CategoryPath.ROOT);

            DataTypeManager dtm = program.getDataTypeManager();
            if ("category".equalsIgnoreCase(dataTypeKind)) {
                try {
                    return deleteCategory(dtm, categoryPath, name, annotation, args);
                } catch (GhidraMcpException e) {
                    throw new RuntimeException(e);
                }
            }
            DataType dataType = null;

            // Try data type ID lookup first (most direct)
            Optional<Long> dataTypeIdOpt = getOptionalLongArgument(args, ARG_DATA_TYPE_ID);
            if (dataTypeIdOpt.isPresent()) {
                dataType = dtm.getDataType(dataTypeIdOpt.get());
            }

            // Fallback to name-based lookup
            if (dataType == null) {
                dataType = dtm.getDataType(categoryPath, name);
            }

            if (dataType == null) {
                throw new GhidraMcpException(createDataTypeError(
                        GhidraMcpError.ErrorCode.DATA_TYPE_NOT_FOUND,
                        "Data type not found: " + name,
                        "Deleting data type",
                        args,
                        name,
                        dtm));
            }

            boolean removed = dtm.remove(dataType, null);
            if (!removed) {
                GhidraMcpError error = GhidraMcpError.execution()
                        .errorCode(GhidraMcpError.ErrorCode.TRANSACTION_FAILED)
                        .message("Failed to remove data type: " + name)
                        .build();
                throw new GhidraMcpException(error);
            }

            return new DataTypeDeleteResult(
                    true,
                    "Successfully deleted " + dataTypeKind + " '" + name + "'",
                    name,
                    categoryPath.toString());
        }).onErrorMap(throwable -> {
            if (throwable instanceof RuntimeException runtime
                    && runtime.getCause() instanceof GhidraMcpException ghidra) {
                return ghidra;
            }
            return throwable;
        });
    }

    private DataTypeDeleteResult deleteCategory(DataTypeManager dtm,
            CategoryPath categoryPath,
            String name,
            GhidraMcpTool annotation,
            Map<String, Object> args) throws GhidraMcpException {

        CategoryPath targetPath = buildCategoryPath(categoryPath, name);

        if (targetPath.isRoot()) {
            GhidraMcpError error = GhidraMcpError.validation()
                    .errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
                    .message("Cannot delete the root category '/' using this tool.")
                    .context(new GhidraMcpError.ErrorContext(
                            annotation.mcpName(),
                            "category validation",
                            args,
                            Map.of(ARG_CATEGORY_PATH, targetPath.getPath()),
                            Map.of("isRoot", true)))
                    .suggestions(List.of(
                            new GhidraMcpError.ErrorSuggestion(
                                    GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
                                    "Provide a non-root category",
                                    "Specify a specific category path to delete",
                                    List.of("/UserDefined", "/MyTypes/MyEmptyCategory"),
                                    null)))
                    .build();
            throw new GhidraMcpException(error);
        }

        Category targetCategory = dtm.getCategory(targetPath);
        if (targetCategory == null) {
            GhidraMcpError error = GhidraMcpError.resourceNotFound()
                    .errorCode(GhidraMcpError.ErrorCode.DATA_TYPE_NOT_FOUND)
                    .message("Category not found at path: " + targetPath.getPath())
                    .context(new GhidraMcpError.ErrorContext(
                            annotation.mcpName(),
                            "category lookup",
                            args,
                            Map.of(ARG_CATEGORY_PATH, targetPath.getPath()),
                            Map.of("categoryExists", false)))
                    .build();
            throw new GhidraMcpException(error);
        }

        CategoryPath parentPath = targetCategory.getParent() != null
                ? targetCategory.getParent().getCategoryPath()
                : CategoryPath.ROOT;

        Category parentCategory = dtm.getCategory(parentPath);
        if (parentCategory == null) {
            throw new IllegalStateException(
                    "Parent category '" + parentPath.getPath() + "' not found for '" + targetPath.getPath() + "'");
        }

        boolean removed = parentCategory.removeCategory(targetPath.getName(), TaskMonitor.DUMMY);
        if (!removed) {
            GhidraMcpError error = GhidraMcpError.execution()
                    .errorCode(GhidraMcpError.ErrorCode.TRANSACTION_FAILED)
                    .message("Failed to delete category '" + targetPath.getPath() + "'. Ensure it is empty.")
                    .context(new GhidraMcpError.ErrorContext(
                            annotation.mcpName(),
                            "category deletion",
                            args,
                            Map.of("attemptedCategory", targetPath.getPath()),
                            Map.of("categoryEmpty", false)))
                    .suggestions(List.of(
                            new GhidraMcpError.ErrorSuggestion(
                                    GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
                                    "Ensure the category is empty",
                                    "Remove any contained data types or subcategories before deletion",
                                    null,
                                    null)))
                    .build();
            throw new GhidraMcpException(error);
        }

        return new DataTypeDeleteResult(
                true,
                "Successfully deleted category '" + targetPath.getPath() + "'",
                targetPath.getName(),
                parentPath.getPath());
    }

    private static CategoryPath buildCategoryPath(CategoryPath parentPath, String name) {
        CategoryPath safeParent = parentPath == null ? CategoryPath.ROOT : parentPath;
        if (name == null || name.isBlank()) {
            return safeParent;
        }
        if (safeParent.toString().endsWith("/" + name)) {
            return safeParent;
        }
        return new CategoryPath(safeParent, name);
    }

    private GhidraMcpError createDataTypeError(GhidraMcpError.ErrorCode errorCode, String message,
            String context, Map<String, Object> args,
            String failedTypeName, DataTypeManager dtm) {
        return GhidraMcpError.dataTypeParsing()
                .errorCode(errorCode)
                .message(message)
                .context(new GhidraMcpError.ErrorContext(
                        this.getMcpName(),
                        context,
                        args,
                        Map.of("failedTypeName", failedTypeName),
                        Map.of()))
                .suggestions(List.of(
                        new GhidraMcpError.ErrorSuggestion(
                                GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
                                "Browse available data types",
                                "Use list_data_types to see what's available",
                                null,
                                List.of("list_data_types"))))
                .build();
    }
}
