package com.themixednuts.tools;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.DataTypeDeleteResult;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.google.SchemaBuilder;
import com.themixednuts.utils.jsonschema.google.SchemaBuilder.IObjectSchemaBuilder;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.Category;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.common.McpTransportContext;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import reactor.core.publisher.Mono;

@GhidraMcpTool(
    name = "Delete Data Type",
    description =
        "Delete data types (structs, enums, unions, typedefs, pointers, function definitions) and"
            + " categories.",
    mcpName = "delete_data_type",
    title = "Delete Data Type",
    destructiveHint = true,
    mcpDescription =
        """
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
                  "file_name": "program.exe",
                  "data_type_kind": "struct",
                  "data_type_id": 12345
                }

                Delete a data type by name:
                {
                  "file_name": "program.exe",
                  "data_type_kind": "struct",
                  "name": "MyStruct",
                  "category_path": "/MyTypes"
                }

                Delete an empty category:
                {
                  "file_name": "program.exe",
                  "data_type_kind": "category",
                  "name": "OldCategory",
                  "category_path": "/MyTypes"
                }
                </examples>
        """)
public class DeleteDataTypeTool extends BaseMcpTool {

  public static final String ARG_DATA_TYPE_KIND = "data_type_kind";

  @Override
  public JsonSchema schema() {
    IObjectSchemaBuilder schemaRoot = createBaseSchemaNode();

    schemaRoot.property(
        ARG_FILE_NAME, SchemaBuilder.string(mapper).description("The name of the program file."));

    schemaRoot.property(
        ARG_DATA_TYPE_KIND,
        SchemaBuilder.string(mapper)
            .enumValues(
                "struct", "enum", "union", "typedef", "pointer", "function_definition", "category")
            .description("Type of data type to delete"));

    schemaRoot.property(
        ARG_NAME,
        SchemaBuilder.string(mapper).description("Name of the data type or category to delete"));

    schemaRoot.property(
        ARG_CATEGORY_PATH,
        SchemaBuilder.string(mapper)
            .description(
                "For non-category data types: full category path. For category operations: parent"
                    + " category path (default '/').")
            .defaultValue("/"));

    schemaRoot.property(
        ARG_DATA_TYPE_ID,
        SchemaBuilder.integer(mapper)
            .description("Optional: Data type ID for direct lookup by internal ID"));

    schemaRoot.requiredProperty(ARG_FILE_NAME).requiredProperty(ARG_DATA_TYPE_KIND);

    // At least one identifier must be provided
    schemaRoot.anyOf(
        SchemaBuilder.object(mapper).requiredProperty(ARG_DATA_TYPE_ID),
        SchemaBuilder.object(mapper).requiredProperty(ARG_NAME));

    return schemaRoot.build();
  }

  @Override
  public Mono<? extends Object> execute(
      McpTransportContext context, Map<String, Object> args, PluginTool tool) {
    GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);

    return getProgram(args, tool)
        .flatMap(
            program -> {
              String dataTypeKind;
              try {
                dataTypeKind = getRequiredStringArgument(args, ARG_DATA_TYPE_KIND);
              } catch (GhidraMcpException e) {
                return Mono.error(e);
              }
              return handleDelete(program, args, annotation, dataTypeKind);
            });
  }

  private Mono<? extends Object> handleDelete(
      Program program, Map<String, Object> args, GhidraMcpTool annotation, String dataTypeKind) {
    return executeInTransaction(
            program,
            "MCP - Delete " + dataTypeKind,
            () -> {
              Optional<String> nameOpt = getOptionalStringArgument(args, ARG_NAME);
              Optional<Long> dataTypeIdOpt = getOptionalLongArgument(args, ARG_DATA_TYPE_ID);
              CategoryPath categoryPath =
                  getOptionalStringArgument(args, ARG_CATEGORY_PATH)
                      .map(CategoryPath::new)
                      .orElse(CategoryPath.ROOT);

              DataTypeManager dtm = program.getDataTypeManager();

              // Category operations require name
              if ("category".equalsIgnoreCase(dataTypeKind)) {
                String name =
                    nameOpt.orElseThrow(
                        () ->
                            new IllegalArgumentException(
                                "name is required for category operations"));
                try {
                  return deleteCategory(dtm, categoryPath, name, annotation, args);
                } catch (GhidraMcpException e) {
                  throw new RuntimeException(e);
                }
              }

              DataType dataType = null;

              // Try data type ID lookup first (most direct)
              if (dataTypeIdOpt.isPresent()) {
                dataType = dtm.getDataType(dataTypeIdOpt.get());
              }

              // Fallback to name-based lookup
              if (dataType == null && nameOpt.isPresent()) {
                dataType = dtm.getDataType(categoryPath, nameOpt.get());
              }

              if (dataType == null) {
                String identifier =
                    nameOpt.orElse(dataTypeIdOpt.map(String::valueOf).orElse("unknown"));
                throw new GhidraMcpException(
                    createDataTypeError(
                        GhidraMcpError.ErrorCode.DATA_TYPE_NOT_FOUND,
                        "Data type not found: " + identifier,
                        "Deleting data type",
                        args,
                        identifier,
                        dtm));
              }

              // Get actual name from found data type
              String actualName = dataType.getName();

              boolean removed = dtm.remove(dataType, null);
              if (!removed) {
                GhidraMcpError error =
                    GhidraMcpError.execution()
                        .errorCode(GhidraMcpError.ErrorCode.TRANSACTION_FAILED)
                        .message("Failed to remove data type: " + actualName)
                        .build();
                throw new GhidraMcpException(error);
              }

              return new DataTypeDeleteResult(
                  true,
                  "Successfully deleted " + dataTypeKind + " '" + actualName + "'",
                  actualName,
                  categoryPath.toString());
            })
        .onErrorMap(
            throwable -> {
              if (throwable instanceof RuntimeException runtime
                  && runtime.getCause() instanceof GhidraMcpException ghidra) {
                return ghidra;
              }
              return throwable;
            });
  }

  private DataTypeDeleteResult deleteCategory(
      DataTypeManager dtm,
      CategoryPath categoryPath,
      String name,
      GhidraMcpTool annotation,
      Map<String, Object> args)
      throws GhidraMcpException {

    CategoryPath targetPath = buildCategoryPath(categoryPath, name);

    if (targetPath.isRoot()) {
      GhidraMcpError error =
          GhidraMcpError.validation()
              .errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
              .message("Cannot delete the root category '/' using this tool.")
              .context(
                  new GhidraMcpError.ErrorContext(
                      annotation.mcpName(),
                      "category validation",
                      args,
                      Map.of(ARG_CATEGORY_PATH, targetPath.getPath()),
                      Map.of("isRoot", true)))
              .suggestions(
                  List.of(
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
      GhidraMcpError error =
          GhidraMcpError.resourceNotFound()
              .errorCode(GhidraMcpError.ErrorCode.DATA_TYPE_NOT_FOUND)
              .message("Category not found at path: " + targetPath.getPath())
              .context(
                  new GhidraMcpError.ErrorContext(
                      annotation.mcpName(),
                      "category lookup",
                      args,
                      Map.of(ARG_CATEGORY_PATH, targetPath.getPath()),
                      Map.of("categoryExists", false)))
              .build();
      throw new GhidraMcpException(error);
    }

    CategoryPath parentPath =
        targetCategory.getParent() != null
            ? targetCategory.getParent().getCategoryPath()
            : CategoryPath.ROOT;

    Category parentCategory = dtm.getCategory(parentPath);
    if (parentCategory == null) {
      throw new IllegalStateException(
          "Parent category '"
              + parentPath.getPath()
              + "' not found for '"
              + targetPath.getPath()
              + "'");
    }

    boolean removed = parentCategory.removeCategory(targetPath.getName(), TaskMonitor.DUMMY);
    if (!removed) {
      GhidraMcpError error =
          GhidraMcpError.execution()
              .errorCode(GhidraMcpError.ErrorCode.TRANSACTION_FAILED)
              .message(
                  "Failed to delete category '" + targetPath.getPath() + "'. Ensure it is empty.")
              .context(
                  new GhidraMcpError.ErrorContext(
                      annotation.mcpName(),
                      "category deletion",
                      args,
                      Map.of("attemptedCategory", targetPath.getPath()),
                      Map.of("categoryEmpty", false)))
              .suggestions(
                  List.of(
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

  private GhidraMcpError createDataTypeError(
      GhidraMcpError.ErrorCode errorCode,
      String message,
      String context,
      Map<String, Object> args,
      String failedTypeName,
      DataTypeManager dtm) {
    return GhidraMcpError.dataTypeParsing()
        .errorCode(errorCode)
        .message(message)
        .context(
            new GhidraMcpError.ErrorContext(
                this.getMcpName(),
                context,
                args,
                Map.of("failedTypeName", failedTypeName),
                Map.of()))
        .suggestions(
            List.of(
                new GhidraMcpError.ErrorSuggestion(
                    GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
                    "Browse available data types",
                    "Use list_data_types to see what's available",
                    null,
                    List.of("list_data_types"))))
        .build();
  }
}
