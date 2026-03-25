package com.themixednuts.tools;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.DataTypeDeleteResult;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.models.OperationResult;
import com.themixednuts.utils.SymbolLookupHelper;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.draft7.SchemaBuilder;
import ghidra.app.cmd.function.DeleteFunctionCmd;
import ghidra.app.cmd.label.DeleteLabelCmd;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.Category;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.common.McpTransportContext;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import reactor.core.publisher.Mono;

@GhidraMcpTool(
    name = "Delete",
    description =
        "Consolidated destructive tool for deleting functions, symbols, data types, and bookmarks.",
    mcpName = "delete",
    title = "Delete",
    destructiveHint = true,
    mcpDescription =
        """
        <use_case>
        Single destructive tool that handles deletion of functions, symbols, data types,
        and bookmarks. All destructive delete operations are consolidated here so MCP clients
        can deny this single tool to prevent any data loss.
        </use_case>

        <important_notes>
        - DESTRUCTIVE: All actions in this tool permanently remove data from the program
        - MCP clients can deny this entire tool to prevent accidental data loss
        - Prefer update actions (manage_functions, symbols, data_types) over delete-and-recreate
        - Undo/redo is the only recovery mechanism after deletion
        - Four actions: function, symbol, data_type, bookmark
        - Bookmark deletion requires at least one filter OR explicit delete_all=true
        </important_notes>

        <examples>
        Delete a function by address:
        { "file_name": "program.exe", "action": "function", "address": "0x401500" }

        Delete a symbol by name:
        { "file_name": "program.exe", "action": "symbol", "name": "old_label" }

        Delete a data type by name:
        { "file_name": "program.exe", "action": "data_type", "data_type_kind": "struct",
          "name": "MyStruct", "category_path": "/MyTypes" }

        Delete bookmarks with a filter:
        { "file_name": "program.exe", "action": "bookmark", "address": "0x401000",
          "bookmark_type": "Note", "bookmark_category": "Analysis" }

        Delete all bookmarks at an address:
        { "file_name": "program.exe", "action": "bookmark", "address": "0x401000",
          "delete_all": true }
        </examples>
        """)
public class DeleteTool extends BaseMcpTool {

  private static final String ACTION_FUNCTION = "function";
  private static final String ACTION_SYMBOL = "symbol";
  private static final String ACTION_DATA_TYPE = "data_type";
  private static final String ACTION_BOOKMARK = "bookmark";

  private static final String ARG_DATA_TYPE_KIND = "data_type_kind";
  private static final String ARG_BOOKMARK_TYPE = "bookmark_type";
  private static final String ARG_BOOKMARK_CATEGORY = "bookmark_category";
  private static final String ARG_COMMENT_CONTAINS = "comment_contains";
  private static final String ARG_DELETE_ALL = "delete_all";

  @Override
  public JsonSchema schema() {
    var schemaRoot = createDraft7SchemaNode();

    schemaRoot.property(
        ARG_FILE_NAME, SchemaBuilder.string(mapper).description("The name of the program file."));

    schemaRoot.property(
        ARG_ACTION,
        SchemaBuilder.string(mapper)
            .enumValues(ACTION_FUNCTION, ACTION_SYMBOL, ACTION_DATA_TYPE, ACTION_BOOKMARK)
            .description("The type of entity to delete."));

    // Identifier fields shared by function and symbol actions
    schemaRoot.property(
        ARG_SYMBOL_ID,
        SchemaBuilder.integer(mapper)
            .description("Symbol ID for precise identification (highest precedence)."));

    schemaRoot.property(
        ARG_ADDRESS,
        SchemaBuilder.string(mapper)
            .description("Memory address for identification.")
            .pattern("^(0x)?[0-9a-fA-F]+$"));

    schemaRoot.property(
        ARG_NAME,
        SchemaBuilder.string(mapper)
            .description("Name of the entity to delete (supports regex for functions)."));

    // Data type fields
    schemaRoot.property(
        ARG_DATA_TYPE_KIND,
        SchemaBuilder.string(mapper)
            .enumValues(
                "struct", "enum", "union", "typedef", "pointer", "function_definition", "category")
            .description("Type of data type to delete."));

    schemaRoot.property(
        ARG_CATEGORY_PATH,
        SchemaBuilder.string(mapper)
            .description(
                "Category path for data type lookup. For category operations: parent category"
                    + " path.")
            .defaultValue("/"));

    schemaRoot.property(
        ARG_DATA_TYPE_ID,
        SchemaBuilder.integer(mapper).description("Data type ID for direct lookup."));

    // Bookmark filter fields
    schemaRoot.property(
        ARG_BOOKMARK_TYPE,
        SchemaBuilder.string(mapper)
            .description("Filter bookmarks by type (e.g., 'Note', 'Analysis')."));

    schemaRoot.property(
        ARG_BOOKMARK_CATEGORY,
        SchemaBuilder.string(mapper)
            .description("Filter bookmarks by category (e.g., 'Default', 'My Analysis')."));

    schemaRoot.property(
        ARG_COMMENT_CONTAINS,
        SchemaBuilder.string(mapper)
            .description("Filter bookmarks whose comment contains this text."));

    schemaRoot.property(
        ARG_DELETE_ALL,
        SchemaBuilder.bool(mapper)
            .description("Set to true to delete all bookmarks at the address without filters.")
            .defaultValue(false));

    schemaRoot.requiredProperty(ARG_FILE_NAME).requiredProperty(ARG_ACTION);

    // Conditional requirements per action
    schemaRoot.allOf(
        // function action: requires at least one identifier
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(ARG_ACTION, SchemaBuilder.string(mapper).constValue(ACTION_FUNCTION)),
                SchemaBuilder.objectDraft7(mapper)
                    .anyOf(
                        SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_SYMBOL_ID),
                        SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_ADDRESS),
                        SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_NAME))),
        // symbol action: requires at least one identifier
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(ARG_ACTION, SchemaBuilder.string(mapper).constValue(ACTION_SYMBOL)),
                SchemaBuilder.objectDraft7(mapper)
                    .anyOf(
                        SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_SYMBOL_ID),
                        SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_ADDRESS),
                        SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_NAME))),
        // data_type action: requires data_type_kind and at least one of data_type_id or name
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_ACTION, SchemaBuilder.string(mapper).constValue(ACTION_DATA_TYPE)),
                SchemaBuilder.objectDraft7(mapper)
                    .requiredProperty(ARG_DATA_TYPE_KIND)
                    .anyOf(
                        SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_DATA_TYPE_ID),
                        SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_NAME))),
        // bookmark action: requires address
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(ARG_ACTION, SchemaBuilder.string(mapper).constValue(ACTION_BOOKMARK)),
                SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_ADDRESS)));

    return schemaRoot.build();
  }

  @Override
  public Mono<? extends Object> execute(
      McpTransportContext context, Map<String, Object> args, PluginTool tool) {
    return getProgram(args, tool)
        .flatMap(
            program -> {
              String action;
              try {
                action = getRequiredStringArgument(args, ARG_ACTION);
              } catch (GhidraMcpException e) {
                return Mono.error(e);
              }

              return switch (action.toLowerCase()) {
                case ACTION_FUNCTION -> handleDeleteFunction(program, args);
                case ACTION_SYMBOL -> handleDeleteSymbol(program, args);
                case ACTION_DATA_TYPE -> handleDeleteDataType(program, args);
                case ACTION_BOOKMARK -> handleDeleteBookmark(program, args);
                default -> {
                  GhidraMcpError error =
                      GhidraMcpError.invalid(
                          ARG_ACTION,
                          action,
                          "must be one of: "
                              + ACTION_FUNCTION
                              + ", "
                              + ACTION_SYMBOL
                              + ", "
                              + ACTION_DATA_TYPE
                              + ", "
                              + ACTION_BOOKMARK);
                  yield Mono.error(new GhidraMcpException(error));
                }
              };
            });
  }

  // =================== Function Deletion ===================

  private Mono<? extends Object> handleDeleteFunction(Program program, Map<String, Object> args) {
    String toolOperation = "delete";

    // Apply precedence: symbol_id > address > name
    if (args.containsKey(ARG_SYMBOL_ID)) {
      Long symbolId = getOptionalLongArgument(args, ARG_SYMBOL_ID).orElse(null);
      if (symbolId != null) {
        return deleteFunctionBySymbolId(program, symbolId, toolOperation);
      }
    } else if (args.containsKey(ARG_ADDRESS)) {
      String address = getOptionalStringArgument(args, ARG_ADDRESS).orElse(null);
      if (address != null && !address.trim().isEmpty()) {
        return deleteFunctionByAddress(program, address, toolOperation);
      }
    } else if (args.containsKey(ARG_NAME)) {
      String name = getOptionalStringArgument(args, ARG_NAME).orElse(null);
      if (name != null && !name.trim().isEmpty()) {
        return deleteFunctionByName(program, name, toolOperation);
      }
    }

    GhidraMcpError error =
        GhidraMcpError.validation()
            .errorCode(GhidraMcpError.ErrorCode.MISSING_REQUIRED_ARGUMENT)
            .message("At least one identifier must be provided (symbol_id, address, or name)")
            .build();
    return Mono.error(new GhidraMcpException(error));
  }

  private Mono<? extends Object> deleteFunctionBySymbolId(
      Program program, Long symbolId, String toolOperation) {
    return Mono.fromCallable(
            () -> {
              Symbol symbol = program.getSymbolTable().getSymbol(symbolId);
              if (symbol == null) {
                throw new GhidraMcpException(
                    createFunctionNotFoundError(toolOperation, "symbol_id", symbolId.toString()));
              }
              Function function = program.getFunctionManager().getFunctionAt(symbol.getAddress());
              if (function == null) {
                throw new GhidraMcpException(
                    createFunctionNotFoundError(toolOperation, "symbol_id", symbolId.toString()));
              }
              return function;
            })
        .flatMap(function -> deleteFunction(program, function, toolOperation));
  }

  private Mono<? extends Object> deleteFunctionByAddress(
      Program program, String addressStr, String toolOperation) {
    return parseAddress(program, addressStr, toolOperation)
        .flatMap(
            addressResult -> {
              Function function =
                  program.getFunctionManager().getFunctionAt(addressResult.getAddress());
              if (function == null) {
                return Mono.error(
                    new GhidraMcpException(
                        createFunctionNotFoundError(toolOperation, "address", addressStr)));
              }
              return deleteFunction(program, function, toolOperation);
            });
  }

  private Mono<? extends Object> deleteFunctionByName(
      Program program, String name, String toolOperation) {
    return Mono.fromCallable(() -> SymbolLookupHelper.resolveFunction(program, name))
        .flatMap(function -> deleteFunction(program, function, toolOperation));
  }

  private Mono<? extends Object> deleteFunction(
      Program program, Function function, String toolOperation) {
    Address entryPoint = function.getEntryPoint();
    String entryPointStr = entryPoint.toString();

    return executeInTransaction(
        program,
        "MCP - Delete Function at " + entryPointStr,
        () -> {
          DeleteFunctionCmd cmd = new DeleteFunctionCmd(entryPoint);
          if (!cmd.applyTo(program)) {
            String status = Optional.ofNullable(cmd.getStatusMsg()).orElse("Unknown error");
            GhidraMcpError fnError =
                GhidraMcpError.execution()
                    .errorCode(GhidraMcpError.ErrorCode.TRANSACTION_FAILED)
                    .message("Failed to delete function: " + status)
                    .context(
                        new GhidraMcpError.ErrorContext(
                            toolOperation,
                            "function deletion command",
                            Map.of(ARG_ADDRESS, entryPointStr),
                            Map.of("command_status", status),
                            Map.of("command_success", false)))
                    .build();
            throw new GhidraMcpException(fnError);
          }

          return OperationResult.success(
                  "delete_function", entryPointStr, "Function deleted successfully")
              .setMetadata(Map.of("name", function.getName(), "entry_point", entryPointStr));
        });
  }

  private GhidraMcpError createFunctionNotFoundError(
      String toolOperation, String searchType, String searchValue) {
    return GhidraMcpError.validation()
        .errorCode(GhidraMcpError.ErrorCode.FUNCTION_NOT_FOUND)
        .message("Function not found using " + searchType + ": " + searchValue)
        .context(
            new GhidraMcpError.ErrorContext(
                toolOperation,
                "function resolution",
                Map.of(searchType, searchValue),
                Map.of(),
                Map.of("search_method", searchType)))
        .suggestions(
            List.of(
                new GhidraMcpError.ErrorSuggestion(
                    GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
                    "Verify the function exists",
                    "Check that the function identifier is correct",
                    List.of(
                        "\"symbol_id\": 12345", "\"address\": \"0x401000\"", "\"name\": \"main\""),
                    null)))
        .build();
  }

  // =================== Symbol Deletion ===================

  private Mono<? extends Object> handleDeleteSymbol(Program program, Map<String, Object> args) {
    return executeInTransaction(
        program,
        "MCP - Delete Symbol",
        () -> {
          Optional<String> addressOpt = getOptionalStringArgument(args, ARG_ADDRESS);
          Optional<String> nameOpt = getOptionalStringArgument(args, ARG_NAME);
          Optional<Long> symbolIdOpt = getOptionalLongArgument(args, ARG_SYMBOL_ID);

          if (addressOpt.isEmpty() && nameOpt.isEmpty() && symbolIdOpt.isEmpty()) {
            GhidraMcpError symError =
                GhidraMcpError.validation()
                    .errorCode(GhidraMcpError.ErrorCode.MISSING_REQUIRED_ARGUMENT)
                    .message("At least one identifier must be provided")
                    .build();
            throw new GhidraMcpException(symError);
          }

          SymbolTable symbolTable = program.getSymbolTable();
          Symbol symbolToDelete = null;

          if (symbolIdOpt.isPresent()) {
            symbolToDelete = symbolTable.getSymbol(symbolIdOpt.get());
          } else if (addressOpt.isPresent()) {
            try {
              Address address = program.getAddressFactory().getAddress(addressOpt.get());
              if (address != null) {
                symbolToDelete = symbolTable.getPrimarySymbol(address);
              }
            } catch (Exception e) {
              GhidraMcpError symError =
                  GhidraMcpError.validation()
                      .errorCode(GhidraMcpError.ErrorCode.ADDRESS_PARSE_FAILED)
                      .message("Failed to parse address: " + e.getMessage())
                      .build();
              throw new GhidraMcpException(symError);
            }
          } else if (nameOpt.isPresent()) {
            symbolToDelete = SymbolLookupHelper.resolveSymbol(program, nameOpt.get());
          }

          if (symbolToDelete == null) {
            GhidraMcpError symError =
                GhidraMcpError.resourceNotFound()
                    .errorCode(GhidraMcpError.ErrorCode.SYMBOL_NOT_FOUND)
                    .message("Symbol not found")
                    .build();
            throw new GhidraMcpException(symError);
          }

          DeleteLabelCmd cmd =
              new DeleteLabelCmd(
                  symbolToDelete.getAddress(),
                  symbolToDelete.getName(),
                  symbolToDelete.getParentNamespace());
          if (!cmd.applyTo(program)) {
            GhidraMcpError symError =
                GhidraMcpError.execution()
                    .errorCode(GhidraMcpError.ErrorCode.TRANSACTION_FAILED)
                    .message("Failed to delete symbol: " + cmd.getStatusMsg())
                    .build();
            throw new GhidraMcpException(symError);
          }

          return OperationResult.success(
                  "delete_symbol",
                  symbolToDelete.getAddress().toString(),
                  "Symbol deleted successfully")
              .setMetadata(
                  Map.of(
                      "name", symbolToDelete.getName(),
                      "address", symbolToDelete.getAddress().toString()));
        });
  }

  // =================== Data Type Deletion ===================

  private Mono<? extends Object> handleDeleteDataType(Program program, Map<String, Object> args) {
    String dataTypeKind;
    try {
      dataTypeKind = getRequiredStringArgument(args, ARG_DATA_TYPE_KIND);
    } catch (GhidraMcpException e) {
      return Mono.error(e);
    }

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
                  return deleteCategory(dtm, categoryPath, name, args);
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

              String actualName = dataType.getName();

              boolean removed = dtm.remove(dataType, null);
              if (!removed) {
                GhidraMcpError dtError =
                    GhidraMcpError.execution()
                        .errorCode(GhidraMcpError.ErrorCode.TRANSACTION_FAILED)
                        .message("Failed to remove data type: " + actualName)
                        .build();
                throw new GhidraMcpException(dtError);
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
      DataTypeManager dtm, CategoryPath categoryPath, String name, Map<String, Object> args)
      throws GhidraMcpException {

    CategoryPath targetPath = buildCategoryPath(categoryPath, name);
    String toolOperation = "delete";

    if (targetPath.isRoot()) {
      GhidraMcpError catError =
          GhidraMcpError.validation()
              .errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
              .message("Cannot delete the root category '/' using this tool.")
              .context(
                  new GhidraMcpError.ErrorContext(
                      toolOperation,
                      "category validation",
                      args,
                      Map.of(ARG_CATEGORY_PATH, targetPath.getPath()),
                      Map.of("is_root", true)))
              .suggestions(
                  List.of(
                      new GhidraMcpError.ErrorSuggestion(
                          GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
                          "Provide a non-root category",
                          "Specify a specific category path to delete",
                          List.of("/UserDefined", "/MyTypes/MyEmptyCategory"),
                          null)))
              .build();
      throw new GhidraMcpException(catError);
    }

    Category targetCategory = dtm.getCategory(targetPath);
    if (targetCategory == null) {
      GhidraMcpError catError =
          GhidraMcpError.resourceNotFound()
              .errorCode(GhidraMcpError.ErrorCode.DATA_TYPE_NOT_FOUND)
              .message("Category not found at path: " + targetPath.getPath())
              .context(
                  new GhidraMcpError.ErrorContext(
                      toolOperation,
                      "category lookup",
                      args,
                      Map.of(ARG_CATEGORY_PATH, targetPath.getPath()),
                      Map.of("category_exists", false)))
              .build();
      throw new GhidraMcpException(catError);
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
      GhidraMcpError catError =
          GhidraMcpError.execution()
              .errorCode(GhidraMcpError.ErrorCode.TRANSACTION_FAILED)
              .message(
                  "Failed to delete category '" + targetPath.getPath() + "'. Ensure it is empty.")
              .context(
                  new GhidraMcpError.ErrorContext(
                      toolOperation,
                      "category deletion",
                      args,
                      Map.of("attempted_category", targetPath.getPath()),
                      Map.of("category_empty", false)))
              .suggestions(
                  List.of(
                      new GhidraMcpError.ErrorSuggestion(
                          GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
                          "Ensure the category is empty",
                          "Remove any contained data types or subcategories before deletion",
                          null,
                          null)))
              .build();
      throw new GhidraMcpException(catError);
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
                Map.of("failed_type_name", failedTypeName),
                Map.of()))
        .suggestions(
            List.of(
                new GhidraMcpError.ErrorSuggestion(
                    GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
                    "Browse available data types",
                    "Use data_types to see what's available",
                    null,
                    List.of("data_types"))))
        .build();
  }

  // =================== Bookmark Deletion ===================

  private Mono<? extends Object> handleDeleteBookmark(Program program, Map<String, Object> args) {
    String addressStr;
    try {
      addressStr = getRequiredStringArgument(args, ARG_ADDRESS);
    } catch (GhidraMcpException e) {
      return Mono.error(e);
    }
    Optional<String> bookmarkTypeOpt = getOptionalStringArgument(args, ARG_BOOKMARK_TYPE);
    Optional<String> bookmarkCategoryOpt = getOptionalStringArgument(args, ARG_BOOKMARK_CATEGORY);
    Optional<String> commentContainsOpt = getOptionalStringArgument(args, ARG_COMMENT_CONTAINS);
    boolean deleteAll = getOptionalBooleanArgument(args, ARG_DELETE_ALL).orElse(false);

    // Validate: require at least one filter or explicit delete_all
    boolean hasFilter =
        bookmarkTypeOpt.isPresent()
            || bookmarkCategoryOpt.isPresent()
            || commentContainsOpt.isPresent();
    if (!hasFilter && !deleteAll) {
      GhidraMcpError bmError =
          GhidraMcpError.validation()
              .errorCode(GhidraMcpError.ErrorCode.MISSING_REQUIRED_ARGUMENT)
              .message(
                  "Specify at least one filter or set delete_all to true to delete all bookmarks"
                      + " at address.")
              .build();
      return Mono.error(new GhidraMcpException(bmError));
    }

    String toolOperation = "delete";

    return parseAddress(program, addressStr, toolOperation)
        .flatMap(
            addressResult ->
                executeInTransaction(
                    program,
                    "MCP - Delete Bookmark",
                    () -> {
                      Address address = addressResult.getAddress();
                      String normalizedAddress = addressResult.getAddressString();
                      try {
                        BookmarkManager bookmarkManager = program.getBookmarkManager();
                        Bookmark[] bookmarks = bookmarkManager.getBookmarks(address);

                        if (bookmarks.length == 0) {
                          GhidraMcpError bmError =
                              GhidraMcpError.resourceNotFound()
                                  .errorCode(GhidraMcpError.ErrorCode.BOOKMARK_NOT_FOUND)
                                  .message("No bookmarks found at address: " + addressStr)
                                  .context(
                                      new GhidraMcpError.ErrorContext(
                                          toolOperation,
                                          "bookmark lookup",
                                          args,
                                          Map.of(ARG_ADDRESS, normalizedAddress),
                                          Map.of("bookmark_count", 0)))
                                  .suggestions(
                                      List.of(
                                          new GhidraMcpError.ErrorSuggestion(
                                              GhidraMcpError.ErrorSuggestion.SuggestionType
                                                  .CHECK_RESOURCES,
                                              "Inspect available bookmarks",
                                              "List bookmarks to verify available types and"
                                                  + " categories",
                                              null,
                                              null)))
                                  .build();
                          throw new GhidraMcpException(bmError);
                        }

                        List<Bookmark> matched =
                            Arrays.stream(bookmarks)
                                .filter(
                                    bookmark ->
                                        bookmarkTypeOpt
                                            .map(type -> type.equals(bookmark.getTypeString()))
                                            .orElse(true))
                                .filter(
                                    bookmark ->
                                        bookmarkCategoryOpt
                                            .map(
                                                category -> category.equals(bookmark.getCategory()))
                                            .orElse(true))
                                .filter(
                                    bookmark ->
                                        commentContainsOpt
                                            .map(
                                                filter ->
                                                    Optional.ofNullable(bookmark.getComment())
                                                        .map(comment -> comment.contains(filter))
                                                        .orElse(false))
                                            .orElse(true))
                                .collect(Collectors.toList());

                        if (matched.isEmpty()) {
                          GhidraMcpError bmError =
                              GhidraMcpError.resourceNotFound()
                                  .errorCode(GhidraMcpError.ErrorCode.BOOKMARK_NOT_FOUND)
                                  .message(
                                      "No bookmarks matched the specified criteria at address: "
                                          + addressStr)
                                  .context(
                                      new GhidraMcpError.ErrorContext(
                                          toolOperation,
                                          "bookmark filtering",
                                          args,
                                          Map.of(
                                              ARG_ADDRESS,
                                              addressStr,
                                              ARG_BOOKMARK_TYPE,
                                              bookmarkTypeOpt.orElse("any"),
                                              ARG_BOOKMARK_CATEGORY,
                                              bookmarkCategoryOpt.orElse("any"),
                                              ARG_COMMENT_CONTAINS,
                                              commentContainsOpt.orElse("none")),
                                          Map.of("bookmarks_inspected", bookmarks.length)))
                                  .suggestions(
                                      List.of(
                                          new GhidraMcpError.ErrorSuggestion(
                                              GhidraMcpError.ErrorSuggestion.SuggestionType
                                                  .CHECK_RESOURCES,
                                              "Review bookmark filters",
                                              "Adjust type, category, or comment filters to match"
                                                  + " existing bookmarks",
                                              null,
                                              null)))
                                  .build();
                          throw new GhidraMcpException(bmError);
                        }

                        matched.forEach(bookmarkManager::removeBookmark);

                        return OperationResult.success(
                                "delete_bookmark",
                                address.toString(),
                                "Deleted " + matched.size() + " bookmark(s).")
                            .setMetadata(
                                Map.of(
                                    "deleted_count",
                                    matched.size(),
                                    ARG_BOOKMARK_TYPE,
                                    bookmarkTypeOpt.orElse("any"),
                                    ARG_BOOKMARK_CATEGORY,
                                    bookmarkCategoryOpt.orElse("any")));
                      } catch (GhidraMcpException e) {
                        throw e;
                      } catch (Exception e) {
                        GhidraMcpError bmError =
                            GhidraMcpError.execution()
                                .errorCode(GhidraMcpError.ErrorCode.TRANSACTION_FAILED)
                                .message("Failed to delete bookmark: " + e.getMessage())
                                .context(
                                    new GhidraMcpError.ErrorContext(
                                        toolOperation,
                                        "bookmark deletion",
                                        args,
                                        Map.of("address", addressStr),
                                        Map.of("exception_type", e.getClass().getSimpleName())))
                                .suggestions(
                                    List.of(
                                        new GhidraMcpError.ErrorSuggestion(
                                            GhidraMcpError.ErrorSuggestion.SuggestionType
                                                .CHECK_RESOURCES,
                                            "Verify program state and bookmark accessibility",
                                            "Ensure the program is writable and bookmark manager"
                                                + " is available",
                                            null,
                                            null)))
                                .build();
                        throw new GhidraMcpException(bmError, e);
                      }
                    }));
  }
}
