package com.themixednuts.tools;

import com.themixednuts.GhidraMcpServer;
import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.FunctionInfo;
import com.themixednuts.models.FunctionListEntry;
import com.themixednuts.models.FunctionVariableInfo;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.ui.NavigateToAddressEffect;
import com.themixednuts.ui.ToolOutcome;
import com.themixednuts.utils.GhidraMcpErrorUtils;
import com.themixednuts.utils.NameFilterPattern;
import com.themixednuts.utils.OpaqueCursorCodec;
import com.themixednuts.utils.PaginatedResult;
import com.themixednuts.utils.SymbolLookupHelper;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.draft7.SchemaBuilder;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.ClangFieldToken;
import ghidra.app.decompiler.ClangNode;
import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.services.DataTypeQueryService;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.Union;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.pcode.DynamicHash;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.pcode.PartialUnion;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.common.McpTransportContext;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;
import reactor.core.publisher.Mono;

@GhidraMcpTool(
    name = "Functions",
    description =
        "Function lifecycle: list, get, create, update prototypes, variables, union facets.",
    mcpName = "functions",
    mcpDescription =
        """
        List, get, create, and edit functions in an open program. Use update_prototype for signatures,
        list_variables and update_variable for locals or parameters, and list_union_field_candidates
        before force_union_field. list returns paged summary rows with symbol_id; get returns full
        metadata. For repeated variable edits, use variable_symbol_id from list_variables because
        generated variable names can change after renaming. Use inspect to decompile code.
        """)
public class FunctionsTool extends BaseMcpTool {

  public static final String ARG_ACTION = "action";
  public static final String ARG_SYMBOL_ID = "symbol_id";
  public static final String ARG_ADDRESS = "address";
  public static final String ARG_NAME = "name";
  public static final String ARG_PROTOTYPE = "prototype";
  public static final String ARG_RETURN_TYPE = "return_type";
  public static final String ARG_CALLING_CONVENTION = "calling_convention";
  public static final String ARG_NEW_FUNCTION_NAME = "new_function_name";
  public static final String ARG_PARAMETERS = "parameters";
  public static final String ARG_NO_RETURN = "no_return";
  public static final String ARG_PARAMETER_NAME = "name";
  public static final String ARG_PARAMETER_DATA_TYPE = "data_type";
  public static final String ARG_CURRENT_NAME = "current_name";
  public static final String ARG_NEW_NAME = "new_name";
  public static final String ARG_VARIABLE_SYMBOL_ID = "variable_symbol_id";
  public static final String ARG_NEW_DATA_TYPE = "new_data_type";
  public static final String ARG_VERBOSE = "verbose";
  public static final String ARG_ADDRESS_START = "address_start";
  public static final String ARG_ADDRESS_END = "address_end";
  public static final String ARG_UNION_TYPE_PATH = "union_type_path";
  public static final String ARG_TOKEN_TEXT = "token_text";
  public static final String ARG_CANDIDATE_INDEX = "candidate_index";
  public static final String ARG_PC_ADDRESS = "pc_address";
  public static final String ARG_DYNAMIC_HASH = "dynamic_hash";
  public static final String ARG_FIELD_NAME = "field_name";
  public static final String ARG_FIELD_ORDINAL = "field_ordinal";

  private static final String ACTION_LIST = "list";
  private static final String ACTION_GET = "get";
  private static final String ACTION_CREATE = "create";
  private static final String ACTION_UPDATE_PROTOTYPE = "update_prototype";
  private static final String ACTION_LIST_VARIABLES = "list_variables";
  private static final String ACTION_RENAME_VARIABLE = "rename_variable";
  private static final String ACTION_UPDATE_VARIABLE = "update_variable";
  private static final String ACTION_LIST_UNION_FIELD_CANDIDATES = "list_union_field_candidates";
  private static final String ACTION_FORCE_UNION_FIELD = "force_union_field";

  @Override
  public JsonSchema schema() {
    var schemaRoot = createDraft7SchemaNode();

    schemaRoot.property(
        ARG_FILE_NAME, SchemaBuilder.string(mapper).description("The name of the program file."));

    schemaRoot.property(
        ARG_ACTION,
        SchemaBuilder.string(mapper)
            .enumValues(
                ACTION_LIST,
                ACTION_GET,
                ACTION_CREATE,
                ACTION_UPDATE_PROTOTYPE,
                ACTION_LIST_VARIABLES,
                ACTION_RENAME_VARIABLE,
                ACTION_UPDATE_VARIABLE,
                ACTION_LIST_UNION_FIELD_CANDIDATES,
                ACTION_FORCE_UNION_FIELD)
            .description("Action to perform on functions"));

    schemaRoot.requiredProperty(ARG_FILE_NAME).requiredProperty(ARG_ACTION);

    schemaRoot.allOf(
        // action=list: optional filtering and pagination
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(ARG_ACTION, SchemaBuilder.string(mapper).constValue(ACTION_LIST)),
                SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_NAME_PATTERN,
                        SchemaBuilder.string(mapper)
                            .description("Optional regex or * and ? glob to filter function names"))
                    .property(
                        ARG_ADDRESS_START,
                        SchemaBuilder.string(mapper)
                            .description(
                                "Optional inclusive lower bound on the function entry point"
                                    + " address")
                            .pattern(ADDRESS_PATTERN))
                    .property(
                        ARG_ADDRESS_END,
                        SchemaBuilder.string(mapper)
                            .description(
                                "Optional inclusive upper bound on the function entry point"
                                    + " address")
                            .pattern(ADDRESS_PATTERN))
                    .property(
                        ARG_CURSOR,
                        SchemaBuilder.string(mapper)
                            .description(
                                "Opaque cursor copied from the previous functions.list"
                                    + " next_cursor. Keep name_pattern/address bounds unchanged."
                                    + " Format: v1:<base64url_symbol_id>."))
                    .property(
                        ARG_PAGE_SIZE,
                        SchemaBuilder.integer(mapper)
                            .description(
                                "Number of functions to return per page (default: "
                                    + DEFAULT_PAGE_LIMIT
                                    + ", max: "
                                    + MAX_PAGE_LIMIT
                                    + ")")
                            .minimum(1)
                            .maximum(MAX_PAGE_LIMIT))
                    .property(
                        ARG_VERBOSE,
                        SchemaBuilder.bool(mapper)
                            .description(
                                "Include signature and namespace metadata. Default false returns"
                                    + " only symbol_id, name, and entry_point."))),
        // action=get: requires at least one identifier (symbol_id, address, name)
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(ARG_ACTION, SchemaBuilder.string(mapper).constValue(ACTION_GET)),
                SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_SYMBOL_ID,
                        SchemaBuilder.integer(mapper)
                            .description("Symbol ID to identify a specific function"))
                    .property(
                        ARG_ADDRESS,
                        SchemaBuilder.string(mapper)
                            .description("Function address for identification")
                            .pattern(ADDRESS_PATTERN))
                    .property(
                        ARG_NAME,
                        SchemaBuilder.string(mapper)
                            .description("Function name for lookup (supports * and ? wildcards)"))
                    .anyOf(
                        SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_SYMBOL_ID),
                        SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_ADDRESS),
                        SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_NAME))),
        // action=create: requires address; allows functionName
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(ARG_ACTION, SchemaBuilder.string(mapper).constValue(ACTION_CREATE)),
                SchemaBuilder.objectDraft7(mapper)
                    .requiredProperty(ARG_ADDRESS)
                    .property(
                        ARG_ADDRESS,
                        SchemaBuilder.string(mapper)
                            .description("Address where function should be created")
                            .pattern(ADDRESS_PATTERN))
                    .property(
                        ARG_FUNCTION_NAME,
                        SchemaBuilder.string(mapper)
                            .description(
                                "Optional name for the new function (auto-generated if not"
                                    + " provided)"))),
        // action=update_prototype: requires at least one identifier (symbol_id,
        // address, name);
        // allows prototype or structured fields
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_ACTION,
                        SchemaBuilder.string(mapper).constValue(ACTION_UPDATE_PROTOTYPE)),
                SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_SYMBOL_ID,
                        SchemaBuilder.integer(mapper)
                            .description("Function symbol ID for identification"))
                    .property(
                        ARG_ADDRESS,
                        SchemaBuilder.string(mapper)
                            .description("Function address for identification")
                            .pattern(ADDRESS_PATTERN))
                    .property(
                        ARG_NAME,
                        SchemaBuilder.string(mapper)
                            .description("Function name for identification"))
                    .property(
                        ARG_PROTOTYPE,
                        SchemaBuilder.string(mapper)
                            .description("Full function prototype string (C syntax)"))
                    .property(
                        ARG_RETURN_TYPE,
                        SchemaBuilder.string(mapper)
                            .description("Return type name (required if prototype not provided)"))
                    .property(
                        ARG_CALLING_CONVENTION,
                        SchemaBuilder.string(mapper)
                            .description("Calling convention (e.g., __cdecl, __stdcall)"))
                    .property(
                        ARG_NEW_FUNCTION_NAME,
                        SchemaBuilder.string(mapper).description("New name for the function"))
                    .property(
                        ARG_PARAMETERS,
                        SchemaBuilder.array(mapper)
                            .description("Function parameters with 'name' and 'data_type' fields")
                            .items(
                                SchemaBuilder.object(mapper)
                                    .property(ARG_PARAMETER_NAME, SchemaBuilder.string(mapper))
                                    .property(ARG_PARAMETER_DATA_TYPE, SchemaBuilder.string(mapper))
                                    .requiredProperty(ARG_PARAMETER_NAME)
                                    .requiredProperty(ARG_PARAMETER_DATA_TYPE)))
                    .property(
                        ARG_NO_RETURN,
                        SchemaBuilder.bool(mapper).description("Whether function does not return"))
                    .anyOf(
                        SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_SYMBOL_ID),
                        SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_ADDRESS),
                        SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_NAME))),
        // action=list_variables: requires at least one identifier (symbol_id, address,
        // name);
        // allows cursor and verbose metadata
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_ACTION, SchemaBuilder.string(mapper).constValue(ACTION_LIST_VARIABLES)),
                SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_SYMBOL_ID,
                        SchemaBuilder.integer(mapper)
                            .description("Function symbol ID for identification"))
                    .property(
                        ARG_ADDRESS,
                        SchemaBuilder.string(mapper)
                            .description("Function address for identification")
                            .pattern(ADDRESS_PATTERN))
                    .property(
                        ARG_NAME,
                        SchemaBuilder.string(mapper)
                            .description("Function name for identification"))
                    .property(
                        ARG_CURSOR,
                        SchemaBuilder.string(mapper)
                            .description(
                                "Opaque cursor copied from the previous"
                                    + " functions.list_variables next_cursor. Keep the same"
                                    + " function identifier and filters. Format:"
                                    + " v1:<base64url_variable_symbol_id>."))
                    .property(
                        ARG_PAGE_SIZE,
                        SchemaBuilder.integer(mapper)
                            .description(
                                "Number of variables to return per page (default: "
                                    + DEFAULT_PAGE_LIMIT
                                    + ", max: "
                                    + MAX_PAGE_LIMIT
                                    + ")")
                            .minimum(1)
                            .maximum(MAX_PAGE_LIMIT))
                    .property(
                        ARG_VERBOSE,
                        SchemaBuilder.bool(mapper)
                            .description(
                                "Include variable metadata fields (data_type, storage,"
                                    + " is_parameter). Default false returns only name and"
                                    + " variable_symbol_id"))
                    .anyOf(
                        SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_SYMBOL_ID),
                        SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_ADDRESS),
                        SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_NAME))),
        // action=rename_variable/update_variable: requires function identifier + variable
        // targeting + new_name and/or new_data_type
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_ACTION,
                        SchemaBuilder.string(mapper)
                            .enumValues(ACTION_RENAME_VARIABLE, ACTION_UPDATE_VARIABLE)),
                SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_SYMBOL_ID,
                        SchemaBuilder.integer(mapper)
                            .description("Function symbol ID for identification"))
                    .property(
                        ARG_ADDRESS,
                        SchemaBuilder.string(mapper)
                            .description("Function address for identification")
                            .pattern(ADDRESS_PATTERN))
                    .property(
                        ARG_NAME,
                        SchemaBuilder.string(mapper)
                            .description("Function name for identification"))
                    .property(
                        ARG_VARIABLE_SYMBOL_ID,
                        SchemaBuilder.anyOf(
                                SchemaBuilder.string(mapper).pattern("^-?\\d+$"),
                                SchemaBuilder.integer(mapper))
                            .description(
                                "Decompiler symbol ID of the variable to update (from"
                                    + " list_variables variable_symbol_id). Stable across"
                                    + " renames — preferred for batch operations. Pass as a"
                                    + " STRING (e.g. \"4614873502636310661\") for IDs above"
                                    + " 2^53 to avoid JSON number precision loss in 64-bit-float"
                                    + " JSON parsers; integers are also accepted for small IDs"))
                    .property(
                        ARG_CURRENT_NAME,
                        SchemaBuilder.string(mapper)
                            .description(
                                "Current name of the variable to rename (as shown by"
                                    + " list_variables name). Use"
                                    + " variable_symbol_id for batch operations to avoid"
                                    + " renumbering issues"))
                    .property(
                        ARG_NEW_NAME,
                        SchemaBuilder.string(mapper).description("New name for the variable"))
                    .property(
                        ARG_NEW_DATA_TYPE,
                        SchemaBuilder.string(mapper)
                            .description(
                                "New data type for the variable (e.g. \"int\", \"char *\","
                                    + " \"/MyCategory/MyStruct\")"))
                    .allOf(
                        SchemaBuilder.objectDraft7(mapper)
                            .anyOf(
                                SchemaBuilder.objectDraft7(mapper)
                                    .requiredProperty(ARG_VARIABLE_SYMBOL_ID),
                                SchemaBuilder.objectDraft7(mapper)
                                    .requiredProperty(ARG_CURRENT_NAME)),
                        SchemaBuilder.objectDraft7(mapper)
                            .anyOf(
                                SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_SYMBOL_ID),
                                SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_ADDRESS),
                                SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_NAME)))),
        // action=list_union_field_candidates: requires a function identifier, optional filters
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_ACTION,
                        SchemaBuilder.string(mapper)
                            .constValue(ACTION_LIST_UNION_FIELD_CANDIDATES)),
                SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_SYMBOL_ID,
                        SchemaBuilder.integer(mapper)
                            .description("Function symbol ID for identification"))
                    .property(
                        ARG_ADDRESS,
                        SchemaBuilder.string(mapper)
                            .description("Function address for identification")
                            .pattern(ADDRESS_PATTERN))
                    .property(
                        ARG_NAME,
                        SchemaBuilder.string(mapper)
                            .description("Function name for identification"))
                    .property(
                        ARG_UNION_TYPE_PATH,
                        SchemaBuilder.string(mapper)
                            .description("Optional union data type path/name filter"))
                    .property(
                        ARG_TOKEN_TEXT,
                        SchemaBuilder.string(mapper)
                            .description("Optional currently displayed field token filter"))
                    .property(
                        ARG_PC_ADDRESS,
                        SchemaBuilder.string(mapper)
                            .description("Optional dynamic-hash address filter")
                            .pattern(ADDRESS_PATTERN))
                    .property(
                        ARG_DYNAMIC_HASH,
                        SchemaBuilder.anyOf(
                                SchemaBuilder.string(mapper)
                                    .pattern("^(?:-?\\d+|0[xX][0-9a-fA-F]+)$"),
                                SchemaBuilder.integer(mapper))
                            .description(
                                "Optional dynamic hash filter. Pass as a string to avoid JSON"
                                    + " number precision loss."))
                    .anyOf(
                        SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_SYMBOL_ID),
                        SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_ADDRESS),
                        SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_NAME))),
        // action=force_union_field: requires a function identifier, candidate target, and field
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_ACTION,
                        SchemaBuilder.string(mapper).constValue(ACTION_FORCE_UNION_FIELD)),
                SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_SYMBOL_ID,
                        SchemaBuilder.integer(mapper)
                            .description("Function symbol ID for identification"))
                    .property(
                        ARG_ADDRESS,
                        SchemaBuilder.string(mapper)
                            .description("Function address for identification")
                            .pattern(ADDRESS_PATTERN))
                    .property(
                        ARG_NAME,
                        SchemaBuilder.string(mapper)
                            .description("Function name for identification"))
                    .property(
                        ARG_CANDIDATE_INDEX,
                        SchemaBuilder.integer(mapper)
                            .description(
                                "Candidate index from list_union_field_candidates. Preferred."))
                    .property(
                        ARG_PC_ADDRESS,
                        SchemaBuilder.string(mapper)
                            .description(
                                "Dynamic-hash address from list_union_field_candidates; use with"
                                    + " dynamic_hash when candidate_index is not supplied")
                            .pattern(ADDRESS_PATTERN))
                    .property(
                        ARG_DYNAMIC_HASH,
                        SchemaBuilder.anyOf(
                                SchemaBuilder.string(mapper)
                                    .pattern("^(?:-?\\d+|0[xX][0-9a-fA-F]+)$"),
                                SchemaBuilder.integer(mapper))
                            .description(
                                "Dynamic hash from list_union_field_candidates. Pass as a string"
                                    + " to avoid JSON number precision loss."))
                    .property(
                        ARG_UNION_TYPE_PATH,
                        SchemaBuilder.string(mapper)
                            .description("Optional union data type path/name filter"))
                    .property(
                        ARG_TOKEN_TEXT,
                        SchemaBuilder.string(mapper)
                            .description("Optional currently displayed field token filter"))
                    .property(
                        ARG_FIELD_NAME,
                        SchemaBuilder.string(mapper)
                            .description(
                                "Union field name to force. Use \"(no field)\" to clear the"
                                    + " forced field."))
                    .property(
                        ARG_FIELD_ORDINAL,
                        SchemaBuilder.integer(mapper)
                            .description(
                                "Zero-based union field ordinal to force; -1 clears the forced"
                                    + " field."))
                    .allOf(
                        SchemaBuilder.objectDraft7(mapper)
                            .anyOf(
                                SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_SYMBOL_ID),
                                SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_ADDRESS),
                                SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_NAME)),
                        SchemaBuilder.objectDraft7(mapper)
                            .anyOf(
                                SchemaBuilder.objectDraft7(mapper)
                                    .requiredProperty(ARG_CANDIDATE_INDEX),
                                SchemaBuilder.objectDraft7(mapper)
                                    .requiredProperty(ARG_PC_ADDRESS)
                                    .requiredProperty(ARG_DYNAMIC_HASH)),
                        SchemaBuilder.objectDraft7(mapper)
                            .anyOf(
                                SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_FIELD_NAME),
                                SchemaBuilder.objectDraft7(mapper)
                                    .requiredProperty(ARG_FIELD_ORDINAL)))));

    return schemaRoot.build();
  }

  @Override
  public Mono<? extends Object> execute(
      McpTransportContext context, Map<String, Object> args, PluginTool tool) {
    GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);

    return getProgram(args, tool)
        .flatMap(
            program -> {
              String action = getRequiredStringArgument(args, ARG_ACTION);

              try {
                if ("create".equalsIgnoreCase(action)) {
                  ensureArgumentPresent(args, ARG_ADDRESS, annotation.mcpName() + ".create");
                }
              } catch (GhidraMcpException e) {
                return Mono.error(e);
              }

              return switch (action.toLowerCase(Locale.ROOT)) {
                case ACTION_LIST -> handleList(program, args);
                case ACTION_GET -> handleGet(program, args);
                case ACTION_CREATE -> handleCreate(program, args, annotation);
                case ACTION_UPDATE_PROTOTYPE ->
                    handleUpdatePrototype(program, tool, args, annotation);
                case ACTION_LIST_VARIABLES -> handleListVariables(program, args, annotation);
                case ACTION_RENAME_VARIABLE, ACTION_UPDATE_VARIABLE ->
                    handleUpdateVariable(
                        program, args, annotation, action.toLowerCase(Locale.ROOT));
                case ACTION_LIST_UNION_FIELD_CANDIDATES ->
                    handleListUnionFieldCandidates(program, args, annotation);
                case ACTION_FORCE_UNION_FIELD -> handleForceUnionField(program, args, annotation);
                default -> {
                  // Common cross-tool guesses (disassemble/decompile/delete/etc.) — return a
                  // redirect rather than the bare valid-actions list so the next call lands.
                  Map<String, String> aliases =
                      Map.ofEntries(
                          Map.entry("disassemble", "use `inspect` (action: listing)"),
                          Map.entry("decompile", "use `inspect` (action: decompile)"),
                          Map.entry("delete", "use `delete` tool"),
                          Map.entry("remove", "use `delete` tool"),
                          Map.entry("find", ACTION_GET),
                          Map.entry("resolve", ACTION_GET),
                          Map.entry("search", ACTION_LIST),
                          Map.entry("rename", ACTION_UPDATE_VARIABLE),
                          Map.entry("update", ACTION_UPDATE_PROTOTYPE),
                          Map.entry("force_field", ACTION_FORCE_UNION_FIELD),
                          Map.entry("select_union_field", ACTION_FORCE_UNION_FIELD));
                  GhidraMcpError error =
                      GhidraMcpErrorUtils.invalidAction(
                          action,
                          List.of(
                              ACTION_LIST,
                              ACTION_GET,
                              ACTION_CREATE,
                              ACTION_UPDATE_PROTOTYPE,
                              ACTION_LIST_VARIABLES,
                              ACTION_RENAME_VARIABLE,
                              ACTION_UPDATE_VARIABLE,
                              ACTION_LIST_UNION_FIELD_CANDIDATES,
                              ACTION_FORCE_UNION_FIELD),
                          aliases);
                  yield Mono.error(new GhidraMcpException(error));
                }
              };
            });
  }

  private Mono<PaginatedResult<FunctionListEntry>> handleList(
      Program program, Map<String, Object> args) {
    return Mono.fromCallable(() -> listFunctions(program, args));
  }

  private PaginatedResult<FunctionListEntry> listFunctions(
      Program program, Map<String, Object> args) {
    FunctionManager functionManager = program.getFunctionManager();
    int pageSize = getPageSizeArgument(args, DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT);

    Optional<String> namePatternOpt = getOptionalStringArgument(args, ARG_NAME_PATTERN);
    Optional<String> cursorOpt = getOptionalStringArgument(args, ARG_CURSOR);
    Optional<String> addressStartOpt = getOptionalStringArgument(args, ARG_ADDRESS_START);
    Optional<String> addressEndOpt = getOptionalStringArgument(args, ARG_ADDRESS_END);
    boolean verbose = getOptionalBooleanArgument(args, ARG_VERBOSE).orElse(false);

    FunctionCursor cursor =
        cursorOpt.map(value -> parseFunctionCursor(program, value)).orElse(null);

    Pattern namePattern = null;
    if (namePatternOpt.isPresent()) {
      try {
        namePattern = NameFilterPattern.compile(namePatternOpt.get(), 0);
      } catch (PatternSyntaxException e) {
        throw new GhidraMcpException(
            GhidraMcpError.invalid("name_pattern", namePatternOpt.get(), e.getMessage()));
      }
    }

    AddressSet addressBounds =
        buildAddressBounds(program, addressStartOpt.orElse(null), addressEndOpt.orElse(null));
    if (cursor != null && addressBounds != null && !addressBounds.contains(cursor.address)) {
      throw new GhidraMcpException(
          GhidraMcpError.invalid(
              ARG_CURSOR,
              cursor.toCursorString(),
              "cursor is outside the requested address range"));
    }

    FunctionIterator funcIter = selectFunctionIterator(functionManager, addressBounds, cursor);

    List<FunctionListEntry> paginatedResults = new ArrayList<>(pageSize + 1);
    boolean cursorMatched = cursor == null;
    boolean collectResults = cursor == null;
    while (funcIter.hasNext() && paginatedResults.size() <= pageSize) {
      Function function = funcIter.next();
      if (namePattern != null && !namePattern.matcher(function.getName()).matches()) {
        continue;
      }

      if (!collectResults) {
        if (matchesFunctionCursor(function, cursor)) {
          cursorMatched = true;
          collectResults = true;
        }
        continue;
      }

      paginatedResults.add(new FunctionListEntry(function, verbose));
    }

    if (!cursorMatched) {
      throw new GhidraMcpException(
          GhidraMcpError.invalid(
              ARG_CURSOR,
              cursor.toCursorString(),
              "cursor is invalid or no longer present in this function listing"));
    }

    boolean hasMore = paginatedResults.size() > pageSize;
    List<FunctionListEntry> results =
        hasMore ? new ArrayList<>(paginatedResults.subList(0, pageSize)) : paginatedResults;

    String nextCursor = null;
    if (hasMore && !results.isEmpty()) {
      FunctionListEntry lastFunc = results.get(results.size() - 1);
      nextCursor = encodeFunctionCursor(lastFunc.getSymbolId());
    }

    return new PaginatedResult<>(results, nextCursor);
  }

  private FunctionIterator selectFunctionIterator(
      FunctionManager functionManager, AddressSet addressBounds, FunctionCursor cursor) {
    if (addressBounds != null) {
      return functionManager.getFunctions(addressBounds, true);
    }
    if (cursor != null) {
      return functionManager.getFunctions(cursor.address, true);
    }
    return functionManager.getFunctions(true);
  }

  private boolean matchesFunctionCursor(Function function, FunctionCursor cursor) {
    return function != null
        && cursor != null
        && function.getSymbol() != null
        && function.getSymbol().getID() == cursor.symbolId;
  }

  private Mono<? extends Object> handleGet(Program program, Map<String, Object> args) {
    return Mono.fromCallable(
        () -> {
          FunctionManager functionManager = program.getFunctionManager();

          Optional<Long> symbolIdOpt = getOptionalLongArgument(args, ARG_SYMBOL_ID);
          Optional<String> addressOpt = getOptionalStringArgument(args, ARG_ADDRESS);
          Optional<String> nameOpt = getOptionalStringArgument(args, ARG_NAME);

          FunctionInfo info;

          // Apply precedence: symbol_id > address > name
          if (symbolIdOpt.isPresent()) {
            info = readBySymbolId(program, functionManager, symbolIdOpt.get());
          } else if (addressOpt.isPresent()) {
            info = readByAddress(program, functionManager, addressOpt.get());
          } else if (nameOpt.isPresent()) {
            info = readByName(program, nameOpt.get());
          } else {
            throw new GhidraMcpException(GhidraMcpError.missing("symbol_id, address, or name"));
          }

          Address entryPoint =
              info.getEntryPoint() != null
                  ? program.getAddressFactory().getAddress(info.getEntryPoint())
                  : null;
          if (entryPoint == null) {
            return info;
          }

          return ToolOutcome.of(info, NavigateToAddressEffect.listing(program, entryPoint));
        });
  }

  private FunctionInfo readBySymbolId(
      Program program, FunctionManager functionManager, Long symbolId) throws GhidraMcpException {
    Symbol symbol = program.getSymbolTable().getSymbol(symbolId);
    if (symbol != null && symbol.getSymbolType() == SymbolType.FUNCTION) {
      Function function = functionManager.getFunctionAt(symbol.getAddress());
      if (function == null) {
        function = getOrCreateFunction(program, symbol.getAddress());
      }
      if (function != null) {
        return new FunctionInfo(function);
      }
    }
    throw new GhidraMcpException(GhidraMcpError.notFound("function", "symbol_id=" + symbolId));
  }

  private FunctionInfo readByAddress(
      Program program, FunctionManager functionManager, String addressStr)
      throws GhidraMcpException {
    if (addressStr == null || addressStr.isBlank()) {
      throw new GhidraMcpException(GhidraMcpError.missing(ARG_ADDRESS));
    }

    try {
      Address functionAddress = parseAddressValue(program, addressStr, ARG_ADDRESS);
      if (functionAddress != null) {
        Function function = getOrCreateFunction(program, functionAddress);
        if (function == null) {
          function = followFunctionPointer(program, functionAddress);
        }
        if (function != null) {
          return new FunctionInfo(function);
        }
      }
    } catch (Exception e) {
      throw new GhidraMcpException(GhidraMcpError.parse("address", addressStr));
    }

    throw new GhidraMcpException(GhidraMcpError.notFound("function", "address=" + addressStr));
  }

  private FunctionInfo readByName(Program program, String name) throws GhidraMcpException {
    return new FunctionInfo(SymbolLookupHelper.resolveFunction(program, name));
  }

  private Mono<? extends Object> handleCreate(
      Program program, Map<String, Object> args, GhidraMcpTool annotation) {
    String toolOperation = annotation.mcpName() + ".create";
    String addressString = getRequiredStringArgument(args, ARG_ADDRESS);
    Optional<String> nameOpt = getOptionalStringArgument(args, ARG_FUNCTION_NAME);

    return parseAddressOrThrow(program, addressString, toolOperation, args)
        .flatMap(
            functionAddress -> {
              if (program.getFunctionManager().getFunctionAt(functionAddress) != null) {
                GhidraMcpError error =
                    GhidraMcpError.conflict("Function already exists at address " + addressString);
                return Mono.error(new GhidraMcpException(error));
              }

              return executeInTransaction(
                  program,
                  "MCP - Create Function at " + functionAddress,
                  () -> {
                    CreateFunctionCmd cmd =
                        new CreateFunctionCmd(
                            nameOpt.orElse(null),
                            functionAddress,
                            new AddressSet(functionAddress),
                            SourceType.USER_DEFINED);

                    boolean success = cmd.applyTo(program);
                    if (!success) {
                      String status =
                          Optional.ofNullable(cmd.getStatusMsg()).orElse("Unknown error");
                      throw new GhidraMcpException(
                          GhidraMcpError.failed("create function", status));
                    }

                    Function createdFunction = cmd.getFunction();
                    if (createdFunction == null) {
                      throw new GhidraMcpException(
                          GhidraMcpError.internal(
                              "Function creation succeeded but returned no function object"));
                    }

                    return ToolOutcome.of(
                        new FunctionInfo(createdFunction),
                        NavigateToAddressEffect.listing(program, createdFunction.getEntryPoint()));
                  });
            });
  }

  private List<String> getFunctionNameSamples(FunctionManager functionManager, int limit) {
    if (limit <= 0) {
      return List.of();
    }

    return StreamSupport.stream(functionManager.getFunctions(true).spliterator(), false)
        .map(Function::getName)
        .filter(name -> name != null && !name.isBlank())
        .distinct()
        .limit(limit)
        .collect(Collectors.toList());
  }

  private Mono<? extends Object> handleUpdatePrototype(
      Program program, PluginTool tool, Map<String, Object> args, GhidraMcpTool annotation) {
    String toolOperation = annotation.mcpName() + ".update_prototype";

    FunctionIdentifiers identifiers;
    try {
      identifiers = extractFunctionIdentifiers(args);
    } catch (GhidraMcpException e) {
      return Mono.error(e);
    }

    if (identifiers.isEmpty()) {
      return Mono.error(new GhidraMcpException(createMissingIdentifierError()));
    }

    Optional<String> rawPrototypeOpt =
        getOptionalStringArgument(args, ARG_PROTOTYPE)
            .map(String::trim)
            .filter(value -> !value.isEmpty());

    if (rawPrototypeOpt.isPresent()) {
      return Mono.fromCallable(
              () -> resolveFunctionByIdentifiers(program, identifiers, toolOperation))
          .map(function -> new UpdatePrototypeContext(program, function, rawPrototypeOpt.get()))
          .flatMap(context -> executePrototypeUpdate(program, annotation, tool, context));
    } else {
      String returnTypeName = getRequiredStringArgument(args, ARG_RETURN_TYPE);
      Optional<String> callingConventionOpt =
          getOptionalStringArgument(args, ARG_CALLING_CONVENTION);
      Optional<String> newFunctionNameOpt = getOptionalStringArgument(args, ARG_NEW_FUNCTION_NAME);
      Optional<List<Map<String, Object>>> parametersOpt =
          getOptionalListArgument(args, ARG_PARAMETERS);
      boolean noReturn = getOptionalBooleanArgument(args, ARG_NO_RETURN).orElse(false);

      return Mono.fromCallable(
              () ->
                  resolveFunctionForPrototype(
                      program,
                      tool,
                      identifiers,
                      returnTypeName,
                      callingConventionOpt,
                      newFunctionNameOpt,
                      parametersOpt,
                      noReturn,
                      toolOperation))
          .flatMap(context -> executePrototypeUpdate(program, annotation, tool, context));
    }
  }

  private Mono<? extends Object> executePrototypeUpdate(
      Program program, GhidraMcpTool annotation, PluginTool tool, UpdatePrototypeContext context) {
    return executeInTransaction(
        program,
        "MCP - Update Function Prototype: " + context.function().getName(),
        () -> applyPrototype(program, annotation, tool, context));
  }

  private Object applyPrototype(
      Program program, GhidraMcpTool annotation, PluginTool tool, UpdatePrototypeContext context)
      throws GhidraMcpException {
    Function function = context.function();
    String prototype = context.prototypeString();

    try {
      DataTypeManager dtm = program.getDataTypeManager();
      DataTypeQueryService service =
          tool != null ? tool.getService(DataTypeQueryService.class) : null;
      FunctionSignatureParser parser = new FunctionSignatureParser(dtm, service);
      FunctionDefinitionDataType parsedSignature = parser.parse(function.getSignature(), prototype);

      ghidra.app.cmd.function.ApplyFunctionSignatureCmd cmd =
          new ghidra.app.cmd.function.ApplyFunctionSignatureCmd(
              function.getEntryPoint(), parsedSignature, SourceType.USER_DEFINED);

      if (!cmd.applyTo(program)) {
        String status = Optional.ofNullable(cmd.getStatusMsg()).orElse("Unknown error");
        throw new GhidraMcpException(GhidraMcpError.failed("apply function prototype", status));
      }

      return ToolOutcome.of(
          new FunctionInfo(function),
          NavigateToAddressEffect.listing(program, function.getEntryPoint()));
    } catch (GhidraMcpException e) {
      throw e;
    } catch (Exception e) {
      throw new GhidraMcpException(GhidraMcpError.parse("function prototype", prototype));
    }
  }

  private UpdatePrototypeContext resolveFunctionForPrototype(
      Program program,
      PluginTool tool,
      FunctionIdentifiers identifiers,
      String returnTypeName,
      Optional<String> callingConventionOpt,
      Optional<String> newFunctionNameOpt,
      Optional<List<Map<String, Object>>> parametersOpt,
      boolean noReturn,
      String toolOperation)
      throws GhidraMcpException {
    Function function = resolveFunctionByIdentifiers(program, identifiers, toolOperation);

    String prototype =
        buildPrototypeString(
            program,
            tool,
            function,
            returnTypeName,
            callingConventionOpt,
            newFunctionNameOpt.orElse(function.getName()),
            parametersOpt,
            noReturn);

    return new UpdatePrototypeContext(program, function, prototype);
  }

  private Function resolveFunctionByIdentifiers(
      Program program, FunctionIdentifiers identifiers, String toolOperation)
      throws GhidraMcpException {
    FunctionManager funcMan = program.getFunctionManager();
    SymbolTable symbolTable = program.getSymbolTable();
    Function function = null;

    if (identifiers.symbolId().isPresent()) {
      Symbol symbol = symbolTable.getSymbol(identifiers.symbolId().get());
      if (symbol != null && symbol.getSymbolType() == SymbolType.FUNCTION) {
        function = funcMan.getFunctionAt(symbol.getAddress());
      }
    }

    if (function == null && identifiers.address().isPresent()) {
      String addressString = identifiers.address().get();
      try {
        Address entryPoint = parseAddressValue(program, addressString, ARG_ADDRESS);
        function = getOrCreateFunction(program, entryPoint);
      } catch (GhidraMcpException e) {
        throw e;
      } catch (Exception e) {
        throw new GhidraMcpException(
            GhidraMcpErrorUtils.addressParseError(addressString, toolOperation, e));
      }
    }

    if (function == null && identifiers.name().isPresent()) {
      try {
        function = SymbolLookupHelper.resolveFunction(program, identifiers.name().get());
      } catch (GhidraMcpException e) {
        if (!e.isResourceNotFoundError()) {
          throw e;
        }
      }
    }

    if (function == null) {
      String searchDesc =
          identifiers
              .symbolId()
              .map(id -> "symbol_id=" + id)
              .or(() -> identifiers.address().map(a -> "address=" + a))
              .or(() -> identifiers.name().map(n -> "name=" + n))
              .orElse("unknown");
      throw new GhidraMcpException(GhidraMcpError.notFound("function", searchDesc));
    }

    return function;
  }

  private String buildPrototypeString(
      Program program,
      PluginTool tool,
      Function function,
      String returnTypeName,
      Optional<String> callingConventionOpt,
      String functionName,
      Optional<List<Map<String, Object>>> parametersOpt,
      boolean noReturn)
      throws GhidraMcpException {
    StringBuilder prototype = new StringBuilder();

    DataType returnType = resolveDataTypeWithFallback(program.getDataTypeManager(), returnTypeName);
    if (returnType == null) {
      throw new GhidraMcpException(
          GhidraMcpError.invalid(ARG_RETURN_TYPE, returnTypeName, "could not be resolved"));
    }

    String normalizedReturnType = normalizeTypeExpressionForPrototype(returnTypeName);

    prototype.append(normalizedReturnType);
    callingConventionOpt.ifPresent(cc -> prototype.append(" ").append(cc));
    prototype.append(" ").append(functionName).append("(");

    if (parametersOpt.isPresent() && !parametersOpt.get().isEmpty()) {
      List<String> params = new ArrayList<>();
      for (Map<String, Object> param : parametersOpt.get()) {
        params.add(parameterToString(program, tool, param));
      }
      prototype.append(String.join(", ", params));
    }

    if (noReturn) {
      function.setNoReturn(true);
    }

    prototype.append(")");
    return prototype.toString();
  }

  private String parameterToString(Program program, PluginTool tool, Map<String, Object> paramMap)
      throws GhidraMcpException {
    String name = getOptionalStringArgument(paramMap, ARG_PARAMETER_NAME).orElse(null);
    String dataType = getOptionalStringArgument(paramMap, ARG_PARAMETER_DATA_TYPE).orElse(null);

    if (name == null || dataType == null) {
      throw new GhidraMcpException(
          GhidraMcpError.invalid("parameter", "must include both 'name' and 'data_type' fields"));
    }

    if ("...".equals(dataType)) {
      return "...";
    }

    DataType resolved = resolveDataTypeWithFallback(program.getDataTypeManager(), dataType);
    if (resolved == null) {
      throw new GhidraMcpException(
          GhidraMcpError.invalid("parameter.data_type", dataType, "could not be resolved"));
    }

    String normalizedDataType = normalizeTypeExpressionForPrototype(dataType);
    return normalizedDataType + " " + name;
  }

  private String normalizeTypeExpressionForPrototype(String typeExpression) {
    if (typeExpression == null) {
      return "";
    }
    String collapsed = typeExpression.replaceAll("\\s+", " ").trim();
    return collapsed.replaceAll("\\s*\\[\\s*", "[").replaceAll("\\s*\\]\\s*", "]");
  }

  private record UpdatePrototypeContext(
      Program program, Function function, String prototypeString) {}

  private record FunctionIdentifiers(
      Optional<Long> symbolId, Optional<String> address, Optional<String> name) {
    boolean isEmpty() {
      return symbolId.isEmpty() && address.isEmpty() && name.isEmpty();
    }
  }

  private FunctionIdentifiers extractFunctionIdentifiers(Map<String, Object> args) {
    Long symbolId = getOptionalLongArgument(args, ARG_SYMBOL_ID).orElse(null);
    String addressValue = getOptionalStringArgument(args, ARG_ADDRESS).orElse(null);
    String functionNameValue = getOptionalStringArgument(args, ARG_NAME).orElse(null);
    return new FunctionIdentifiers(
        Optional.ofNullable(symbolId),
        Optional.ofNullable(addressValue),
        Optional.ofNullable(functionNameValue));
  }

  private GhidraMcpError createMissingIdentifierError() {
    return GhidraMcpError.of(
        "At least one function identifier must be provided (symbol_id, address, or name)",
        "Include one of: symbol_id, address, or name");
  }

  private Mono<Address> parseAddressOrThrow(
      Program program, String addressString, String toolOperation, Map<String, Object> args) {
    return Mono.fromCallable(
            () -> {
              return parseAddressValue(program, addressString, ARG_ADDRESS);
            })
        .onErrorMap(
            e -> {
              if (e instanceof GhidraMcpException) {
                return e;
              }
              return new GhidraMcpException(
                  GhidraMcpErrorUtils.addressParseError(addressString, toolOperation, e));
            });
  }

  private Mono<? extends Object> handleListVariables(
      Program program, Map<String, Object> args, GhidraMcpTool annotation) {
    String toolOperation = annotation.mcpName() + ".list_variables";

    FunctionIdentifiers identifiers;
    try {
      identifiers = extractFunctionIdentifiers(args);
    } catch (GhidraMcpException e) {
      return Mono.error(e);
    }

    if (identifiers.isEmpty()) {
      return Mono.error(new GhidraMcpException(createMissingIdentifierError()));
    }

    return withTaskMonitor(
        "functions.list_variables",
        monitor -> {
          Function function = resolveFunctionByIdentifiers(program, identifiers, toolOperation);
          return listFunctionVariables(function, program, args, monitor);
        });
  }

  private Mono<? extends Object> handleUpdateVariable(
      Program program, Map<String, Object> args, GhidraMcpTool annotation, String actionName) {
    String toolOperation = annotation.mcpName() + "." + actionName;

    FunctionIdentifiers identifiers;
    try {
      identifiers = extractFunctionIdentifiers(args);
    } catch (GhidraMcpException e) {
      return Mono.error(e);
    }

    if (identifiers.isEmpty()) {
      return Mono.error(new GhidraMcpException(createMissingIdentifierError()));
    }

    Optional<String> currentNameOpt = getOptionalStringArgument(args, ARG_CURRENT_NAME);
    Optional<Long> variableSymbolIdOpt = getOptionalLongArgument(args, ARG_VARIABLE_SYMBOL_ID);
    Optional<String> newNameOpt = getOptionalStringArgument(args, ARG_NEW_NAME);
    Optional<String> newDataTypeOpt = getOptionalStringArgument(args, ARG_NEW_DATA_TYPE);

    if (currentNameOpt.isEmpty() && variableSymbolIdOpt.isEmpty()) {
      return Mono.error(
          new GhidraMcpException(
              GhidraMcpError.of(
                  "Either 'current_name' or 'variable_symbol_id' is required",
                  "Use 'variable_symbol_id' from list_variables for stable targeting in batch"
                      + " operations")));
    }

    if (newNameOpt.isEmpty() && newDataTypeOpt.isEmpty()) {
      return Mono.error(
          new GhidraMcpException(
              GhidraMcpError.of(
                  "At least one of 'new_name' or 'new_data_type' is required",
                  "Provide 'new_name' to rename, 'new_data_type' to retype, or both")));
    }

    return withTaskMonitor(
            "functions." + actionName,
            monitor -> {
              Function function = resolveFunctionByIdentifiers(program, identifiers, toolOperation);
              LocalSymbolMap localSymbolMap =
                  getDecompilerLocalSymbolMap(program, function, monitor, "update variable");

              HighSymbol targetSymbol =
                  findVariableSymbol(
                      localSymbolMap,
                      variableSymbolIdOpt.orElse(null),
                      currentNameOpt.orElse(null),
                      function.getName());

              DataType resolvedType = null;
              if (newDataTypeOpt.isPresent()) {
                DataTypeManager dtm = program.getDataTypeManager();
                resolvedType = resolveDataTypeWithFallback(dtm, newDataTypeOpt.get());
                if (resolvedType == null) {
                  throw new GhidraMcpException(
                      GhidraMcpError.of(
                          "Cannot resolve data type: " + newDataTypeOpt.get(),
                          "Use a valid type like 'int', 'char *', 'byte', or a full path like"
                              + " '/MyCategory/MyStruct'"));
                }
              }

              return new UpdateVariableContext(
                  function, targetSymbol, newNameOpt.orElse(null), resolvedType);
            })
        .flatMap(
            context -> {
              String oldName = context.symbol().getName();
              String effectiveNewName = context.newName() != null ? context.newName() : oldName;
              String description =
                  "MCP - Update Variable: " + oldName + " in " + context.function().getName();

              return executeInTransaction(
                  program,
                  description,
                  () -> {
                    try {
                      HighFunctionDBUtil.updateDBVariable(
                          context.symbol(),
                          effectiveNewName,
                          context.newDataType(),
                          SourceType.USER_DEFINED);
                    } catch (Exception e) {
                      throw new GhidraMcpException(
                          GhidraMcpError.failed(
                              "update variable",
                              "Failed to update '" + oldName + "': " + e.getMessage()));
                    }

                    var result = new java.util.LinkedHashMap<String, Object>();
                    result.put("function", context.function().getName());
                    result.put("variable_symbol_id", Long.toString(context.symbol().getId()));
                    result.put("old_name", oldName);
                    result.put("new_name", effectiveNewName);
                    if (context.newDataType() != null) {
                      result.put("new_data_type", context.newDataType().getName());
                    }
                    return result;
                  });
            });
  }

  private HighSymbol findVariableSymbol(
      LocalSymbolMap localSymbolMap, Long variableSymbolId, String currentName, String functionName)
      throws GhidraMcpException {
    HighSymbol targetSymbol = null;
    java.util.Iterator<HighSymbol> symbolIterator = localSymbolMap.getSymbols();

    while (symbolIterator.hasNext()) {
      HighSymbol sym = symbolIterator.next();

      if (variableSymbolId != null) {
        // Match against HighSymbol.getId() which works for both listing-backed
        // and decompiler-synthetic variables (bVar0, etc.)
        if (sym.getId() == variableSymbolId) {
          targetSymbol = sym;
          break;
        }
        Symbol listingSymbol = sym.getSymbol();
        if (listingSymbol != null && listingSymbol.getID() == variableSymbolId) {
          targetSymbol = sym;
          break;
        }
      } else if (currentName != null && currentName.equals(sym.getName())) {
        targetSymbol = sym;
        break;
      }
    }

    if (targetSymbol == null) {
      String identifier =
          variableSymbolId != null
              ? "variable_symbol_id=" + variableSymbolId
              : "'" + currentName + "'";
      throw new GhidraMcpException(
          GhidraMcpError.notFound("variable", identifier + " in function '" + functionName + "'"));
    }

    return targetSymbol;
  }

  private record UpdateVariableContext(
      Function function, HighSymbol symbol, String newName, DataType newDataType) {}

  private Mono<? extends Object> handleListUnionFieldCandidates(
      Program program, Map<String, Object> args, GhidraMcpTool annotation) {
    String toolOperation = annotation.mcpName() + "." + ACTION_LIST_UNION_FIELD_CANDIDATES;

    FunctionIdentifiers identifiers;
    try {
      identifiers = extractFunctionIdentifiers(args);
    } catch (GhidraMcpException e) {
      return Mono.error(e);
    }

    if (identifiers.isEmpty()) {
      return Mono.error(new GhidraMcpException(createMissingIdentifierError()));
    }

    return withTaskMonitor(
        "functions.list_union_field_candidates",
        monitor -> {
          Function function = resolveFunctionByIdentifiers(program, identifiers, toolOperation);
          List<UnionFieldCandidate> candidates = discoverUnionFieldCandidates(function, monitor);
          return filterUnionFieldCandidates(program, candidates, args).stream()
              .map(this::unionFieldCandidateToMap)
              .collect(Collectors.toList());
        });
  }

  private Mono<? extends Object> handleForceUnionField(
      Program program, Map<String, Object> args, GhidraMcpTool annotation) {
    String toolOperation = annotation.mcpName() + "." + ACTION_FORCE_UNION_FIELD;

    FunctionIdentifiers identifiers;
    try {
      identifiers = extractFunctionIdentifiers(args);
    } catch (GhidraMcpException e) {
      return Mono.error(e);
    }

    if (identifiers.isEmpty()) {
      return Mono.error(new GhidraMcpException(createMissingIdentifierError()));
    }

    return withTaskMonitor(
            "functions.force_union_field",
            monitor -> {
              Function function = resolveFunctionByIdentifiers(program, identifiers, toolOperation);
              List<UnionFieldCandidate> candidates =
                  discoverUnionFieldCandidates(function, monitor);
              UnionFieldCandidate candidate = selectUnionFieldCandidate(program, candidates, args);
              int fieldOrdinal = resolveUnionFieldOrdinal(candidate, args);
              String fieldName = getUnionFieldName(candidate, fieldOrdinal);
              return new ForceUnionFieldContext(function, candidate, fieldOrdinal, fieldName);
            })
        .flatMap(
            context ->
                executeInTransaction(
                    program,
                    "MCP - Force Union Field: "
                        + context.function().getName()
                        + " -> "
                        + context.fieldName(),
                    () -> {
                      try {
                        HighFunctionDBUtil.writeUnionFacet(
                            context.function(),
                            context.candidate().parentDataType(),
                            context.fieldOrdinal(),
                            context.candidate().pcAddress(),
                            context.candidate().dynamicHash(),
                            SourceType.USER_DEFINED);
                      } catch (Exception e) {
                        throw new GhidraMcpException(
                            GhidraMcpError.failed("force union field", e.getMessage()));
                      }

                      Map<String, Object> result = new LinkedHashMap<>();
                      result.put("function", context.function().getName());
                      result.put("entry_point", context.function().getEntryPoint().toString());
                      result.put("candidate_index", context.candidate().index());
                      result.put("pc_address", context.candidate().pcAddress().toString());
                      result.put("dynamic_hash", Long.toString(context.candidate().dynamicHash()));
                      result.put(
                          "dynamic_hash_hex",
                          "0x" + Long.toUnsignedString(context.candidate().dynamicHash(), 16));
                      result.put("union_type", context.candidate().unionTypePath());
                      result.put("parent_data_type", context.candidate().parentDataTypePath());
                      result.put("field_ordinal", context.fieldOrdinal());
                      result.put("field_name", context.fieldName());
                      return ToolOutcome.of(
                          result,
                          NavigateToAddressEffect.decompiler(
                              program, context.function().getEntryPoint()));
                    }));
  }

  private List<UnionFieldCandidate> discoverUnionFieldCandidates(
      Function function, TaskMonitor monitor) {
    DecompInterface decompInterface = new DecompInterface();
    try {
      decompInterface.setOptions(new DecompileOptions());
      decompInterface.openProgram(function.getProgram());
      DecompileResults results =
          decompInterface.decompileFunction(
              function, GhidraMcpServer.getRequestTimeoutSeconds(), monitor);
      if (results == null || !results.decompileCompleted()) {
        String error =
            results != null && results.getErrorMessage() != null
                ? results.getErrorMessage()
                : "decompilation did not complete";
        throw new GhidraMcpException(GhidraMcpError.failed("list union field candidates", error));
      }

      HighFunction highFunction = results.getHighFunction();
      ClangTokenGroup markup = results.getCCodeMarkup();
      if (highFunction == null || markup == null) {
        return List.of();
      }

      List<ClangNode> flattened = new ArrayList<>();
      markup.flatten(flattened);

      LinkedHashMap<String, UnionFieldCandidate> candidatesByKey = new LinkedHashMap<>();
      for (ClangNode node : flattened) {
        if (!(node instanceof ClangFieldToken token)) {
          continue;
        }

        Composite composite = getCompositeDataType(token);
        if (!(composite instanceof Union unionDataType)) {
          continue;
        }

        UnionFacetTarget target = determineUnionFacetTarget(token, unionDataType);
        if (target == null || target.accessOp() == null || target.accessVarnode() == null) {
          continue;
        }

        DynamicHash dynamicHash =
            new DynamicHash(target.accessOp(), target.accessSlot(), highFunction);
        Address pcAddress = dynamicHash.getAddress();
        if (pcAddress == null || pcAddress == Address.NO_ADDRESS) {
          continue;
        }

        List<UnionFieldOption> fieldOptions =
            buildUnionFieldOptions(unionDataType, target.parentDataType(), target.accessVarnode());
        Set<Integer> selectableOrdinals =
            fieldOptions.stream()
                .filter(UnionFieldOption::selectable)
                .map(UnionFieldOption::ordinal)
                .collect(Collectors.toCollection(LinkedHashSet::new));

        String key =
            pcAddress
                + ":"
                + dynamicHash.getHash()
                + ":"
                + target.accessSlot()
                + ":"
                + dataTypePath(target.parentDataType());
        if (!candidatesByKey.containsKey(key)) {
          int index = candidatesByKey.size();
          candidatesByKey.put(
              key,
              new UnionFieldCandidate(
                  index,
                  token.getText(),
                  addressToString(token.getMinAddress()),
                  dataTypePath(unionDataType),
                  unionDataType.getName(),
                  dataTypePath(target.parentDataType()),
                  target.parentDataType(),
                  target.accessSlot(),
                  target.accessOp().getMnemonic(),
                  target.accessOp().toString(),
                  addressToString(target.accessOp().getSeqnum().getTarget()),
                  pcAddress,
                  dynamicHash.getHash(),
                  fieldOptions,
                  selectableOrdinals));
        }
      }

      return new ArrayList<>(candidatesByKey.values());
    } finally {
      decompInterface.dispose();
    }
  }

  private Composite getCompositeDataType(ClangFieldToken token) {
    DataType dataType = unwrapTypeDef(token.getDataType());
    return dataType instanceof Composite composite ? composite : null;
  }

  private UnionFacetTarget determineUnionFacetTarget(ClangFieldToken token, Union unionDataType) {
    PcodeOp accessOp = token.getPcodeOp();
    if (accessOp == null) {
      return null;
    }

    int opcode = accessOp.getOpcode();
    DataType parentDataType = null;
    Varnode accessVarnode = null;
    int accessSlot = 0;

    if (opcode == PcodeOp.PTRSUB) {
      parentDataType = typeIsUnionRelated(accessOp.getInput(0), unionDataType);
      if (parentDataType != null) {
        accessVarnode = accessOp.getInput(0);
        accessSlot = 0;

        while (accessOp.getInput(1).getOffset() == 0) {
          Varnode output = accessOp.getOutput();
          if (output == null) {
            break;
          }
          PcodeOp loneDescendant = output.getLoneDescend();
          if (loneDescendant == null) {
            break;
          }

          accessOp = loneDescendant;
          accessVarnode = output;
          accessSlot = accessOp.getSlot(accessVarnode);
          if (accessOp.getOpcode() != PcodeOp.PTRSUB || accessOp.getInput(1).getOffset() != 0) {
            break;
          }
        }

        return new UnionFacetTarget(accessOp, accessVarnode, accessSlot, parentDataType);
      }
    } else {
      for (accessSlot = 0; accessSlot < accessOp.getNumInputs(); accessSlot++) {
        accessVarnode = accessOp.getInput(accessSlot);
        parentDataType = typeIsUnionRelated(accessVarnode, unionDataType);
        if (parentDataType != null) {
          break;
        }
      }

      if (parentDataType != null) {
        if (opcode == PcodeOp.SUBPIECE && accessSlot == 0 && !(parentDataType instanceof Pointer)) {
          accessSlot = -1;
          accessVarnode = accessOp.getOutput();
        }
        return new UnionFacetTarget(accessOp, accessVarnode, accessSlot, parentDataType);
      }
    }

    accessSlot = -1;
    accessVarnode = accessOp.getOutput();
    if (accessVarnode != null) {
      parentDataType = typeIsUnionRelated(accessVarnode, unionDataType);
      if (parentDataType != null) {
        return new UnionFacetTarget(accessOp, accessVarnode, accessSlot, parentDataType);
      }
    }

    return null;
  }

  private DataType typeIsUnionRelated(Varnode varnode, Union unionDataType) {
    if (varnode == null) {
      return null;
    }

    HighVariable highVariable = varnode.getHigh();
    if (highVariable == null) {
      return null;
    }

    DataType dataType = unwrapTypeDef(highVariable.getDataType());
    DataType candidate = dataType;
    if (candidate instanceof Pointer pointer) {
      candidate = pointer.getDataType();
    } else if (candidate instanceof PartialUnion partialUnion) {
      candidate = partialUnion.getParent();
      candidate = unwrapTypeDef(candidate);
    }

    if (isSameDataType(candidate, unionDataType)) {
      return dataType;
    }

    HighSymbol symbol = highVariable.getSymbol();
    if (symbol == null) {
      return null;
    }

    dataType = unwrapTypeDef(symbol.getDataType());
    return isSameDataType(dataType, unionDataType) ? dataType : null;
  }

  private DataType unwrapTypeDef(DataType dataType) {
    while (dataType instanceof TypeDef typeDef) {
      dataType = typeDef.getBaseDataType();
    }
    return dataType;
  }

  private boolean isSameDataType(DataType candidate, DataType expected) {
    if (candidate == expected) {
      return true;
    }
    if (candidate == null || expected == null) {
      return false;
    }
    String candidatePath = candidate.getPathName();
    String expectedPath = expected.getPathName();
    return candidatePath != null && candidatePath.equals(expectedPath);
  }

  private List<UnionFieldOption> buildUnionFieldOptions(
      Union unionDataType, DataType parentDataType, Varnode accessVarnode) {
    int accessSize = accessVarnode.getSize();
    int accessStartOffset = 0;
    boolean requireExactFit = true;

    if (parentDataType instanceof Pointer) {
      accessSize = 0;
    }
    if (parentDataType instanceof PartialUnion partialUnion) {
      accessStartOffset = partialUnion.getOffset();
      requireExactFit = false;
    }

    int accessEndOffset = accessStartOffset + accessSize;
    List<UnionFieldOption> options = new ArrayList<>();
    boolean noFieldSelectable =
        accessSize == 0 || (requireExactFit && accessSize == parentDataType.getLength());
    options.add(new UnionFieldOption(-1, "(no field)", null, null, null, noFieldSelectable));

    DataTypeComponent[] components = unionDataType.getDefinedComponents();
    for (int i = 0; i < components.length; i++) {
      DataTypeComponent component = components[i];
      String fieldName = component.getFieldName();
      if (fieldName == null || fieldName.isBlank()) {
        fieldName = component.getDefaultFieldName();
      }

      int componentStart = component.getOffset();
      int componentEnd = component.getOffset() + component.getLength();
      boolean selectable =
          accessSize == 0
              || (requireExactFit
                  ? accessStartOffset == componentStart && accessEndOffset == componentEnd
                  : accessStartOffset >= componentStart && accessEndOffset <= componentEnd);

      options.add(
          new UnionFieldOption(
              i,
              fieldName,
              component.getOffset(),
              component.getLength(),
              dataTypePath(component.getDataType()),
              selectable));
    }

    return options;
  }

  private List<UnionFieldCandidate> filterUnionFieldCandidates(
      Program program, List<UnionFieldCandidate> candidates, Map<String, Object> args) {
    Optional<String> unionFilter =
        getOptionalStringArgument(args, ARG_UNION_TYPE_PATH)
            .map(String::trim)
            .filter(v -> !v.isEmpty());
    Optional<String> tokenTextFilter =
        getOptionalStringArgument(args, ARG_TOKEN_TEXT).map(String::trim).filter(v -> !v.isEmpty());
    Optional<Address> pcAddressFilter =
        getOptionalStringArgument(args, ARG_PC_ADDRESS)
            .map(String::trim)
            .filter(v -> !v.isEmpty())
            .map(value -> parseAddressValue(program, value, ARG_PC_ADDRESS));
    Optional<Long> dynamicHashFilter = parseOptionalFlexibleLong(args, ARG_DYNAMIC_HASH);

    return candidates.stream()
        .filter(
            candidate -> unionFilter.isEmpty() || matchesUnionFilter(candidate, unionFilter.get()))
        .filter(
            candidate ->
                tokenTextFilter.isEmpty()
                    || tokenTextFilter.get().equalsIgnoreCase(candidate.tokenText()))
        .filter(
            candidate ->
                pcAddressFilter.isEmpty() || candidate.pcAddress().equals(pcAddressFilter.get()))
        .filter(
            candidate ->
                dynamicHashFilter.isEmpty() || candidate.dynamicHash() == dynamicHashFilter.get())
        .collect(Collectors.toList());
  }

  private boolean matchesUnionFilter(UnionFieldCandidate candidate, String filter) {
    return filter.equalsIgnoreCase(candidate.unionTypePath())
        || filter.equalsIgnoreCase(candidate.unionName())
        || filter.equalsIgnoreCase(candidate.parentDataTypePath());
  }

  private UnionFieldCandidate selectUnionFieldCandidate(
      Program program, List<UnionFieldCandidate> candidates, Map<String, Object> args) {
    List<UnionFieldCandidate> filteredCandidates =
        filterUnionFieldCandidates(program, candidates, args);
    Optional<Integer> candidateIndexOpt = getOptionalIntArgument(args, ARG_CANDIDATE_INDEX);

    if (candidateIndexOpt.isPresent()) {
      int candidateIndex = candidateIndexOpt.get();
      return filteredCandidates.stream()
          .filter(candidate -> candidate.index() == candidateIndex)
          .findFirst()
          .orElseThrow(
              () ->
                  new GhidraMcpException(
                      GhidraMcpError.notFound(
                          "union field candidate", "candidate_index=" + candidateIndex)));
    }

    if (filteredCandidates.isEmpty()) {
      throw new GhidraMcpException(
          GhidraMcpError.notFound("union field candidate", "pc_address/dynamic_hash filters"));
    }
    if (filteredCandidates.size() > 1) {
      throw new GhidraMcpException(
          GhidraMcpError.invalid(
              "union field candidate",
              filteredCandidates.size(),
              "filters matched multiple candidates; pass candidate_index"));
    }
    return filteredCandidates.get(0);
  }

  private int resolveUnionFieldOrdinal(UnionFieldCandidate candidate, Map<String, Object> args) {
    Optional<Integer> fieldOrdinalOpt = getOptionalIntArgument(args, ARG_FIELD_ORDINAL);
    if (fieldOrdinalOpt.isPresent()) {
      int fieldOrdinal = fieldOrdinalOpt.get();
      validateUnionFieldOrdinal(candidate, fieldOrdinal, ARG_FIELD_ORDINAL);
      return fieldOrdinal;
    }

    String fieldName = getRequiredStringArgument(args, ARG_FIELD_NAME);
    if ("(no field)".equalsIgnoreCase(fieldName.trim())
        || "none".equalsIgnoreCase(fieldName.trim())) {
      validateUnionFieldOrdinal(candidate, -1, ARG_FIELD_NAME);
      return -1;
    }

    for (UnionFieldOption option : candidate.fieldOptions()) {
      if (option.ordinal() >= 0 && option.name().equalsIgnoreCase(fieldName.trim())) {
        validateUnionFieldOrdinal(candidate, option.ordinal(), ARG_FIELD_NAME);
        return option.ordinal();
      }
    }

    throw new GhidraMcpException(
        GhidraMcpError.invalid(
            ARG_FIELD_NAME,
            fieldName,
            "not a field of "
                + candidate.unionTypePath()
                + "; selectable fields: "
                + selectableFieldNames(candidate)));
  }

  private void validateUnionFieldOrdinal(
      UnionFieldCandidate candidate, int fieldOrdinal, String argumentName) {
    if (!candidate.selectableFieldOrdinals().contains(fieldOrdinal)) {
      throw new GhidraMcpException(
          GhidraMcpError.invalid(
              argumentName,
              fieldOrdinal,
              "field is not selectable for this p-code access; selectable fields: "
                  + selectableFieldNames(candidate)));
    }
  }

  private String selectableFieldNames(UnionFieldCandidate candidate) {
    return candidate.fieldOptions().stream()
        .filter(UnionFieldOption::selectable)
        .map(UnionFieldOption::name)
        .collect(Collectors.joining(", "));
  }

  private String getUnionFieldName(UnionFieldCandidate candidate, int fieldOrdinal) {
    return candidate.fieldOptions().stream()
        .filter(option -> option.ordinal() == fieldOrdinal)
        .map(UnionFieldOption::name)
        .findFirst()
        .orElse("(unknown)");
  }

  private Map<String, Object> unionFieldCandidateToMap(UnionFieldCandidate candidate) {
    Map<String, Object> result = new LinkedHashMap<>();
    result.put("candidate_index", candidate.index());
    result.put("token_text", candidate.tokenText());
    result.put("token_address", candidate.tokenAddress());
    result.put("union_type", candidate.unionTypePath());
    result.put("union_name", candidate.unionName());
    result.put("parent_data_type", candidate.parentDataTypePath());
    result.put("access_slot", candidate.accessSlot());
    result.put("pcode_mnemonic", candidate.pcodeMnemonic());
    result.put("pcode", candidate.pcodeText());
    result.put("pcode_address", candidate.pcodeAddress());
    result.put("pc_address", candidate.pcAddress().toString());
    result.put("dynamic_hash", Long.toString(candidate.dynamicHash()));
    result.put("dynamic_hash_hex", "0x" + Long.toUnsignedString(candidate.dynamicHash(), 16));
    result.put(
        "fields",
        candidate.fieldOptions().stream()
            .map(this::unionFieldOptionToMap)
            .collect(Collectors.toList()));
    return result;
  }

  private Map<String, Object> unionFieldOptionToMap(UnionFieldOption option) {
    Map<String, Object> result = new LinkedHashMap<>();
    result.put("ordinal", option.ordinal());
    result.put("name", option.name());
    result.put("selectable", option.selectable());
    if (option.offset() != null) {
      result.put("offset", option.offset());
    }
    if (option.length() != null) {
      result.put("length", option.length());
    }
    if (option.dataType() != null) {
      result.put("data_type", option.dataType());
    }
    return result;
  }

  private Optional<Long> parseOptionalFlexibleLong(Map<String, Object> args, String argumentName) {
    Object rawValue = args.get(argumentName);
    if (rawValue == null) {
      return Optional.empty();
    }

    String value =
        rawValue instanceof String ? ((String) rawValue).trim() : rawValue.toString().trim();
    if (value.isEmpty()) {
      return Optional.empty();
    }

    try {
      if (value.startsWith("0x") || value.startsWith("0X")) {
        return Optional.of((long) Long.parseUnsignedLong(value.substring(2), 16));
      }
      return Optional.of(Long.parseLong(value));
    } catch (NumberFormatException e) {
      throw new GhidraMcpException(
          GhidraMcpError.invalid(
              argumentName, rawValue, "must be a signed integer or 0x hex value"));
    }
  }

  private String dataTypePath(DataType dataType) {
    return dataType != null ? dataType.getPathName() : null;
  }

  private String addressToString(Address address) {
    return address != null && address != Address.NO_ADDRESS ? address.toString() : null;
  }

  private record UnionFacetTarget(
      PcodeOp accessOp, Varnode accessVarnode, int accessSlot, DataType parentDataType) {}

  private record UnionFieldOption(
      int ordinal,
      String name,
      Integer offset,
      Integer length,
      String dataType,
      boolean selectable) {}

  private record UnionFieldCandidate(
      int index,
      String tokenText,
      String tokenAddress,
      String unionTypePath,
      String unionName,
      String parentDataTypePath,
      DataType parentDataType,
      int accessSlot,
      String pcodeMnemonic,
      String pcodeText,
      String pcodeAddress,
      Address pcAddress,
      long dynamicHash,
      List<UnionFieldOption> fieldOptions,
      Set<Integer> selectableFieldOrdinals) {}

  private record ForceUnionFieldContext(
      Function function, UnionFieldCandidate candidate, int fieldOrdinal, String fieldName) {}

  private PaginatedResult<FunctionVariableInfo> listFunctionVariables(
      Function function, Program program, Map<String, Object> args, TaskMonitor monitor) {
    Optional<String> cursorOpt = getOptionalStringArgument(args, ARG_CURSOR);
    int pageSize = getPageSizeArgument(args, DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT);
    boolean verbose = getOptionalBooleanArgument(args, ARG_VERBOSE).orElse(false);
    LocalSymbolMap localSymbolMap =
        getDecompilerLocalSymbolMap(program, function, monitor, "list variables");

    java.util.Set<String> representedVariableKeys = new java.util.LinkedHashSet<>();
    List<VariableListEntry> variableEntries = new ArrayList<>();
    java.util.Iterator<HighSymbol> symbolIterator = localSymbolMap.getSymbols();
    while (symbolIterator.hasNext()) {
      HighSymbol symbol = symbolIterator.next();
      if (symbol != null && !symbol.isHiddenReturn()) {
        Variable functionVariable = HighFunctionDBUtil.getFunctionVariable(symbol);
        if (functionVariable != null) {
          representedVariableKeys.add(variableIdentityKey(functionVariable));
        }
        FunctionVariableInfo info = new FunctionVariableInfo(symbol, verbose);
        variableEntries.add(
            new VariableListEntry(
                info,
                symbol.isParameter() ? 0 : 1,
                symbol.isParameter() ? symbol.getCategoryIndex() : 0,
                symbol.getStorage() != null ? symbol.getStorage().toString() : info.getStorage(),
                symbol.getId()));
      }
    }

    for (Variable variable : function.getAllVariables()) {
      String variableKey = variableIdentityKey(variable);
      if (!representedVariableKeys.add(variableKey)) {
        continue;
      }
      Long variableSymbolId = variable.getSymbol() != null ? variable.getSymbol().getID() : null;
      FunctionVariableInfo info = new FunctionVariableInfo(variable, variableSymbolId, verbose);
      int parameterOrdinal = variable instanceof Parameter parameter ? parameter.getOrdinal() : 0;
      variableEntries.add(
          new VariableListEntry(
              info,
              info.isParameter() ? 0 : 1,
              parameterOrdinal,
              info.getStorage(),
              info.getVariableSymbolId() != null ? info.getVariableSymbolId() : Long.MAX_VALUE));
    }

    variableEntries.sort(
        Comparator.comparingInt(VariableListEntry::sortGroup)
            .thenComparingInt(VariableListEntry::sortIndex)
            .thenComparing(entry -> entry.storage() != null ? entry.storage() : "")
            .thenComparingLong(VariableListEntry::sortId));

    List<VariableListEntry> deduplicatedEntries = new ArrayList<>();
    java.util.Set<String> seenVariableKeys = new java.util.LinkedHashSet<>();
    for (VariableListEntry entry : variableEntries) {
      FunctionVariableInfo variableInfo = entry.info();
      String dedupeKey =
          variableInfo.getVariableSymbolId() != null
              ? "id:" + variableInfo.getVariableSymbolId()
              : "name:" + variableInfo.getName() + "|storage:" + entry.storage();
      if (seenVariableKeys.add(dedupeKey)) {
        deduplicatedEntries.add(entry);
      }
    }
    List<FunctionVariableInfo> variablesToList =
        deduplicatedEntries.stream().map(VariableListEntry::info).collect(Collectors.toList());

    VariableCursor cursor = cursorOpt.map(this::parseVariableCursor).orElse(null);

    int startIndex = 0;
    if (cursor != null) {
      boolean cursorMatched = false;
      for (int i = 0; i < variablesToList.size(); i++) {
        FunctionVariableInfo variableInfo = variablesToList.get(i);
        if (variableInfo.getVariableSymbolId() != null
            && variableInfo.getVariableSymbolId().longValue() == cursor.variableSymbolId) {
          startIndex = i + 1;
          cursorMatched = true;
          break;
        }
      }

      if (!cursorMatched) {
        throw new GhidraMcpException(
            GhidraMcpError.invalid(
                ARG_CURSOR,
                cursor.rawCursor,
                "cursor is invalid or no longer present in this function variable listing"));
      }
    }

    int endExclusive = Math.min(variablesToList.size(), startIndex + pageSize + 1);
    List<FunctionVariableInfo> paginatedVariables =
        new ArrayList<>(variablesToList.subList(startIndex, endExclusive));

    boolean hasMore = paginatedVariables.size() > pageSize;
    List<FunctionVariableInfo> resultsForPage =
        paginatedVariables.subList(0, Math.min(paginatedVariables.size(), pageSize));
    String nextCursor = null;
    if (hasMore && !resultsForPage.isEmpty()) {
      FunctionVariableInfo lastItem = resultsForPage.get(resultsForPage.size() - 1);
      nextCursor = encodeVariableCursor(lastItem.getVariableSymbolId());
    }

    return new PaginatedResult<>(resultsForPage, nextCursor);
  }

  private VariableCursor parseVariableCursor(String cursorValue) {
    String variableSymbolId =
        decodeOpaqueCursorSingleV1(cursorValue, ARG_CURSOR, "v1:<base64url_variable_symbol_id>");
    try {
      return new VariableCursor(Long.parseLong(variableSymbolId), cursorValue);
    } catch (NumberFormatException e) {
      throw new GhidraMcpException(
          GhidraMcpError.invalid(
              ARG_CURSOR, cursorValue, "contains an invalid variable_symbol_id component"));
    }
  }

  private String encodeVariableCursor(Long variableSymbolId) {
    if (variableSymbolId == null) {
      return null;
    }
    return OpaqueCursorCodec.encodeV1(Long.toString(variableSymbolId));
  }

  private static final class VariableCursor {
    private final long variableSymbolId;
    private final String rawCursor;

    private VariableCursor(long variableSymbolId, String rawCursor) {
      this.variableSymbolId = variableSymbolId;
      this.rawCursor = rawCursor;
    }
  }

  private String variableIdentityKey(Variable variable) {
    Symbol symbol = variable.getSymbol();
    if (symbol != null) {
      return "symbol:" + symbol.getID();
    }
    return "storage:" + variable.getVariableStorage() + "|param:" + (variable instanceof Parameter);
  }

  private record VariableListEntry(
      FunctionVariableInfo info, int sortGroup, int sortIndex, String storage, long sortId) {}

  private LocalSymbolMap getDecompilerLocalSymbolMap(
      Program program, Function function, TaskMonitor monitor, String operationLabel) {
    DecompInterface decompInterface = new DecompInterface();
    try {
      decompInterface.setOptions(new DecompileOptions());
      decompInterface.openProgram(program);
      DecompileResults results =
          decompInterface.decompileFunction(
              function, GhidraMcpServer.getRequestTimeoutSeconds(), monitor);

      if (results == null || results.getHighFunction() == null) {
        throw new GhidraMcpException(
            GhidraMcpError.failed(
                operationLabel, "Decompilation failed for function: " + function.getName()));
      }

      HighFunction highFunction = results.getHighFunction();
      LocalSymbolMap localSymbolMap = highFunction.getLocalSymbolMap();
      if (localSymbolMap == null) {
        throw new GhidraMcpException(
            GhidraMcpError.failed(
                operationLabel,
                "No local symbol map available for function: " + function.getName()));
      }
      return localSymbolMap;
    } finally {
      decompInterface.dispose();
    }
  }

  private FunctionCursor parseFunctionCursor(Program program, String cursorValue) {
    List<String> parts =
        decodeOpaqueCursorV1(cursorValue, 1, ARG_CURSOR, "v1:<base64url_symbol_id>");
    long symbolId;
    try {
      symbolId = Long.parseLong(parts.get(0));
    } catch (NumberFormatException e) {
      throw new GhidraMcpException(
          GhidraMcpError.invalid(ARG_CURSOR, cursorValue, "contains an invalid symbol_id"));
    }

    Symbol symbol = program.getSymbolTable().getSymbol(symbolId);
    if (symbol == null || symbol.getSymbolType() != SymbolType.FUNCTION) {
      throw new GhidraMcpException(
          GhidraMcpError.invalid(
              ARG_CURSOR, cursorValue, "symbol_id no longer identifies a function"));
    }

    Function function = program.getFunctionManager().getFunctionAt(symbol.getAddress());
    if (function == null) {
      throw new GhidraMcpException(
          GhidraMcpError.invalid(ARG_CURSOR, cursorValue, "function no longer exists"));
    }

    return new FunctionCursor(symbolId, function.getEntryPoint(), function.getName(), cursorValue);
  }

  private String encodeFunctionCursor(Long symbolId) {
    if (symbolId == null) {
      throw new GhidraMcpException(
          GhidraMcpError.invalid(ARG_CURSOR, null, "function row is missing symbol_id"));
    }
    return OpaqueCursorCodec.encodeV1(Long.toString(symbolId));
  }

  private static final class FunctionCursor {
    private final long symbolId;
    private final Address address;
    private final String name;
    private final String rawCursor;

    private FunctionCursor(long symbolId, Address address, String name, String rawCursor) {
      this.symbolId = symbolId;
      this.address = address;
      this.name = name;
      this.rawCursor = rawCursor;
    }

    private String toCursorString() {
      return rawCursor;
    }
  }

  private void ensureArgumentPresent(
      Map<String, Object> args, String argumentName, String toolOperation)
      throws GhidraMcpException {
    if (!args.containsKey(argumentName) || args.get(argumentName) == null) {
      throw new GhidraMcpException(GhidraMcpError.missing(argumentName));
    }
  }
}
