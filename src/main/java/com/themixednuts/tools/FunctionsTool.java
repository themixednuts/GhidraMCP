package com.themixednuts.tools;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.FunctionInfo;
import com.themixednuts.models.FunctionVariableInfo;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.utils.GhidraMcpErrorUtils;
import com.themixednuts.utils.OpaqueCursorCodec;
import com.themixednuts.utils.PaginatedResult;
import com.themixednuts.utils.SymbolLookupHelper;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.draft7.SchemaBuilder;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.services.DataTypeQueryService;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.task.ConsoleTaskMonitor;
import io.modelcontextprotocol.common.McpTransportContext;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Spliterator;
import java.util.Spliterators;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;
import reactor.core.publisher.Mono;

@GhidraMcpTool(
    name = "Functions",
    description = "Function lifecycle: list, get, create, update prototypes, and list variables.",
    mcpName = "functions",
    mcpDescription =
        """
         <use_case>
         Function lifecycle operations for reverse engineering workflows. List and browse functions
         with filtering and pagination, get detailed function info by identifier, create functions,
         update function prototypes, and list function variables with detailed categorization.
         </use_case>

         <important_notes>
         - Supports multiple function identification methods (name, address, symbol ID)
         - List mode supports regex filtering by name_pattern and cursor-based pagination
         - Get mode returns detailed FunctionInfo by symbol_id, address, or name (with wildcard support)
         - Handles function creation with automatic boundary detection
         - Lists both listing variables and decompiler-generated variables with detailed categorization
         - Use `inspect` (action: decompile) for decompilation analysis
         - For browsing all functions without filtering, use the ghidra://program/{name}/functions resource
         </important_notes>

        <examples>
        List all functions (first page):
        {
          "file_name": "program.exe",
          "action": "list"
        }

        List functions matching pattern:
        {
          "file_name": "program.exe",
          "action": "list",
          "name_pattern": ".*decrypt.*"
        }

        Get a function by address:
        {
          "file_name": "program.exe",
          "action": "get",
          "address": "0x401000"
        }

        Get a function by name:
        {
          "file_name": "program.exe",
          "action": "get",
          "name": "main"
        }

        Get a function by symbol ID:
        {
          "file_name": "program.exe",
          "action": "get",
          "symbol_id": 12345
        }

        Create a function at an address with custom name:
        {
          "file_name": "program.exe",
          "action": "create",
          "address": "0x401000",
          "function_name": "decrypt_data"
        }

        Create a function at an address (auto-generated name):
        {
          "file_name": "program.exe",
          "action": "create",
          "address": "0x401000"
        }

        List variables in a function:
        {
          "file_name": "program.exe",
          "action": "list_variables",
          "name": "main"
        }
        </examples>
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

  private static final String ACTION_LIST = "list";
  private static final String ACTION_GET = "get";
  private static final String ACTION_CREATE = "create";
  private static final String ACTION_UPDATE_PROTOTYPE = "update_prototype";
  private static final String ACTION_LIST_VARIABLES = "list_variables";

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
                ACTION_LIST_VARIABLES)
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
                            .description("Optional regex pattern to filter function names"))
                    .property(
                        ARG_CURSOR,
                        SchemaBuilder.string(mapper)
                            .description(
                                "Pagination cursor from previous request (format:"
                                    + " v1:<base64url_address>:<base64url_function_name>)"))
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
                            .maximum(MAX_PAGE_LIMIT))),
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
                            .pattern("^(0x)?[0-9a-fA-F]+$"))
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
                            .pattern("^(0x)?[0-9a-fA-F]+$"))
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
                            .pattern("^(0x)?[0-9a-fA-F]+$"))
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
                            .description("Function parameters with 'name' and 'data_type' fields"))
                    .property(
                        ARG_NO_RETURN,
                        SchemaBuilder.bool(mapper).description("Whether function does not return"))
                    .anyOf(
                        SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_SYMBOL_ID),
                        SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_ADDRESS),
                        SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_NAME))),
        // action=list_variables: requires at least one identifier (symbol_id, address,
        // name);
        // allows cursor
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
                            .pattern("^(0x)?[0-9a-fA-F]+$"))
                    .property(
                        ARG_NAME,
                        SchemaBuilder.string(mapper)
                            .description("Function name for identification"))
                    .property(
                        ARG_CURSOR,
                        SchemaBuilder.string(mapper)
                            .description(
                                "Pagination cursor (format:"
                                    + " v1:<base64url_storage>:<base64url_variable_name>)"))
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
                    .anyOf(
                        SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_SYMBOL_ID),
                        SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_ADDRESS),
                        SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_NAME))));

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
                default -> {
                  GhidraMcpError error =
                      GhidraMcpError.invalid(
                          ARG_ACTION,
                          action,
                          "must be one of: list, get, create, update_prototype, list_variables");
                  yield Mono.error(new GhidraMcpException(error));
                }
              };
            });
  }

  private Mono<PaginatedResult<FunctionInfo>> handleList(
      Program program, Map<String, Object> args) {
    return Mono.fromCallable(() -> listFunctions(program, args));
  }

  private PaginatedResult<FunctionInfo> listFunctions(Program program, Map<String, Object> args) {
    FunctionManager functionManager = program.getFunctionManager();
    int pageSize = getPageSizeArgument(args, DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT);

    Optional<String> namePatternOpt = getOptionalStringArgument(args, ARG_NAME_PATTERN);
    Optional<String> cursorOpt = getOptionalStringArgument(args, ARG_CURSOR);

    FunctionCursor cursor =
        cursorOpt.map(value -> parseFunctionCursor(program, value)).orElse(null);

    Pattern namePattern = null;
    if (namePatternOpt.isPresent()) {
      try {
        namePattern = Pattern.compile(namePatternOpt.get());
      } catch (PatternSyntaxException e) {
        throw new GhidraMcpException(
            GhidraMcpError.invalid("name_pattern", namePatternOpt.get(), e.getMessage()));
      }
    }

    List<FunctionInfo> allMatches = new ArrayList<>();
    FunctionIterator funcIter = functionManager.getFunctions(true);
    while (funcIter.hasNext()) {
      Function function = funcIter.next();
      if (namePattern != null && !namePattern.matcher(function.getName()).matches()) {
        continue;
      }
      allMatches.add(new FunctionInfo(function));
    }

    int startIndex = 0;
    if (cursor != null) {
      boolean matched = false;
      for (int i = 0; i < allMatches.size(); i++) {
        FunctionInfo functionInfo = allMatches.get(i);
        if (functionInfo.getEntryPoint().equalsIgnoreCase(cursor.address)
            && functionInfo.getName().equals(cursor.name)) {
          startIndex = i + 1;
          matched = true;
          break;
        }
      }

      if (!matched) {
        throw new GhidraMcpException(
            GhidraMcpError.invalid(
                ARG_CURSOR,
                cursor.toCursorString(),
                "cursor is invalid or no longer present in this function listing"));
      }
    }

    int endExclusive = Math.min(allMatches.size(), startIndex + pageSize + 1);
    List<FunctionInfo> paginatedResults =
        new ArrayList<>(allMatches.subList(startIndex, endExclusive));

    boolean hasMore = paginatedResults.size() > pageSize;
    List<FunctionInfo> results =
        hasMore ? new ArrayList<>(paginatedResults.subList(0, pageSize)) : paginatedResults;

    String nextCursor = null;
    if (hasMore && !results.isEmpty()) {
      FunctionInfo lastFunc = results.get(results.size() - 1);
      nextCursor = encodeFunctionCursor(lastFunc.getEntryPoint(), lastFunc.getName());
    }

    return new PaginatedResult<>(results, nextCursor);
  }

  private Mono<FunctionInfo> handleGet(Program program, Map<String, Object> args) {
    return Mono.fromCallable(
        () -> {
          FunctionManager functionManager = program.getFunctionManager();

          Optional<Long> symbolIdOpt = getOptionalLongArgument(args, ARG_SYMBOL_ID);
          Optional<String> addressOpt = getOptionalStringArgument(args, ARG_ADDRESS);
          Optional<String> nameOpt = getOptionalStringArgument(args, ARG_NAME);

          // Apply precedence: symbol_id > address > name
          if (symbolIdOpt.isPresent()) {
            return readBySymbolId(program, functionManager, symbolIdOpt.get());
          } else if (addressOpt.isPresent()) {
            return readByAddress(program, functionManager, addressOpt.get());
          } else if (nameOpt.isPresent()) {
            return readByName(program, nameOpt.get());
          } else {
            throw new GhidraMcpException(GhidraMcpError.missing("symbol_id, address, or name"));
          }
        });
  }

  private FunctionInfo readBySymbolId(
      Program program, FunctionManager functionManager, Long symbolId) throws GhidraMcpException {
    Symbol symbol = program.getSymbolTable().getSymbol(symbolId);
    if (symbol != null && symbol.getSymbolType() == SymbolType.FUNCTION) {
      Function function = functionManager.getFunctionAt(symbol.getAddress());
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
      Address functionAddress = program.getAddressFactory().getAddress(addressStr);
      if (functionAddress != null) {
        Function function = functionManager.getFunctionContaining(functionAddress);
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

                    return new FunctionInfo(createdFunction);
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

      return new FunctionInfo(function);
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
        Address entryPoint = program.getAddressFactory().getAddress(addressString);
        if (entryPoint == null) {
          throw new IllegalArgumentException("Unresolvable address");
        }
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
              Address address = program.getAddressFactory().getAddress(addressString);
              if (address == null) {
                throw new GhidraMcpException(
                    GhidraMcpError.invalid(
                        ARG_ADDRESS, addressString, "could not be resolved to a valid address"));
              }
              return address;
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

    return Mono.fromCallable(
        () -> {
          Function function = resolveFunctionByIdentifiers(program, identifiers, toolOperation);
          return listFunctionVariables(function, program, args);
        });
  }

  private PaginatedResult<FunctionVariableInfo> listFunctionVariables(
      Function function, Program program, Map<String, Object> args) {
    Optional<String> cursorOpt = getOptionalStringArgument(args, ARG_CURSOR);
    int pageSize = getPageSizeArgument(args, DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT);

    Stream<FunctionVariableInfo> listingVarStream =
        Arrays.stream(function.getAllVariables()).map(FunctionVariableInfo::new);

    Stream<FunctionVariableInfo> decompilerVarStream = Stream.empty();
    DecompInterface decomplib = new DecompInterface();
    try {
      decomplib.setOptions(new DecompileOptions());
      decomplib.openProgram(program);
      DecompileResults results =
          decomplib.decompileFunction(
              function, decomplib.getOptions().getDefaultTimeout(), new ConsoleTaskMonitor());

      if (results == null) {
        ghidra.util.Msg.warn(
            this, "Decompiler returned null results for function: " + function.getName());
      } else {
        HighFunction hf = results.getHighFunction();
        if (hf != null) {
          LocalSymbolMap localSymbolMap = hf.getLocalSymbolMap();
          if (localSymbolMap != null) {
            java.util.Iterator<HighSymbol> highSymbolIterator = localSymbolMap.getSymbols();
            decompilerVarStream =
                StreamSupport.stream(
                        Spliterators.spliteratorUnknownSize(
                            highSymbolIterator, Spliterator.ORDERED),
                        false)
                    .map(HighSymbol::getHighVariable)
                    .filter(java.util.Objects::nonNull)
                    .map(hv -> new FunctionVariableInfo(hv, program));
          }
        } else {
          ghidra.util.Msg.warn(
              this,
              "Decompilation did not yield a HighFunction for function: " + function.getName());
        }
      }
    } catch (Exception e) {
      ghidra.util.Msg.error(
          this, "Error during decompilation for ListFunctionVariables: " + e.getMessage(), e);
    } finally {
      if (decomplib != null) {
        decomplib.dispose();
      }
    }

    List<FunctionVariableInfo> variablesToList =
        Stream.concat(listingVarStream, decompilerVarStream)
            .sorted(
                Comparator.comparing(FunctionVariableInfo::getStorage)
                    .thenComparing(FunctionVariableInfo::getEffectiveName))
            .collect(Collectors.toList());

    VariableCursor cursor = cursorOpt.map(this::parseVariableCursor).orElse(null);

    int startIndex = 0;
    if (cursor != null) {
      boolean cursorMatched = false;
      for (int i = 0; i < variablesToList.size(); i++) {
        FunctionVariableInfo variableInfo = variablesToList.get(i);
        if (variableInfo.getStorage().equals(cursor.storage)
            && variableInfo.getEffectiveName().equals(cursor.name)) {
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
      nextCursor = encodeVariableCursor(lastItem.getStorage(), lastItem.getEffectiveName());
    }

    return new PaginatedResult<>(resultsForPage, nextCursor);
  }

  private VariableCursor parseVariableCursor(String cursorValue) {
    List<String> parts =
        decodeOpaqueCursorV1(
            cursorValue, 2, ARG_CURSOR, "v1:<base64url_storage>:<base64url_variable_name>");
    return new VariableCursor(parts.get(0), parts.get(1), cursorValue);
  }

  private String encodeVariableCursor(String storage, String name) {
    return OpaqueCursorCodec.encodeV1(storage, name);
  }

  private static final class VariableCursor {
    private final String storage;
    private final String name;
    private final String rawCursor;

    private VariableCursor(String storage, String name, String rawCursor) {
      this.storage = storage;
      this.name = name;
      this.rawCursor = rawCursor;
    }
  }

  private FunctionCursor parseFunctionCursor(Program program, String cursorValue) {
    List<String> parts =
        decodeOpaqueCursorV1(
            cursorValue, 2, ARG_CURSOR, "v1:<base64url_address>:<base64url_function_name>");

    Address cursorAddress = program.getAddressFactory().getAddress(parts.get(0));
    if (cursorAddress == null) {
      throw new GhidraMcpException(
          GhidraMcpError.invalid(ARG_CURSOR, cursorValue, "contains an invalid address component"));
    }

    String decodedName = parts.get(1);

    if (decodedName.isBlank()) {
      throw new GhidraMcpException(
          GhidraMcpError.invalid(ARG_CURSOR, cursorValue, "contains an empty function name"));
    }

    return new FunctionCursor(cursorAddress.toString(), decodedName, cursorValue);
  }

  private String encodeFunctionCursor(String address, String functionName) {
    return OpaqueCursorCodec.encodeV1(address, functionName);
  }

  private static final class FunctionCursor {
    private final String address;
    private final String name;
    private final String rawCursor;

    private FunctionCursor(String address, String name, String rawCursor) {
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
