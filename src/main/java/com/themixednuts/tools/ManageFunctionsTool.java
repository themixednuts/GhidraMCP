package com.themixednuts.tools;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.FunctionGraph;
import com.themixednuts.models.FunctionGraphEdge;
import com.themixednuts.models.FunctionGraphNode;
import com.themixednuts.models.FunctionInfo;
import com.themixednuts.models.FunctionVariableInfo;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.utils.GhidraMcpErrorUtils;
import com.themixednuts.utils.PaginatedResult;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.draft7.SchemaBuilder;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.services.DataTypeQueryService;
import ghidra.app.util.NamespaceUtils;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockModel;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.listing.Function;
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
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.common.McpTransportContext;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Spliterator;
import java.util.Spliterators;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;
import reactor.core.publisher.Mono;

@GhidraMcpTool(
    name = "Manage Functions",
    description =
        "Function operations: create, update prototypes, list variables, and get function graphs.",
    mcpName = "manage_functions",
    mcpDescription =
        """
         <use_case>
         Function operations for reverse engineering workflows. Create, update
         function prototypes, list function variables, and get function control-flow graphs to understand program structure, control flow, and calling conventions.
         </use_case>

         <important_notes>
         - Supports multiple function identification methods (name, address, symbol ID, regex)
         - Handles function creation with automatic boundary detection
         - Lists both listing variables and decompiler-generated variables with detailed categorization
         - Generates control-flow graphs showing basic blocks and their connections
         - Use ReadFunctionsTool for reading/browsing functions with filtering
         - Use FindFunctionTool for searching functions by name, address, or patterns
         - Use DecompileCodeTool for decompilation analysis
         - Use DeleteFunctionTool to delete functions
         </important_notes>

        <examples>
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
          "target_type": "name",
          "target_value": "main"
        }

        Get function control-flow graph:
        {
          "file_name": "program.exe",
          "action": "get_graph",
          "name": "main"
        }
        </examples>
        """)
public class ManageFunctionsTool extends BaseMcpTool {

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

  private static final String ACTION_CREATE = "create";
  private static final String ACTION_UPDATE_PROTOTYPE = "update_prototype";
  private static final String ACTION_LIST_VARIABLES = "list_variables";
  private static final String ACTION_GET_GRAPH = "get_graph";

  /**
   * Defines the JSON input schema for function management operations.
   *
   * @return The JsonSchema defining the expected input arguments
   */
  @Override
  public JsonSchema schema() {
    // Use Draft 7 builder for conditional support with additive approach
    var schemaRoot = createDraft7SchemaNode();

    // Global properties (always available)
    schemaRoot.property(
        ARG_FILE_NAME, SchemaBuilder.string(mapper).description("The name of the program file."));

    schemaRoot.property(
        ARG_ACTION,
        SchemaBuilder.string(mapper)
            .enumValues(
                ACTION_CREATE, ACTION_UPDATE_PROTOTYPE, ACTION_LIST_VARIABLES, ACTION_GET_GRAPH)
            .description("Action to perform on functions"));

    schemaRoot.requiredProperty(ARG_FILE_NAME).requiredProperty(ARG_ACTION);

    // Add conditional requirements based on action (JSON Schema Draft 7)
    schemaRoot.allOf(
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
                        ARG_CURSOR, SchemaBuilder.string(mapper).description("Pagination cursor"))
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
                        SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_NAME))),
        // action=get_graph: requires at least one identifier (symbol_id, address, name)
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_ACTION, SchemaBuilder.string(mapper).constValue(ACTION_GET_GRAPH)),
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
                    .anyOf(
                        SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_SYMBOL_ID),
                        SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_ADDRESS),
                        SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_NAME))));

    return schemaRoot.build();
  }

  /**
   * Executes the function management operation.
   *
   * @param context The MCP transport context
   * @param args The tool arguments containing file_name, action, and action-specific parameters
   * @param tool The Ghidra PluginTool context
   * @return A Mono emitting the result of the function operation
   */
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
                case ACTION_CREATE -> handleCreate(program, args, annotation);
                case ACTION_UPDATE_PROTOTYPE ->
                    handleUpdatePrototype(program, tool, args, annotation);
                case ACTION_LIST_VARIABLES -> handleListVariables(program, args, annotation);
                case ACTION_GET_GRAPH -> handleGetGraph(program, args, annotation);
                default -> {
                  GhidraMcpError error =
                      GhidraMcpError.invalid(
                          ARG_ACTION,
                          action,
                          "must be one of: create, update_prototype, list_variables, get_graph");
                  yield Mono.error(new GhidraMcpException(error));
                }
              };
            });
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

    // Extract function identifiers from both direct arguments and
    // target_type/target_value
    FunctionIdentifiers identifiers = extractFunctionIdentifiers(args);

    if (identifiers.isEmpty()) {
      return Mono.error(new GhidraMcpException(createMissingIdentifierError()));
    }

    // Check if raw prototype string is provided (preferred approach)
    Optional<String> rawPrototypeOpt =
        getOptionalStringArgument(args, ARG_PROTOTYPE)
            .map(String::trim)
            .filter(value -> !value.isEmpty());

    if (rawPrototypeOpt.isPresent()) {
      // Use raw prototype string with FunctionSignatureParser
      return Mono.fromCallable(
              () -> resolveFunctionByIdentifiers(program, identifiers, toolOperation))
          .map(function -> new UpdatePrototypeContext(program, function, rawPrototypeOpt.get()))
          .flatMap(context -> executePrototypeUpdate(program, annotation, tool, context));
    } else {
      // Build prototype from structured arguments
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
        function = funcMan.getFunctionAt(entryPoint);
      } catch (Exception e) {
        throw new GhidraMcpException(
            GhidraMcpErrorUtils.addressParseError(addressString, toolOperation, e));
      }
    }

    if (function == null && identifiers.name().isPresent()) {
      String functionName = identifiers.name().get();

      // Try exact name match first
      function =
          StreamSupport.stream(funcMan.getFunctions(true).spliterator(), false)
              .filter(f -> f.getName(true).equals(functionName))
              .findFirst()
              .orElse(null);

      // If not found and name contains "::", try qualified name search
      if (function == null && functionName.contains("::")) {
        function =
            StreamSupport.stream(funcMan.getFunctions(true).spliterator(), false)
                .filter(
                    f -> {
                      String qualifiedName =
                          NamespaceUtils.getNamespaceQualifiedName(
                              f.getParentNamespace(), f.getName(), false);
                      return qualifiedName.equals(functionName);
                    })
                .findFirst()
                .orElse(null);
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
        "Include at least one of: symbol_id, address, or name");
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

    // Extract function identifiers from both direct arguments and
    // target_type/target_value
    FunctionIdentifiers identifiers = extractFunctionIdentifiers(args);

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
    int pageSize =
        getOptionalIntArgument(args, ARG_PAGE_SIZE)
            .filter(size -> size > 0)
            .map(size -> Math.min(size, MAX_PAGE_LIMIT))
            .orElse(DEFAULT_PAGE_LIMIT);

    // Get listing variables
    Stream<FunctionVariableInfo> listingVarStream =
        Arrays.stream(function.getAllVariables()).map(FunctionVariableInfo::new);

    // Get decompiler variables
    Stream<FunctionVariableInfo> decompilerVarStream = Stream.empty();
    DecompInterface decomplib = new DecompInterface();
    try {
      decomplib.setOptions(new DecompileOptions());
      decomplib.openProgram(program);
      DecompileResults results =
          decomplib.decompileFunction(
              function, decomplib.getOptions().getDefaultTimeout(), new ConsoleTaskMonitor());

      if (results == null) {
        // Decompiler failed but continue with listing variables only
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
      // Log the error but continue with listing variables
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

    final String finalCursorStr = cursorOpt.orElse(null);

    List<FunctionVariableInfo> paginatedVariables =
        variablesToList.stream()
            .dropWhile(
                varInfo -> {
                  if (finalCursorStr == null) return false;

                  String[] parts = finalCursorStr.split(":", 2);
                  String cursorStorage = parts[0];
                  String cursorName = parts.length > 1 ? parts[1] : "";

                  int storageCompare = varInfo.getStorage().compareTo(cursorStorage);
                  if (storageCompare < 0) return true;
                  if (storageCompare == 0) {
                    return varInfo.getEffectiveName().compareTo(cursorName) <= 0;
                  }
                  return false;
                })
            .limit(pageSize + 1L)
            .collect(Collectors.toList());

    boolean hasMore = paginatedVariables.size() > pageSize;
    List<FunctionVariableInfo> resultsForPage =
        paginatedVariables.subList(0, Math.min(paginatedVariables.size(), pageSize));
    String nextCursor = null;
    if (hasMore && !resultsForPage.isEmpty()) {
      FunctionVariableInfo lastItem = resultsForPage.get(resultsForPage.size() - 1);
      nextCursor = lastItem.getStorage() + ":" + lastItem.getEffectiveName();
    }

    return new PaginatedResult<>(resultsForPage, nextCursor);
  }

  private void ensureArgumentPresent(
      Map<String, Object> args, String argumentName, String toolOperation)
      throws GhidraMcpException {
    if (!args.containsKey(argumentName) || args.get(argumentName) == null) {
      throw new GhidraMcpException(GhidraMcpError.missing(argumentName));
    }
  }

  private Mono<? extends Object> handleGetGraph(
      Program program, Map<String, Object> args, GhidraMcpTool annotation) {
    String toolOperation = annotation.mcpName() + ".get_graph";

    // Extract function identifiers from both direct arguments and
    // target_type/target_value
    FunctionIdentifiers identifiers = extractFunctionIdentifiers(args);

    if (identifiers.isEmpty()) {
      return Mono.error(new GhidraMcpException(createMissingIdentifierError()));
    }

    return Mono.fromCallable(
        () -> {
          Function function = resolveFunctionByIdentifiers(program, identifiers, toolOperation);
          return buildFunctionGraph(program, function);
        });
  }

  private FunctionGraph buildFunctionGraph(Program program, Function function)
      throws GhidraMcpException {
    CodeBlockModel model = new BasicBlockModel(program);
    AddressSetView body = function.getBody();

    Map<String, FunctionGraphNode> idToNode = new LinkedHashMap<>();
    List<FunctionGraphEdge> edges = new ArrayList<>();

    try {
      // Use TaskMonitor.DUMMY instead of null
      TaskMonitor monitor = TaskMonitor.DUMMY;
      CodeBlockIterator blocks = model.getCodeBlocksContaining(body, monitor);
      int index = 0;
      Map<Address, String> startToId = new HashMap<>();
      List<CodeBlock> blockList = new ArrayList<>();

      while (blocks.hasNext()) {
        CodeBlock b = blocks.next();
        blockList.add(b);
        String nodeId = "B" + index++;
        startToId.put(b.getFirstStartAddress(), nodeId);
        String range = b.getMinAddress() + "-" + b.getMaxAddress();
        String label = b.getFirstStartAddress().toString();
        idToNode.put(nodeId, new FunctionGraphNode(nodeId, range, label));
      }

      for (CodeBlock b : blockList) {
        String srcId = startToId.get(b.getFirstStartAddress());
        CodeBlockReferenceIterator dests = b.getDestinations(monitor);
        while (dests.hasNext()) {
          CodeBlockReference ref = dests.next();
          CodeBlock dest = ref.getDestinationBlock();
          String dstId = startToId.get(dest.getFirstStartAddress());
          if (dstId != null) {
            String type = ref.getFlowType().toString();
            edges.add(new FunctionGraphEdge(srcId, dstId, type));
          }
        }
      }
    } catch (Exception e) {
      throw new GhidraMcpException(GhidraMcpError.internal(e));
    }

    List<FunctionGraphNode> nodes = new ArrayList<>(idToNode.values());
    String funcName = function.getName(true);
    String funcAddr = function.getEntryPoint() != null ? function.getEntryPoint().toString() : null;
    return new FunctionGraph(funcName, funcAddr, nodes, edges);
  }
}
