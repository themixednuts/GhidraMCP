package com.themixednuts.tools;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.FunctionVariableInfo;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.models.FunctionInfo;
import com.themixednuts.models.OperationResult;
import com.themixednuts.utils.GhidraMcpErrorUtils;
import com.themixednuts.utils.DataTypeUtils;
import com.themixednuts.utils.PaginatedResult;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.cmd.function.DeleteFunctionCmd;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
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
import io.modelcontextprotocol.common.McpTransportContext;
import reactor.core.publisher.Mono;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;
import java.util.Spliterator;
import java.util.Spliterators;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.app.services.DataTypeQueryService;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.ConsoleTaskMonitor;

@GhidraMcpTool(
    name = "Manage Functions",
    description = "Function CRUD operations: create, delete, update prototypes, and list variables.",
    mcpName = "manage_functions",
    mcpDescription = """
    <use_case>
    Function operations for reverse engineering workflows. Create, delete, update
    function prototypes, and list function variables to understand program structure, control flow, and calling conventions.
    </use_case>

    <important_notes>
    - Supports multiple function identification methods (name, address, symbol ID, regex)
    - Handles function creation with automatic boundary detection
    - Lists both listing variables and decompiler-generated variables with detailed categorization
    - Use ListFunctionsTool for browsing functions with filtering
    - Use FindFunctionTool for searching functions by name, address, or patterns
    - Use DecompileCodeTool for decompilation analysis
    </important_notes>

    <examples>
    Delete a function at an address:
    {
      "fileName": "program.exe",
      "action": "delete",
      "address": "0x401500"
    }

    Create a function at an address with custom name:
    {
      "fileName": "program.exe",
      "action": "create",
      "address": "0x401000",
      "function_name": "decrypt_data"
    }

    Create a function at an address (auto-generated name):
    {
      "fileName": "program.exe",
      "action": "create",
      "address": "0x401000"
    }

    List variables in a function:
    {
      "fileName": "program.exe",
      "action": "list_variables",
      "target_type": "name",
      "target_value": "main"
    }
    </examples>
    """
)
public class ManageFunctionsTool implements IGhidraMcpSpecification {

    public static final String ARG_ACTION = "action";
    public static final String ARG_SYMBOL_ID = "symbol_id";
    public static final String ARG_ADDRESS = "address";
    public static final String ARG_NAME = "name";
    public static final String ARG_PROTOTYPE = "prototype";


    private static final String ACTION_CREATE = "create";
    private static final String ACTION_READ = "read";
    private static final String ACTION_DELETE = "delete";
    private static final String ACTION_UPDATE_PROTOTYPE = "update_prototype";
    private static final String ACTION_LIST_VARIABLES = "list_variables";


    @Override
    public JsonSchema schema() {
        IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();

        schemaRoot.property(ARG_FILE_NAME,
                JsonSchemaBuilder.string(mapper)
                        .description("The name of the program file."));

        schemaRoot.property(ARG_ACTION, JsonSchemaBuilder.string(mapper)
                .enumValues(ACTION_CREATE, ACTION_READ, ACTION_DELETE, ACTION_UPDATE_PROTOTYPE, ACTION_LIST_VARIABLES)
                .description("Action to perform on functions"));

        schemaRoot.property(ARG_SYMBOL_ID, JsonSchemaBuilder.integer(mapper)
                .description("Symbol ID to identify target function (highest precedence)"));

        schemaRoot.property(ARG_ADDRESS, JsonSchemaBuilder.string(mapper)
                .description("Function address for create/delete or to identify target function")
                .pattern("^(0x)?[0-9a-fA-F]+$"));

        schemaRoot.property(ARG_NAME, JsonSchemaBuilder.string(mapper)
                .description("Function name - for identification or setting name during creation"));


        schemaRoot.property(ARG_PROTOTYPE, JsonSchemaBuilder.string(mapper)
                .description("Full function prototype string (C syntax). If provided, other structured fields like returnType/parameters are ignored."));

        schemaRoot.requiredProperty(ARG_FILE_NAME)
                .requiredProperty(ARG_ACTION);

        return schemaRoot.build();
    }

    @Override
    public Mono<? extends Object> execute(McpTransportContext context, Map<String, Object> args, PluginTool tool) {
        GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);

        return getProgram(args, tool).flatMap(program -> {
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
                case ACTION_READ -> handleRead(program, args, annotation);
                case ACTION_DELETE -> handleDelete(program, args, annotation);
                case ACTION_UPDATE_PROTOTYPE -> handleUpdatePrototype(program, tool, args, annotation);
                case ACTION_LIST_VARIABLES -> handleListVariables(program, args, annotation);
                default -> {
                    GhidraMcpError error = GhidraMcpError.validation()
                        .errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
                        .message("Invalid action: " + action)
                        .context(new GhidraMcpError.ErrorContext(
                            annotation.mcpName(),
                            "action validation",
                            args,
                            Map.of(ARG_ACTION, action),
                            Map.of("validActions", List.of(ACTION_CREATE, ACTION_READ, ACTION_DELETE, ACTION_UPDATE_PROTOTYPE, ACTION_LIST_VARIABLES))))
                        .suggestions(List.of(
                            new GhidraMcpError.ErrorSuggestion(
                                GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
                                "Use a valid action",
                                "Choose from: create, read, delete, update_prototype, list_variables",
                                List.of(ACTION_CREATE, ACTION_READ, ACTION_DELETE, ACTION_UPDATE_PROTOTYPE, ACTION_LIST_VARIABLES),
                                null)))
                        .build();
                    yield Mono.error(new GhidraMcpException(error));
                }
            };
        });
    }



    private Mono<? extends Object> handleCreate(Program program, Map<String, Object> args, GhidraMcpTool annotation) {
        String toolOperation = annotation.mcpName() + ".create";
        String addressString = getRequiredStringArgument(args, ARG_ADDRESS);
        Optional<String> nameOpt = getOptionalStringArgument(args, ARG_FUNCTION_NAME);

        return parseAddressOrThrow(program, addressString, toolOperation, args).flatMap(functionAddress -> {
            if (program.getFunctionManager().getFunctionAt(functionAddress) != null) {
                GhidraMcpError error = GhidraMcpError.validation()
                    .errorCode(GhidraMcpError.ErrorCode.CONFLICTING_ARGUMENTS)
                    .message("Function already exists at the specified address")
                    .context(new GhidraMcpError.ErrorContext(
                        toolOperation,
                        "function existence check",
                        args,
                        Map.of(ARG_ADDRESS, addressString),
                        Map.of("functionExists", true)))
                    .suggestions(List.of(
                        new GhidraMcpError.ErrorSuggestion(
                            GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
                            "Verify the address is not already a function entry point",
                            "Inspect existing functions around the target address",
                            null,
                            null)))
                    .build();
                return Mono.error(new GhidraMcpException(error));
            }

            return executeInTransaction(program, "MCP - Create Function at " + functionAddress, () -> {
                CreateFunctionCmd cmd = new CreateFunctionCmd(
                    nameOpt.orElse(null),
                    functionAddress,
                    new AddressSet(functionAddress),
                    SourceType.USER_DEFINED);

                boolean success = cmd.applyTo(program);
                if (!success) {
                    String status = Optional.ofNullable(cmd.getStatusMsg()).orElse("Unknown error");
                    GhidraMcpError error = GhidraMcpError.execution()
                        .errorCode(GhidraMcpError.ErrorCode.TRANSACTION_FAILED)
                        .message("Failed to create function: " + status)
                        .context(new GhidraMcpError.ErrorContext(
                            toolOperation,
                            "function creation command",
                            Map.of(ARG_ADDRESS, addressString, ARG_FUNCTION_NAME, nameOpt.orElse("default")),
                            Map.of("commandStatus", status),
                            Map.of("commandSuccess", false)))
                        .suggestions(List.of(
                            new GhidraMcpError.ErrorSuggestion(
                                GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
                                "Ensure the address contains executable code",
                                "Verify the target address has been properly disassembled",
                                null,
                                null)))
                        .build();
                    throw new GhidraMcpException(error);
                }

                Function createdFunction = cmd.getFunction();
                if (createdFunction == null) {
                    GhidraMcpError error = GhidraMcpError.execution()
                        .errorCode(GhidraMcpError.ErrorCode.UNEXPECTED_ERROR)
                        .message("Function creation succeeded but returned no function object")
                        .context(new GhidraMcpError.ErrorContext(
                            toolOperation,
                            "function creation result",
                            Map.of(ARG_ADDRESS, addressString),
                            Map.of("commandSuccess", true, "functionReturned", false),
                            Map.of("internalError", true)))
                        .suggestions(List.of(
                            new GhidraMcpError.ErrorSuggestion(
                                GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
                                "Verify the new function exists",
                                "Inspect the program to confirm the created function",
                                null,
                                null)))
                        .build();
                    throw new GhidraMcpException(error);
                }

                return new FunctionInfo(createdFunction);
            });
        });
    }

    private Mono<? extends Object> handleRead(Program program, Map<String, Object> args, GhidraMcpTool annotation) {
        return Mono.fromCallable(() -> {
            FunctionManager functionManager = program.getFunctionManager();

            // Apply precedence: symbol_id > address > name
            if (args.containsKey(ARG_SYMBOL_ID)) {
                Long symbolId = getOptionalLongArgument(args, ARG_SYMBOL_ID).orElse(null);
                if (symbolId != null) {
                    Symbol symbol = program.getSymbolTable().getSymbol(symbolId);
                    if (symbol != null && symbol.getSymbolType() == SymbolType.FUNCTION) {
                        Function function = functionManager.getFunctionAt(symbol.getAddress());
                        if (function != null) {
                            return new FunctionInfo(function);
                        }
                    }
                }
                throw new GhidraMcpException(createFunctionNotFoundError(annotation.mcpName() + ".read", "symbol_id", symbolId.toString()));
            } else if (args.containsKey(ARG_ADDRESS)) {
                String address = getOptionalStringArgument(args, ARG_ADDRESS).orElse(null);
                if (address != null && !address.trim().isEmpty()) {
                    try {
                        Address functionAddress = program.getAddressFactory().getAddress(address);
                        if (functionAddress != null) {
                            Function function = functionManager.getFunctionAt(functionAddress);
                            if (function != null) {
                                return new FunctionInfo(function);
                            }
                        }
                    } catch (Exception e) {
                        throw new GhidraMcpException(createInvalidAddressError(address, e));
                    }
                }
                throw new GhidraMcpException(createFunctionNotFoundError(annotation.mcpName() + ".read", "address", address));
            } else if (args.containsKey(ARG_NAME)) {
                String name = getOptionalStringArgument(args, ARG_NAME).orElse(null);
                if (name != null && !name.trim().isEmpty()) {
                    // First try exact match
                    Optional<Function> exactMatch = StreamSupport.stream(functionManager.getFunctions(true).spliterator(), false)
                        .filter(f -> f.getName().equals(name))
                        .findFirst();

                    if (exactMatch.isPresent()) {
                        return new FunctionInfo(exactMatch.get());
                    }

                    // Then try regex match
                    try {
                        List<Function> regexMatches = StreamSupport.stream(functionManager.getFunctions(true).spliterator(), false)
                            .filter(f -> f.getName().matches(name))
                            .collect(Collectors.toList());

                        if (regexMatches.size() == 1) {
                            return new FunctionInfo(regexMatches.get(0));
                        } else if (regexMatches.size() > 1) {
                            throw new GhidraMcpException(createMultipleFunctionsFoundError(annotation.mcpName() + ".read", name, regexMatches));
                        }
                    } catch (Exception e) {
                        throw new GhidraMcpException(createInvalidRegexError(name, e));
                    }
                }
                throw new GhidraMcpException(createFunctionNotFoundError(annotation.mcpName() + ".read", "name", name));
            } else {
                throw new GhidraMcpException(createMissingParameterError());
            }
        });
    }

    private Mono<? extends Object> handleDelete(Program program, Map<String, Object> args, GhidraMcpTool annotation) {
        String toolOperation = annotation.mcpName() + ".delete";

        // Apply precedence: symbol_id > address > name
        if (args.containsKey(ARG_SYMBOL_ID)) {
            Long symbolId = getOptionalLongArgument(args, ARG_SYMBOL_ID).orElse(null);
            if (symbolId != null) {
                return deleteBySymbolId(program, symbolId, toolOperation, args, annotation);
            }
        } else if (args.containsKey(ARG_ADDRESS)) {
            String address = getOptionalStringArgument(args, ARG_ADDRESS).orElse(null);
            if (address != null && !address.trim().isEmpty()) {
                return deleteByAddress(program, address, toolOperation, args, annotation);
            }
        } else if (args.containsKey(ARG_NAME)) {
            String name = getOptionalStringArgument(args, ARG_NAME).orElse(null);
            if (name != null && !name.trim().isEmpty()) {
                return deleteByName(program, name, toolOperation, args, annotation);
            }
        }

        // No valid parameters provided
        Map<String, Object> providedIdentifiers = Map.of(
            ARG_SYMBOL_ID, "not provided",
            ARG_ADDRESS, "not provided",
            ARG_NAME, "not provided");

            GhidraMcpError error = GhidraMcpError.validation()
                .errorCode(GhidraMcpError.ErrorCode.MISSING_REQUIRED_ARGUMENT)
                .message("At least one identifier must be provided")
                .context(new GhidraMcpError.ErrorContext(
                    toolOperation,
                    "function identifier validation",
                    args,
                    providedIdentifiers,
                    Map.of("identifiersProvided", 0, "minimumRequired", 1)))
                .suggestions(List.of(
                    new GhidraMcpError.ErrorSuggestion(
                        GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
                        "Provide at least one function identifier",
                        "Include symbol ID, address, or name of the function",
                        List.of(
                            ARG_SYMBOL_ID + ": 12345",
                            ARG_ADDRESS + ": \"0x401000\"",
                            ARG_NAME + ": \"main\""),
                        null)))
                .build();
        return Mono.error(new GhidraMcpException(error));
    }

    private Mono<? extends Object> deleteBySymbolId(Program program, Long symbolId, String toolOperation, Map<String, Object> args, GhidraMcpTool annotation) {
        return Mono.fromCallable(() -> {
            Symbol symbol = program.getSymbolTable().getSymbol(symbolId);
            if (symbol == null) {
                throw new GhidraMcpException(createFunctionNotFoundError(toolOperation, "symbol_id", symbolId.toString()));
            }
            Function function = program.getFunctionManager().getFunctionAt(symbol.getAddress());
            if (function == null) {
                throw new GhidraMcpException(createFunctionNotFoundError(toolOperation, "symbol_id", symbolId.toString()));
            }
            return function;
        }).flatMap(function -> deleteFunction(program, function, toolOperation));
    }

    private Mono<? extends Object> deleteByAddress(Program program, String addressStr, String toolOperation, Map<String, Object> args, GhidraMcpTool annotation) {
        return parseAddress(program, args, addressStr, toolOperation, annotation)
            .flatMap(addressResult -> {
                Function function = program.getFunctionManager().getFunctionAt(addressResult.getAddress());
                if (function == null) {
                    return Mono.error(new GhidraMcpException(createFunctionNotFoundError(toolOperation, "address", addressStr)));
                }
                return deleteFunction(program, function, toolOperation);
            });
    }

    private Mono<? extends Object> deleteByName(Program program, String name, String toolOperation, Map<String, Object> args, GhidraMcpTool annotation) {
        return Mono.fromCallable(() -> {
            // Try exact match first
            Optional<Function> exactMatch = StreamSupport.stream(program.getFunctionManager().getFunctions(true).spliterator(), false)
                .filter(f -> f.getName().equals(name))
                .findFirst();

            if (exactMatch.isPresent()) {
                return exactMatch.get();
            }

            // Try regex match
            List<Function> regexMatches = StreamSupport.stream(program.getFunctionManager().getFunctions(true).spliterator(), false)
                .filter(f -> f.getName().matches(name))
                .collect(Collectors.toList());

            if (regexMatches.isEmpty()) {
                throw new GhidraMcpException(createFunctionNotFoundError(toolOperation, "name", name));
            } else if (regexMatches.size() > 1) {
                throw new GhidraMcpException(createMultipleFunctionsFoundError(toolOperation, name, regexMatches));
            }

            return regexMatches.get(0);
        }).flatMap(function -> deleteFunction(program, function, toolOperation));
    }

    private Mono<? extends Object> deleteFunction(Program program, Function function, String toolOperation) {
        Address entryPoint = function.getEntryPoint();
        String entryPointStr = entryPoint.toString();

        return executeInTransaction(program, "MCP - Delete Function at " + entryPointStr, () -> {
            DeleteFunctionCmd cmd = new DeleteFunctionCmd(entryPoint);
            if (!cmd.applyTo(program)) {
                String status = Optional.ofNullable(cmd.getStatusMsg()).orElse("Unknown error");
                GhidraMcpError error = GhidraMcpError.execution()
                    .errorCode(GhidraMcpError.ErrorCode.TRANSACTION_FAILED)
                    .message("Failed to delete function: " + status)
                    .context(new GhidraMcpError.ErrorContext(
                        toolOperation,
                        "function deletion command",
                        Map.of(ARG_ADDRESS, entryPointStr),
                        Map.of("commandStatus", status),
                        Map.of("commandSuccess", false)))
                    .suggestions(List.of(
                        new GhidraMcpError.ErrorSuggestion(
                            GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
                            "Verify the function is not protected",
                            "Ensure the target function is not locked or already removed",
                            null,
                            null)))
                    .build();
                throw new GhidraMcpException(error);
            }

            return OperationResult
                .success("delete_function", entryPointStr, "Function deleted successfully")
                .setMetadata(Map.of(
                    "name", function.getName(),
                    "entry_point", entryPointStr));
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



    private Mono<? extends Object> handleUpdatePrototype(Program program, PluginTool tool, Map<String, Object> args, GhidraMcpTool annotation) {
        String toolOperation = annotation.mcpName() + ".update_prototype";
        
        // Extract function identifiers from both direct arguments and target_type/target_value
        FunctionIdentifiers identifiers = extractFunctionIdentifiers(args);
        
        if (identifiers.isEmpty()) {
            return Mono.error(new GhidraMcpException(createMissingIdentifierError(annotation, args)));
        }

        // Check if raw prototype string is provided (preferred approach)
        Optional<String> rawPrototypeOpt = getOptionalStringArgument(args, ARG_PROTOTYPE)
            .map(String::trim)
            .filter(value -> !value.isEmpty());

        if (rawPrototypeOpt.isPresent()) {
            // Use raw prototype string with FunctionSignatureParser
            return Mono.fromCallable(() -> resolveFunctionByIdentifiers(
                program, identifiers, annotation, args, toolOperation))
                .map(function -> new UpdatePrototypeContext(program, function, rawPrototypeOpt.get()))
                .flatMap(context -> executePrototypeUpdate(program, annotation, tool, context));
        } else {
            // Build prototype from structured arguments
            String returnTypeName = getRequiredStringArgument(args, "returnType");
            Optional<String> callingConventionOpt = getOptionalStringArgument(args, "callingConvention");
            Optional<String> newFunctionNameOpt = getOptionalStringArgument(args, "newFunctionName");
            Optional<List<Map<String, Object>>> parametersOpt = getOptionalListArgument(args, "parameters");
            boolean noReturn = getOptionalBooleanArgument(args, "noReturn").orElse(false);

            return Mono.fromCallable(() -> resolveFunctionForPrototype(program,
                tool, identifiers, returnTypeName, callingConventionOpt, newFunctionNameOpt,
                parametersOpt, noReturn, annotation, args, toolOperation))
                .flatMap(context -> executePrototypeUpdate(program, annotation, tool, context));
        }
    }

    private Mono<? extends Object> executePrototypeUpdate(Program program,
                                                          GhidraMcpTool annotation,
                                                          PluginTool tool,
                                                          UpdatePrototypeContext context) {
        return executeInTransaction(program,
            "MCP - Update Function Prototype: " + context.function().getName(),
            () -> applyPrototype(program, annotation, tool, context));
    }

    private Object applyPrototype(Program program,
                                  GhidraMcpTool annotation,
                                  PluginTool tool,
                                  UpdatePrototypeContext context) throws GhidraMcpException {
        Function function = context.function();
        String prototype = context.prototypeString();

        try {
            DataTypeManager dtm = program.getDataTypeManager();
            DataTypeQueryService service = tool != null ? tool.getService(DataTypeQueryService.class) : null;
            FunctionSignatureParser parser = new FunctionSignatureParser(dtm, service);
            FunctionDefinitionDataType parsedSignature = parser.parse(function.getSignature(), prototype);

            ghidra.app.cmd.function.ApplyFunctionSignatureCmd cmd = new ghidra.app.cmd.function.ApplyFunctionSignatureCmd(
                function.getEntryPoint(),
                parsedSignature,
                SourceType.USER_DEFINED);

            if (!cmd.applyTo(program)) {
                String status = Optional.ofNullable(cmd.getStatusMsg()).orElse("Unknown error");
                GhidraMcpError error = GhidraMcpError.execution()
                    .errorCode(GhidraMcpError.ErrorCode.TRANSACTION_FAILED)
                    .message("Failed to apply function prototype: " + status)
                    .context(new GhidraMcpError.ErrorContext(
                        annotation.mcpName(),
                        "function prototype update command",
                        Map.of("prototype", prototype, ARG_FUNCTION_NAME, function.getName()),
                        Map.of("commandStatus", status),
                        Map.of("commandSuccess", false, "prototypeValid", true)))
                    .build();
                throw new GhidraMcpException(error);
            }

            return new FunctionInfo(function);
        } catch (GhidraMcpException e) {
            throw e;
        } catch (Exception e) {
            GhidraMcpError error = GhidraMcpError.validation()
                .errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
                .message("Failed to parse constructed function prototype: " + e.getMessage())
                .context(new GhidraMcpError.ErrorContext(
                    annotation.mcpName(),
                    "prototype parsing",
                    null,
                    Map.of("error", e.getMessage()),
                    Map.of("prototypeSyntax", false)))
                .build();
            throw new GhidraMcpException(error);
        }
    }

    private UpdatePrototypeContext resolveFunctionForPrototype(Program program,
                                                               PluginTool tool,
                                                               FunctionIdentifiers identifiers,
                                                               String returnTypeName,
                                                               Optional<String> callingConventionOpt,
                                                               Optional<String> newFunctionNameOpt,
                                                               Optional<List<Map<String, Object>>> parametersOpt,
                                                               boolean noReturn,
                                                               GhidraMcpTool annotation,
                                                               Map<String, Object> args,
                                                               String toolOperation) throws GhidraMcpException {
        Function function = resolveFunctionByIdentifiers(
            program,
            identifiers,
            annotation,
            args,
            toolOperation);

        String prototype = buildPrototypeString(program,
            tool,
            function,
            returnTypeName,
            callingConventionOpt,
            newFunctionNameOpt.orElse(function.getName()),
            parametersOpt,
            noReturn,
            annotation,
            args);

        return new UpdatePrototypeContext(program, function, prototype);
    }

    private Function resolveFunctionByIdentifiers(Program program,
                                                  FunctionIdentifiers identifiers,
                                                  GhidraMcpTool annotation,
                                                  Map<String, Object> args,
                                                  String toolOperation) throws GhidraMcpException {
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
                throw new GhidraMcpException(GhidraMcpErrorUtils.addressParseError(addressString, toolOperation, e));
            }
        }

        if (function == null && identifiers.name().isPresent()) {
            String functionName = identifiers.name().get();
            function = StreamSupport.stream(funcMan.getFunctions(true).spliterator(), false)
                .filter(f -> f.getName(true).equals(functionName))
                .findFirst()
                .orElse(null);
        }

        if (function == null) {
            Map<String, Object> searchCriteria = Map.of(
                ARG_FUNCTION_SYMBOL_ID, identifiers.symbolId().map(Object::toString).orElse("not provided"),
                ARG_ADDRESS, identifiers.address().orElse("not provided"),
                ARG_FUNCTION_NAME, identifiers.name().orElse("not provided"));

            GhidraMcpError error = GhidraMcpError.resourceNotFound()
                .errorCode(GhidraMcpError.ErrorCode.FUNCTION_NOT_FOUND)
                .message("Function not found using provided identifiers")
                .context(new GhidraMcpError.ErrorContext(
                    annotation.mcpName(),
                    "function lookup",
                    args,
                    searchCriteria,
                    Map.of("searchAttempted", true, "functionFound", false)))
                .build();
            throw new GhidraMcpException(error);
        }

        return function;
    }

    private String buildPrototypeString(Program program,
                                        PluginTool tool,
                                        Function function,
                                        String returnTypeName,
                                        Optional<String> callingConventionOpt,
                                        String functionName,
                                        Optional<List<Map<String, Object>>> parametersOpt,
                                        boolean noReturn,
                                        GhidraMcpTool annotation,
                                        Map<String, Object> args) throws GhidraMcpException {
        StringBuilder prototype = new StringBuilder();

        DataType returnType;
        try {
            returnType = DataTypeUtils.parseDataTypeString(program, returnTypeName, tool);
        } catch (InvalidDataTypeException | CancelledException e) {
            GhidraMcpError error = GhidraMcpError.dataTypeParsing()
                .errorCode(GhidraMcpError.ErrorCode.INVALID_TYPE_PATH)
                .message("Invalid return type: " + e.getMessage())
                .context(new GhidraMcpError.ErrorContext(
                    annotation.mcpName(),
                    "return type parsing",
                    args,
                    Map.of("returnType", returnTypeName),
                    Map.of("parseError", e.getMessage())))
                .build();
            throw new GhidraMcpException(error);
        }

        prototype.append(returnType.getName());
        callingConventionOpt.ifPresent(cc -> prototype.append(" ").append(cc));
        prototype.append(" ").append(functionName).append("(");

        if (parametersOpt.isPresent() && !parametersOpt.get().isEmpty()) {
            List<String> params = parametersOpt.get().stream()
                .map(param -> parameterToString(program, tool, param, annotation, args))
                .collect(Collectors.toList());
            prototype.append(String.join(", ", params));
        }

        if (noReturn) {
            function.setNoReturn(true);
        }

        prototype.append(")");
        return prototype.toString();
    }

    private String parameterToString(Program program,
                                     PluginTool tool,
                                     Map<String, Object> paramMap,
                                     GhidraMcpTool annotation,
                                     Map<String, Object> args) {
        String name = (String) paramMap.get("name");
        String dataType = (String) paramMap.get("dataType");

        if (name == null || dataType == null) {
            GhidraMcpError error = GhidraMcpError.validation()
                .errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
                .message("Parameter entries must include 'name' and 'dataType'")
                .context(new GhidraMcpError.ErrorContext(
                    annotation.mcpName(),
                    "parameter validation",
                    args,
                    paramMap,
                    Map.of("hasName", name != null, "hasDataType", dataType != null)))
                .build();
            throw new RuntimeException(error.getMessage());
        }

        if ("...".equals(dataType)) {
            return "...";
        }

        try {
            DataType resolved = DataTypeUtils.parseDataTypeString(program, dataType, tool);
            return resolved.getName() + " " + name;
        } catch (Exception e) {
            GhidraMcpError error = GhidraMcpError.dataTypeParsing()
                .errorCode(GhidraMcpError.ErrorCode.INVALID_TYPE_PATH)
                .message("Invalid parameter data type '" + dataType + "': " + e.getMessage())
                .context(new GhidraMcpError.ErrorContext(
                    annotation.mcpName(),
                    "parameter data type parsing",
                    args,
                    paramMap,
                    Map.of("parseError", e.getMessage())))
                .build();
            throw new RuntimeException(error.getMessage());
        }
    }

    private record UpdatePrototypeContext(Program program, Function function, String prototypeString) {}

    private record FunctionIdentifiers(Optional<Long> symbolId, Optional<String> address, Optional<String> name) {
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
            Optional.ofNullable(functionNameValue)
        );
    }

    private GhidraMcpError createMissingIdentifierError(GhidraMcpTool annotation, Map<String, Object> args) {
        Map<String, Object> providedIdentifiers = Map.of(
            ARG_FUNCTION_SYMBOL_ID, "not provided",
            ARG_ADDRESS, "not provided",
            ARG_FUNCTION_NAME, "not provided");

        return GhidraMcpError.validation()
            .errorCode(GhidraMcpError.ErrorCode.MISSING_REQUIRED_ARGUMENT)
            .message("At least one function identifier must be provided")
            .context(new GhidraMcpError.ErrorContext(
                annotation.mcpName(),
                "function identifier validation",
                args,
                providedIdentifiers,
                Map.of("identifiersProvided", 0, "minimumRequired", 1)))
            .suggestions(List.of(
                new GhidraMcpError.ErrorSuggestion(
                    GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
                    "Provide at least one function identifier",
                    "Include at least one of: " + ARG_FUNCTION_SYMBOL_ID + ", " + ARG_ADDRESS + ", or " + ARG_FUNCTION_NAME,
                    List.of(
                        "\"" + ARG_FUNCTION_SYMBOL_ID + "\": 12345",
                        "\"" + ARG_ADDRESS + "\": \"0x401000\"",
                        "\"" + ARG_FUNCTION_NAME + "\": \"main\""),
                    null)))
            .build();
    }

    private Mono<Address> parseAddressOrThrow(Program program, String addressString, String toolOperation, Map<String, Object> args) {
        return Mono.fromCallable(() -> {
            Address address = program.getAddressFactory().getAddress(addressString);
            if (address == null) {
                GhidraMcpError error = GhidraMcpError.validation()
                    .errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
                    .message("Invalid address: " + addressString)
                    .context(new GhidraMcpError.ErrorContext(
                        toolOperation,
                        "address resolution",
                        args,
                        Map.of(ARG_ADDRESS, addressString),
                        Map.of("addressResolved", false)))
                    .suggestions(List.of(
                        new GhidraMcpError.ErrorSuggestion(
                            GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
                            "Use a valid hexadecimal address",
                            "Provide the function entry point as a hexadecimal value",
                            List.of("0x401000", "401000", "0x00401000"),
                            null)))
                    .build();
                throw new GhidraMcpException(error);
            }
            return address;
        }).onErrorMap(e -> {
            if (e instanceof GhidraMcpException) {
                return e;
            }
            return new GhidraMcpException(GhidraMcpErrorUtils.addressParseError(addressString, toolOperation, e));
        });
    }


    private Mono<? extends Object> handleListVariables(Program program, Map<String, Object> args, GhidraMcpTool annotation) {
        String toolOperation = annotation.mcpName() + ".list_variables";
        
        // Extract function identifiers from both direct arguments and target_type/target_value
        FunctionIdentifiers identifiers = extractFunctionIdentifiers(args);
        
        if (identifiers.isEmpty()) {
            return Mono.error(new GhidraMcpException(createMissingIdentifierError(annotation, args)));
        }

        return Mono.fromCallable(() -> {
            Function function = resolveFunctionByIdentifiers(program, identifiers, annotation, args, toolOperation);
            return listFunctionVariables(function, program, args, annotation);
        });
    }

    private PaginatedResult<FunctionVariableInfo> listFunctionVariables(Function function, Program program, Map<String, Object> args, GhidraMcpTool annotation) {
        Optional<String> cursorOpt = getOptionalStringArgument(args, ARG_CURSOR);
        
        // Get listing variables
        Stream<FunctionVariableInfo> listingVarStream = Arrays.stream(function.getAllVariables())
                .map(FunctionVariableInfo::new);

        // Get decompiler variables
        Stream<FunctionVariableInfo> decompilerVarStream = Stream.empty();
        DecompInterface decomplib = new DecompInterface();
        try {
            decomplib.setOptions(new DecompileOptions());
            decomplib.openProgram(program);
            DecompileResults results = decomplib.decompileFunction(function,
                    decomplib.getOptions().getDefaultTimeout(), new ConsoleTaskMonitor());

            if (results == null) {
                // Decompiler failed but continue with listing variables only
                ghidra.util.Msg.warn(this, "Decompiler returned null results for function: " + function.getName());
            } else {
                HighFunction hf = results.getHighFunction();
                if (hf != null) {
                    LocalSymbolMap localSymbolMap = hf.getLocalSymbolMap();
                    if (localSymbolMap != null) {
                        java.util.Iterator<HighSymbol> highSymbolIterator = localSymbolMap.getSymbols();
                        decompilerVarStream = StreamSupport.stream(
                                Spliterators.spliteratorUnknownSize(highSymbolIterator, Spliterator.ORDERED), false)
                                .map(HighSymbol::getHighVariable)
                                .filter(java.util.Objects::nonNull)
                                .map(hv -> new FunctionVariableInfo(hv, program));
                    }
                } else {
                    ghidra.util.Msg.warn(this,
                            "Decompilation did not yield a HighFunction for function: " + function.getName());
                }
            }
        } catch (Exception e) {
            // Log the error but continue with listing variables
            ghidra.util.Msg.error(this,
                    "Error during decompilation for ListFunctionVariables: " + e.getMessage(), e);
        } finally {
            if (decomplib != null) {
                decomplib.dispose();
            }
        }

        List<FunctionVariableInfo> variablesToList = Stream.concat(listingVarStream, decompilerVarStream)
                .sorted(Comparator.comparing(FunctionVariableInfo::getStorage)
                        .thenComparing(FunctionVariableInfo::getEffectiveName))
                .collect(Collectors.toList());

        final String finalCursorStr = cursorOpt.orElse(null);

        List<FunctionVariableInfo> paginatedVariables = variablesToList.stream()
                .dropWhile(varInfo -> {
                    if (finalCursorStr == null)
                        return false;

                    String[] parts = finalCursorStr.split(":", 2);
                    String cursorStorage = parts[0];
                    String cursorName = parts.length > 1 ? parts[1] : "";

                    int storageCompare = varInfo.getStorage().compareTo(cursorStorage);
                    if (storageCompare < 0)
                        return true;
                    if (storageCompare == 0) {
                        return varInfo.getEffectiveName().compareTo(cursorName) <= 0;
                    }
                    return false;
                })
                .limit(DEFAULT_PAGE_LIMIT + 1)
                .collect(Collectors.toList());

        boolean hasMore = paginatedVariables.size() > DEFAULT_PAGE_LIMIT;
        List<FunctionVariableInfo> resultsForPage = paginatedVariables.subList(0,
                Math.min(paginatedVariables.size(), DEFAULT_PAGE_LIMIT));
        String nextCursor = null;
        if (hasMore && !resultsForPage.isEmpty()) {
            FunctionVariableInfo lastItem = resultsForPage.get(resultsForPage.size() - 1);
            nextCursor = lastItem.getStorage() + ":" + lastItem.getEffectiveName();
        }

        return new PaginatedResult<>(resultsForPage, nextCursor);
    }

    private void ensureArgumentPresent(Map<String, Object> args, String argumentName, String toolOperation) throws GhidraMcpException {
        if (!args.containsKey(argumentName) || args.get(argumentName) == null) {
            GhidraMcpError error = GhidraMcpError.validation()
                .errorCode(GhidraMcpError.ErrorCode.MISSING_REQUIRED_ARGUMENT)
                .message("Missing required argument: '" + argumentName + "'")
                .context(new GhidraMcpError.ErrorContext(
                    toolOperation,
                    "argument validation",
                    args,
                    Map.of(argumentName, "not provided"),
                    Map.of("required", true)))
                .suggestions(List.of(
                    new GhidraMcpError.ErrorSuggestion(
                        GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
                        "Provide the '" + argumentName + "' argument",
                        "Include the " + argumentName + " field with a valid value",
                        List.of("\"" + argumentName + "\": \"example_value\""),
                        null)))
                .build();
            throw new GhidraMcpException(error);
        }
    }

    private GhidraMcpError createFunctionNotFoundError(String toolOperation, String searchType, String searchValue) {
        return GhidraMcpError.validation()
            .errorCode(GhidraMcpError.ErrorCode.FUNCTION_NOT_FOUND)
            .message("Function not found using " + searchType + ": " + searchValue)
            .context(new GhidraMcpError.ErrorContext(
                toolOperation,
                "function resolution",
                Map.of(searchType, searchValue),
                Map.of(),
                Map.of("searchMethod", searchType)))
            .suggestions(List.of(
                new GhidraMcpError.ErrorSuggestion(
                    GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
                    "Verify the function exists",
                    "Check that the function identifier is correct",
                    List.of(
                        "\"symbol_id\": 12345",
                        "\"address\": \"0x401000\"",
                        "\"name\": \"main\""
                    ),
                    null)))
            .build();
    }

    private GhidraMcpError createMultipleFunctionsFoundError(String toolOperation, String searchValue, List<Function> functions) {
        List<String> functionNames = functions.stream()
            .map(Function::getName)
            .limit(5)
            .collect(Collectors.toList());

        return GhidraMcpError.validation()
            .errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
            .message("Multiple functions found for name pattern: " + searchValue)
            .context(new GhidraMcpError.ErrorContext(
                toolOperation,
                "function resolution",
                Map.of("name", searchValue),
                Map.of("matchCount", functions.size()),
                Map.of("firstFiveMatches", functionNames)))
            .suggestions(List.of(
                new GhidraMcpError.ErrorSuggestion(
                    GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
                    "Use a more specific function identifier",
                    "Consider using symbol_id or address for exact identification",
                    List.of(
                        "\"symbol_id\": 12345",
                        "\"address\": \"0x401000\"",
                        "\"name\": \"exact_function_name\""
                    ),
                    null)))
            .build();
    }

    private GhidraMcpError createInvalidAddressError(String addressStr, Exception cause) {
        return GhidraMcpError.validation()
            .errorCode(GhidraMcpError.ErrorCode.ADDRESS_PARSE_FAILED)
            .message("Invalid address format: " + addressStr)
            .context(new GhidraMcpError.ErrorContext(
                this.getClass().getAnnotation(GhidraMcpTool.class).mcpName(),
                "address parsing",
                Map.of(ARG_ADDRESS, addressStr),
                Map.of(),
                Map.of("parseError", cause.getMessage())))
            .suggestions(List.of(
                new GhidraMcpError.ErrorSuggestion(
                    GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
                    "Use valid hexadecimal address format",
                    "Provide address in proper format",
                    List.of("0x401000", "401000", "0x00401000"),
                    null)))
            .build();
    }

    private GhidraMcpError createInvalidRegexError(String pattern, Exception cause) {
        return GhidraMcpError.validation()
            .errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
            .message("Invalid regex pattern: " + cause.getMessage())
            .context(new GhidraMcpError.ErrorContext(
                this.getClass().getAnnotation(GhidraMcpTool.class).mcpName(),
                "regex compilation",
                Map.of(ARG_NAME, pattern),
                Map.of(),
                Map.of("regexError", cause.getMessage())))
            .suggestions(List.of(
                new GhidraMcpError.ErrorSuggestion(
                    GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
                    "Provide a valid Java regex pattern",
                    "Use proper regex syntax for pattern matching",
                    List.of(".*main.*", "decrypt_.*", "^get.*"),
                    null)))
            .build();
    }

    private GhidraMcpError createMissingParameterError() {
        return GhidraMcpError.validation()
            .errorCode(GhidraMcpError.ErrorCode.MISSING_REQUIRED_ARGUMENT)
            .message("No search parameters provided")
            .context(new GhidraMcpError.ErrorContext(
                this.getClass().getAnnotation(GhidraMcpTool.class).mcpName(),
                "parameter validation",
                Map.of(),
                Map.of(),
                Map.of("availableParameters", List.of(ARG_SYMBOL_ID, ARG_ADDRESS, ARG_NAME))))
            .suggestions(List.of(
                new GhidraMcpError.ErrorSuggestion(
                    GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
                    "Provide at least one search parameter",
                    "Use symbol_id, address, or name parameter",
                    List.of(
                        "\"symbol_id\": 12345",
                        "\"address\": \"0x401000\"",
                        "\"name\": \"main\"",
                        "\"name\": \".*decrypt.*\""
                    ),
                    null)))
            .build();
    }
}