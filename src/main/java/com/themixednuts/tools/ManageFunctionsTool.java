package com.themixednuts.tools;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.FunctionAnalysis;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.models.FunctionInfo;
import com.themixednuts.models.FunctionSearchCriteria;
import com.themixednuts.models.FunctionSearchResponse;
import com.themixednuts.models.OperationResult;
import com.themixednuts.utils.GhidraMcpErrorUtils;
import com.themixednuts.utils.DataTypeUtils;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.cmd.function.DeleteFunctionCmd;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import io.modelcontextprotocol.common.McpTransportContext;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import java.util.stream.Stream;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.app.services.DataTypeQueryService;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.util.exception.CancelledException;

@GhidraMcpTool(
    name = "Manage Functions",
    description = "Comprehensive function management including creation, inspection, decompilation, and prototype updates.",
    mcpName = "manage_functions",
    mcpDescription = """
    <use_case>
    Manage and analyze functions for reverse engineering workflows. Create, inspect, decompile, search, and update
    function prototypes to understand program structure, control flow, and calling conventions.
    </use_case>

    <important_notes>
    - Supports multiple function identification methods (name, address, symbol ID, regex)
    - Provides detailed function information including parameters, return types, and call sites
    - Integrates decompilation for high-level code analysis
    - Handles function creation with automatic boundary detection
    </important_notes>

    <examples>
    Retrieve a function by name:
    {
      "fileName": "program.exe",
      "action": "analyze",
      "target_type": "name",
      "target_value": "main"
    }

    Create a function at an address:
    {
      "fileName": "program.exe",
      "action": "create",
      "target_type": "address",
      "target_value": "0x401000",
      "function_name": "decrypt_data"
    }
    </examples>
    """
)
public class ManageFunctionsTool implements IGhidraMcpSpecification {

    public static final String ARG_ACTION = "action";
    public static final String ARG_TARGET_TYPE = "target_type";
    public static final String ARG_TARGET_VALUE = "target_value";
    public static final String ARG_INCLUDE_DECOMPILATION = "include_decompilation";
    public static final String ARG_INCLUDE_PCODE = "include_pcode";
    public static final String ARG_SEARCH_PATTERN = "search_pattern";
    public static final String ARG_PROTOTYPE = "prototype";
    public static final String ARG_ADDRESS = "address";
    public static final String ARG_FUNCTION_NAME = "function_name";
    public static final String ARG_FUNCTION_SYMBOL_ID = "symbol_id";

    private static final int SEARCH_RESULT_LIMIT = 100;

    @Override
    public JsonSchema schema() {
        IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();

        schemaRoot.property(ARG_FILE_NAME,
                JsonSchemaBuilder.string(mapper)
                        .description("The name of the program file."));

        schemaRoot.property(ARG_ACTION, JsonSchemaBuilder.string(mapper)
                .enumValues("analyze", "create", "delete", "search", "list", "get_function_containing", "update_prototype")
                .description("Action to perform on functions"));

        schemaRoot.property(ARG_TARGET_TYPE, JsonSchemaBuilder.string(mapper)
                .enumValues("name", "address", "symbol_id", "regex", "all")
                .description("How to identify the target function(s)"));

        schemaRoot.property(ARG_TARGET_VALUE, JsonSchemaBuilder.string(mapper)
                .description("The target value (function name, address, symbol ID, or regex pattern)"));

        schemaRoot.property(ARG_FUNCTION_NAME, JsonSchemaBuilder.string(mapper)
                .description("Function name for creation or rename operations"));

        schemaRoot.property(ARG_ADDRESS, JsonSchemaBuilder.string(mapper)
                .description("Function entry point address used by create/delete actions")
                .pattern("^(0x)?[0-9a-fA-F]+$"));

        schemaRoot.property(ARG_FUNCTION_SYMBOL_ID, JsonSchemaBuilder.integer(mapper)
                .description("Symbol ID identifying the target function"));

        schemaRoot.property(ARG_INCLUDE_DECOMPILATION, JsonSchemaBuilder.bool(mapper)
                .description("Include decompiled C code in analysis results")
                .defaultValue(false));

        schemaRoot.property(ARG_INCLUDE_PCODE, JsonSchemaBuilder.bool(mapper)
                .description("Include P-code intermediate representation in results")
                .defaultValue(false));

        schemaRoot.property(ARG_SEARCH_PATTERN, JsonSchemaBuilder.string(mapper)
                .description("Pattern for searching functions (used with search action)"));

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
                case "analyze" -> handleAnalyze(program, args, annotation);
                case "create" -> handleCreate(program, args, annotation);
                case "delete" -> handleDelete(program, args, annotation);
                case "search" -> handleSearch(program, args, annotation);
                case "list" -> handleList(program, args, annotation);
                case "get_function_containing" -> handleGetFunctionContaining(program, args, annotation);
                case "update_prototype" -> handleUpdatePrototype(program, tool, args, annotation);
                default -> {
                    GhidraMcpError error = GhidraMcpError.validation()
                        .errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
                        .message("Invalid action: " + action)
                        .context(new GhidraMcpError.ErrorContext(
                            annotation.mcpName(),
                            "action validation",
                            args,
                            Map.of(ARG_ACTION, action),
                            Map.of("validActions", List.of("analyze", "create", "delete", "search", "list", "update_prototype"))))
                        .suggestions(List.of(
                            new GhidraMcpError.ErrorSuggestion(
                                GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
                                "Use a valid action",
                                "Choose from: analyze, create, delete, search, list, update_prototype",
                                List.of("analyze", "create", "delete", "search", "list", "update_prototype"),
                                null)))
                        .build();
                    yield Mono.error(new GhidraMcpException(error));
                }
            };
        });
    }

    private Mono<? extends Object> handleAnalyze(Program program, Map<String, Object> args, GhidraMcpTool annotation) {
        String targetType = getOptionalStringArgument(args, ARG_TARGET_TYPE).orElse("name");
        String targetValue = getRequiredStringArgument(args, ARG_TARGET_VALUE);
        boolean includeDecompilation = getOptionalBooleanArgument(args, ARG_INCLUDE_DECOMPILATION).orElse(false);
        boolean includePcode = getOptionalBooleanArgument(args, ARG_INCLUDE_PCODE).orElse(false);

        return Mono.fromCallable(() -> analyzeFunction(program, args, annotation, targetType, targetValue, includeDecompilation, includePcode));
    }

    private Map<String, Object> analyzeFunction(Program program,
                                                Map<String, Object> args,
                                                GhidraMcpTool annotation,
                                                String targetType,
                                                String targetValue,
                                                boolean includeDecompilation,
                                                boolean includePcode) throws GhidraMcpException {
        FunctionManager functionManager = program.getFunctionManager();
        List<Function> targetFunctions = findFunctions(functionManager, program, targetType, targetValue, annotation);

        if (targetFunctions.isEmpty()) {
            GhidraMcpError error = GhidraMcpError.resourceNotFound()
                .errorCode(GhidraMcpError.ErrorCode.FUNCTION_NOT_FOUND)
                .message("No functions found matching criteria")
                .context(new GhidraMcpError.ErrorContext(
                    annotation.mcpName(),
                    "function lookup",
                    args,
                    Map.of(ARG_TARGET_TYPE, targetType, ARG_TARGET_VALUE, targetValue),
                    Map.of("functionsFound", 0)))
                .suggestions(List.of(
                    new GhidraMcpError.ErrorSuggestion(
                        GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
                        "Verify function exists",
                        "Use list action to see available functions",
                        null,
                        List.of("list"))))
                .build();
            throw new GhidraMcpException(error);
        }

        List<FunctionAnalysis> results = new ArrayList<>();
        DecompInterface decomp = null;

        try {
            if (includeDecompilation) {
                decomp = new DecompInterface();
                decomp.openProgram(program);
            }

            for (Function function : targetFunctions) {
                FunctionAnalysis functionAnalysis = analyzeSingleFunction(
                    function, program, decomp, includeDecompilation, includePcode);
                results.add(functionAnalysis);
            }

        } finally {
            if (decomp != null) {
                decomp.dispose();
            }
        }

            return Map.of(
                "functions", results,
                "total_analyzed", results.size(),
                "analysis_options", Map.of(
                    "decompilation_included", includeDecompilation,
                    "pcode_included", includePcode
                )
            );
        
    }

    private FunctionAnalysis analyzeSingleFunction(Function function, Program program,
                                                   DecompInterface decomp,
                                                   boolean includeDecompilation,
                                                   boolean includePcode) {
        // Create the base function analysis
        FunctionAnalysis analysis = new FunctionAnalysis(function);

        // Add decompilation if requested
        if (includeDecompilation && decomp != null) {
            try {
                DecompileResults results = decomp.decompileFunction(function, 30, null);
                if (results != null && results.decompileCompleted()) {
                    String code = results.getDecompiledFunction().getC();
                    analysis.setDecompiledCode(code != null ? code : "// Decompilation failed");
                } else {
                    analysis.setDecompiledCode("// Decompilation error: " +
                        (results != null ? results.getErrorMessage() : "Unknown error"));
                }
            } catch (Exception e) {
                analysis.setDecompiledCode("// Decompilation exception: " + e.getMessage());
            }
        }

        // Add P-code if requested
        if (includePcode && decomp != null) {
            try {
                DecompileResults results = decomp.decompileFunction(function, 30, null);
                if (results != null && results.decompileCompleted()) {
                    HighFunction highFunc = results.getHighFunction();
                    if (highFunc != null) {
                        List<String> pcodeOps = new ArrayList<>();
                        Iterator<PcodeOpAST> ops = highFunc.getPcodeOps();
                        while (ops.hasNext() && pcodeOps.size() < 50) { // Limit to first 50 ops
                            PcodeOpAST op = ops.next();
                            pcodeOps.add(op.toString());
                        }
                        analysis.setPcodeOperations(pcodeOps);
                    }
                }
            } catch (Exception e) {
                analysis.setPcodeOperations(List.of("// P-code analysis error: " + e.getMessage()));
            }
        }

        return analysis;
    }

    private List<Function> findFunctions(FunctionManager functionManager, Program program,
                                       String targetType, String targetValue, GhidraMcpTool annotation) {
        return switch (targetType.toLowerCase()) {
            case "name" -> {
                Function func = StreamSupport.stream(functionManager.getFunctions(true).spliterator(), false)
                    .filter(f -> f.getName().equals(targetValue))
                    .findFirst().orElse(null);
                yield func != null ? List.of(func) : List.of();
            }
            case "address" -> {
                try {
                    Address addr = program.getAddressFactory().getAddress(targetValue);
                    Function func = functionManager.getFunctionAt(addr);
                    yield func != null ? List.of(func) : List.of();
                } catch (Exception e) {
                    yield List.of();
                }
            }
            case "symbol_id" -> {
                try {
                    long symbolId = Long.parseLong(targetValue);
                    ghidra.program.model.symbol.Symbol symbol = program.getSymbolTable().getSymbol(symbolId);
                    if (symbol != null) {
                        Function func = functionManager.getFunctionAt(symbol.getAddress());
                        yield func != null ? List.of(func) : List.of();
                    }
                    yield List.of();
                } catch (NumberFormatException e) {
                    yield List.of();
                }
            }
            case "regex" -> StreamSupport.stream(functionManager.getFunctions(true).spliterator(), false)
                .filter(f -> f.getName().matches(targetValue))
                .collect(Collectors.toList());
            case "all" -> StreamSupport.stream(functionManager.getFunctions(true).spliterator(), false)
                .limit(100) // Limit to prevent overwhelming responses
                .collect(Collectors.toList());
            default -> List.of();
        };
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

                return OperationResult
                    .success("create_function", functionAddress.toString(), "Function created successfully")
                    .setResult(new FunctionInfo(createdFunction))
                    .setMetadata(Map.of(
                        "function_name", createdFunction.getName(),
                        "entry_point", createdFunction.getEntryPoint().toString()));
            });
        });
    }

    private Mono<? extends Object> handleDelete(Program program, Map<String, Object> args, GhidraMcpTool annotation) {
        String toolOperation = annotation.mcpName() + ".delete";
        Long symbolId = getOptionalLongArgument(args, ARG_FUNCTION_SYMBOL_ID).orElse(null);
        String addressValue = getOptionalStringArgument(args, ARG_ADDRESS).orElse(null);
        String functionNameValue = getOptionalStringArgument(args, ARG_FUNCTION_NAME).orElse(null);

        Optional<String> targetTypeOpt = getOptionalStringArgument(args, ARG_TARGET_TYPE);
        Optional<String> targetValueOpt = getOptionalStringArgument(args, ARG_TARGET_VALUE);

        if (targetTypeOpt.isPresent() && targetValueOpt.isPresent()) {
            String normalizedType = targetTypeOpt.get().toLowerCase(Locale.ROOT);
            String targetValue = targetValueOpt.get().trim();
            switch (normalizedType) {
                case "symbol_id" -> {
                    if (symbolId == null) {
                        try {
                            symbolId = Long.parseLong(targetValue);
                        } catch (NumberFormatException ignored) {
                            // fall through to validation below
                        }
                    }
                }
                case "address" -> {
                    if (addressValue == null) {
                        addressValue = targetValue;
                    }
                }
                case "name" -> {
                    if (functionNameValue == null) {
                        functionNameValue = targetValue;
                    }
                }
                default -> {
                    // ignore unsupported target types here; validation handled elsewhere
                }
            }
        }

        Optional<Long> symbolIdOpt = Optional.ofNullable(symbolId);
        Optional<String> addressOpt = Optional.ofNullable(addressValue);
        Optional<String> nameOpt = Optional.ofNullable(functionNameValue);

        if (symbolIdOpt.isEmpty() && addressOpt.isEmpty() && nameOpt.isEmpty()) {
            Map<String, Object> providedIdentifiers = Map.of(
                ARG_FUNCTION_SYMBOL_ID, "not provided",
                ARG_ADDRESS, "not provided",
                ARG_FUNCTION_NAME, "not provided");

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
                            ARG_FUNCTION_SYMBOL_ID + ": 12345",
                            ARG_ADDRESS + ": \"0x401000\"",
                            ARG_FUNCTION_NAME + ": \"main\""),
                        null)))
                .build();
            return Mono.error(new GhidraMcpException(error));
        }

        FunctionManager functionManager = program.getFunctionManager();
        SymbolTable symbolTable = program.getSymbolTable();

        Function targetFunction;
        try {
            targetFunction = resolveFunctionForDeletion(
                program,
                functionManager,
                symbolTable,
                symbolIdOpt,
                addressOpt,
                nameOpt,
                toolOperation,
                args);
        } catch (GhidraMcpException e) {
            return Mono.error(e);
        }

        Address entryPoint = targetFunction.getEntryPoint();
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
                    "name", targetFunction.getName(),
                    "entry_point", entryPointStr));
        });
    }

    private Mono<? extends Object> handleSearch(Program program, Map<String, Object> args, GhidraMcpTool annotation) {
        String toolOperation = getMcpName() + ".search";
        return Mono.fromCallable(() -> {
            FunctionManager functionManager = program.getFunctionManager();

            String targetType = getOptionalStringArgument(args, ARG_TARGET_TYPE).orElse("name");
            String normalizedType = targetType.toLowerCase(Locale.ROOT);

            Optional<String> cursorOpt = getOptionalStringArgument(args, ARG_CURSOR);
            Optional<String> searchPatternOpt = getOptionalStringArgument(args, ARG_SEARCH_PATTERN);
            Optional<String> targetValueOpt = getOptionalStringArgument(args, ARG_TARGET_VALUE);

            String searchPatternValue = searchPatternOpt.map(String::trim).filter(value -> !value.isEmpty()).orElse(null);
            String targetValueValue = targetValueOpt.map(String::trim).filter(value -> !value.isEmpty()).orElse(null);
            String cursorValue = cursorOpt.map(String::trim).filter(value -> !value.isEmpty()).orElse(null);

            Map<String, Object> searchCriteria = new HashMap<>();
            searchCriteria.put(ARG_TARGET_TYPE, normalizedType);
            if (searchPatternValue != null) {
                searchCriteria.put(ARG_SEARCH_PATTERN, searchPatternValue);
            }
            if (targetValueValue != null) {
                searchCriteria.put(ARG_TARGET_VALUE, targetValueValue);
            }
            if (cursorValue != null) {
                searchCriteria.put(ARG_CURSOR, cursorValue);
            }

            Address cursorAddress = null;
            if (cursorValue != null) {
                try {
                    cursorAddress = program.getAddressFactory().getAddress(cursorValue);
                    if (cursorAddress == null) {
                        throw new IllegalArgumentException("Unresolvable cursor address");
                    }
                } catch (Exception e) {
                    GhidraMcpError error = GhidraMcpErrorUtils.addressParseError(cursorValue, toolOperation, e);
                    throw new GhidraMcpException(error);
                }
            }

            final Address finalCursorAddress = cursorAddress;

            List<Function> matchingFunctions = switch (normalizedType) {
                case "name" -> {
                    String pattern = searchPatternValue != null ? searchPatternValue : targetValueValue;
                    if (pattern == null) {
                        String missingArgName = searchPatternOpt.isPresent() ? ARG_SEARCH_PATTERN : ARG_TARGET_VALUE;
                        GhidraMcpError error = GhidraMcpErrorUtils.missingRequiredArgument(missingArgName, toolOperation, args);
                        throw new GhidraMcpException(error);
                    }

                    String normalizedPattern = pattern.toLowerCase(Locale.ROOT);
                    yield StreamSupport.stream(functionManager.getFunctions(true).spliterator(), false)
                        .filter(function -> {
                            String functionName = function.getName();
                            return functionName != null && functionName.toLowerCase(Locale.ROOT).contains(normalizedPattern);
                        })
                        .collect(Collectors.toList());
                }
                case "regex" -> {
                    String regexValue = searchPatternValue != null ? searchPatternValue : targetValueValue;
                    if (regexValue == null) {
                        String missingArgName = searchPatternOpt.isPresent() ? ARG_SEARCH_PATTERN : ARG_TARGET_VALUE;
                        GhidraMcpError error = GhidraMcpErrorUtils.missingRequiredArgument(missingArgName, toolOperation, args);
                        throw new GhidraMcpException(error);
                    }

                    Pattern compiled;
                    try {
                        compiled = Pattern.compile(regexValue);
                    } catch (PatternSyntaxException e) {
                        GhidraMcpError error = GhidraMcpError.validation()
                            .errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
                            .message("Invalid regex pattern: " + e.getMessage())
                            .context(new GhidraMcpError.ErrorContext(
                                toolOperation,
                                "function name regex",
                                args,
                                Map.of(ARG_SEARCH_PATTERN, regexValue),
                                Map.of("patternValid", false, "patternError", e.getMessage())))
                            .suggestions(List.of(
                                new GhidraMcpError.ErrorSuggestion(
                                    GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
                                    "Provide a valid regular expression",
                                    "Correct the regex syntax",
                                    List.of("main.*", "sub_\\d+", ".*Init"),
                                    null)))
                            .build();
                        throw new GhidraMcpException(error);
                    }

                    yield StreamSupport.stream(functionManager.getFunctions(true).spliterator(), false)
                        .filter(function -> {
                            String functionName = function.getName();
                            return functionName != null && compiled.matcher(functionName).find();
                        })
                        .collect(Collectors.toList());
                }
                case "address" -> {
                    String addressValue = targetValueValue != null ? targetValueValue : searchPatternValue;
                    if (addressValue == null) {
                        GhidraMcpError error = GhidraMcpErrorUtils.missingRequiredArgument(ARG_TARGET_VALUE, toolOperation, args);
                        throw new GhidraMcpException(error);
                    }

                    Address address;
                    try {
                        address = program.getAddressFactory().getAddress(addressValue);
                        if (address == null) {
                            throw new IllegalArgumentException("Unresolvable address");
                        }
                    } catch (Exception e) {
                        GhidraMcpError error = GhidraMcpErrorUtils.addressParseError(addressValue, toolOperation, e);
                        throw new GhidraMcpException(error);
                    }

                    Function function = functionManager.getFunctionContaining(address);
                    yield function != null ? List.of(function) : List.of();
                }
                case "symbol_id" -> {
                    String symbolIdValue = targetValueValue != null ? targetValueValue : searchPatternValue;
                    if (symbolIdValue == null) {
                        GhidraMcpError error = GhidraMcpErrorUtils.missingRequiredArgument(ARG_TARGET_VALUE, toolOperation, args);
                        throw new GhidraMcpException(error);
                    }

                    long symbolId;
                    try {
                        symbolId = Long.parseLong(symbolIdValue);
                    } catch (NumberFormatException e) {
                        GhidraMcpError error = GhidraMcpError.validation()
                            .errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
                            .message("Invalid symbol ID: " + symbolIdValue)
                            .context(new GhidraMcpError.ErrorContext(
                                toolOperation,
                                "function symbol lookup",
                                args,
                                Map.of(ARG_TARGET_VALUE, symbolIdValue),
                                Map.of("expectedType", "long", "parseError", e.getMessage())))
                            .suggestions(List.of(
                                new GhidraMcpError.ErrorSuggestion(
                                    GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
                                    "Use numeric symbol identifiers",
                                    "Provide a numeric symbol ID",
                                    List.of("1024", "2048", "4096"),
                                    null)))
                            .build();
                        throw new GhidraMcpException(error);
                    }

                    ghidra.program.model.symbol.Symbol symbol = program.getSymbolTable().getSymbol(symbolId);
                    if (symbol == null) {
                        yield List.of();
                    }

                    Function function = functionManager.getFunctionAt(symbol.getAddress());
                    yield function != null ? List.of(function) : List.of();
                }
                case "all" -> StreamSupport.stream(functionManager.getFunctions(true).spliterator(), false)
                    .collect(Collectors.toList());
                default -> {
                    GhidraMcpError error = GhidraMcpError.validation()
                        .errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
                        .message("Unsupported target_type for search: " + targetType)
                        .context(new GhidraMcpError.ErrorContext(
                            toolOperation,
                            "target type validation",
                            args,
                            Map.of(ARG_TARGET_TYPE, targetType),
                            Map.of("supportedTypes", List.of("name", "regex", "address", "symbol_id", "all"))))
                        .suggestions(List.of(
                            new GhidraMcpError.ErrorSuggestion(
                                GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
                                "Use a supported target_type",
                                "Choose one of the supported target types",
                                List.of("name", "regex", "address", "symbol_id", "all"),
                                null)))
                        .build();
                    throw new GhidraMcpException(error);
                }
            };

            if (matchingFunctions.isEmpty()) {
                List<String> suggestionNames = getFunctionNameSamples(functionManager, 10);
                GhidraMcpError error = GhidraMcpErrorUtils.searchNoResults(searchCriteria, toolOperation, suggestionNames);
                throw new GhidraMcpException(error);
            }

            matchingFunctions.sort(Comparator.comparing(Function::getEntryPoint));

            Stream<Function> paginationStream = matchingFunctions.stream();
            if (finalCursorAddress != null) {
                paginationStream = paginationStream.filter(function -> function.getEntryPoint().compareTo(finalCursorAddress) > 0);
            }

            List<Function> pageBuffer = paginationStream
                .limit((long) SEARCH_RESULT_LIMIT + 1)
                .collect(Collectors.toList());

            boolean hasMore = pageBuffer.size() > SEARCH_RESULT_LIMIT;
            List<Function> pageFunctions = hasMore
                ? pageBuffer.subList(0, SEARCH_RESULT_LIMIT)
                : pageBuffer;

            String nextCursor = hasMore
                ? pageBuffer.get(SEARCH_RESULT_LIMIT).getEntryPoint().toString()
                : null;

            List<FunctionInfo> results = pageFunctions.stream()
                .map(FunctionInfo::new)
                .collect(Collectors.toList());

            FunctionSearchCriteria criteria = new FunctionSearchCriteria(
                normalizedType,
                searchPatternValue,
                targetValueValue,
                cursorValue
            );

            return new FunctionSearchResponse(
                criteria,
                List.copyOf(results),
                matchingFunctions.size(),
                results.size(),
                SEARCH_RESULT_LIMIT,
                hasMore,
                nextCursor
            );
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

    private Mono<? extends Object> handleList(Program program, Map<String, Object> args, GhidraMcpTool annotation) {
        return Mono.fromCallable(() -> {
            FunctionManager functionManager = program.getFunctionManager();
            List<FunctionInfo> functions = StreamSupport
                .stream(functionManager.getFunctions(true).spliterator(), false)
                .limit(50)
                .map(FunctionInfo::new)
                .collect(Collectors.toList());

            return Map.of(
                "functions", functions,
                "total_count", functionManager.getFunctionCount(),
                "displayed_count", functions.size()
            );
        });
    }

    private Mono<? extends Object> handleGetFunctionContaining(Program program, Map<String, Object> args, GhidraMcpTool annotation) {
        String addressStr = getRequiredStringArgument(args, ARG_ADDRESS);

        return parseAddress(program, args, addressStr, getMcpName() + ".get_function_containing", annotation)
            .flatMap(addressResult -> {
                FunctionManager functionManager = program.getFunctionManager();
                Function function = functionManager.getFunctionContaining(addressResult.getAddress());

                if (function == null) {
                    Map<String, Object> searchCriteria = Map.of(ARG_ADDRESS, addressResult.getAddressString());

                    List<String> availableFunctions = StreamSupport.stream(functionManager.getFunctions(true).spliterator(), false)
                        .limit(50)
                        .map(Function::getName)
                        .collect(Collectors.toList());

                    GhidraMcpError error = GhidraMcpError.resourceNotFound()
                        .errorCode(GhidraMcpError.ErrorCode.FUNCTION_NOT_FOUND)
                        .message("No function found containing the specified address")
                        .context(new GhidraMcpError.ErrorContext(
                            annotation.mcpName(),
                            "get_function_containing",
                            args,
                            searchCriteria,
                            Map.of("addressValid", true,
                                "functionsChecked", availableFunctions.size())))
                        .relatedResources(availableFunctions)
                        .suggestions(List.of(
                            new GhidraMcpError.ErrorSuggestion(
                                GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
                                "Verify address is within a function",
                                "Confirm the address belongs to an existing function",
                                null,
                                null),
                            new GhidraMcpError.ErrorSuggestion(
                                GhidraMcpError.ErrorSuggestion.SuggestionType.ALTERNATIVE_APPROACH,
                                "Consider defining a function at this location",
                                "Use function creation tools if this address should be part of a function",
                                null,
                                null)))
                        .build();
                    return Mono.error(new GhidraMcpException(error));
                }

                return Mono.just(new FunctionInfo(function));
            });
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

            return Map.of(
                "message", "Function prototype updated successfully",
                "prototype", prototype,
                "functionName", function.getName());
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
        Long symbolId = getOptionalLongArgument(args, ARG_FUNCTION_SYMBOL_ID).orElse(null);
        String addressValue = getOptionalStringArgument(args, ARG_ADDRESS).orElse(null);
        String functionNameValue = getOptionalStringArgument(args, ARG_FUNCTION_NAME).orElse(null);

        Optional<String> targetTypeOpt = getOptionalStringArgument(args, ARG_TARGET_TYPE);
        Optional<String> targetValueOpt = getOptionalStringArgument(args, ARG_TARGET_VALUE);

        if (targetTypeOpt.isPresent() && targetValueOpt.isPresent()) {
            String normalizedType = targetTypeOpt.get().toLowerCase(Locale.ROOT);
            String targetValue = targetValueOpt.get().trim();
            switch (normalizedType) {
                case "symbol_id" -> {
                    if (symbolId == null) {
                        try {
                            symbolId = Long.parseLong(targetValue);
                        } catch (NumberFormatException ignored) {
                            // fall through to validation below
                        }
                    }
                }
                case "address" -> {
                    if (addressValue == null) {
                        addressValue = targetValue;
                    }
                }
                case "name" -> {
                    if (functionNameValue == null) {
                        functionNameValue = targetValue;
                    }
                }
                default -> {
                    // ignore unsupported target types here; validation handled elsewhere
                }
            }
        }

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

    private Function resolveFunctionForDeletion(
        Program program,
        FunctionManager functionManager,
        SymbolTable symbolTable,
        Optional<Long> symbolIdOpt,
        Optional<String> addressOpt,
        Optional<String> nameOpt,
        String toolOperation,
        Map<String, Object> args) throws GhidraMcpException {

        Function function = null;

        if (symbolIdOpt.isPresent()) {
            long symbolId = symbolIdOpt.get();
            Symbol symbol = symbolTable.getSymbol(symbolId);
            if (symbol != null && symbol.getSymbolType() == SymbolType.FUNCTION) {
                function = functionManager.getFunctionAt(symbol.getAddress());
            }
            if (function == null) {
                Map<String, Object> criteria = Map.of(ARG_FUNCTION_SYMBOL_ID, symbolId);
                GhidraMcpError error = GhidraMcpError.resourceNotFound()
                    .errorCode(GhidraMcpError.ErrorCode.FUNCTION_NOT_FOUND)
                    .message("No function found for symbol ID " + symbolId)
                    .context(new GhidraMcpError.ErrorContext(
                        toolOperation,
                        "function lookup by symbol",
                        args,
                        criteria,
                        Map.of("symbolId", symbolId)))
                    .build();
                throw new GhidraMcpException(error);
            }
        }

        if (function == null && addressOpt.isPresent()) {
            String addressString = addressOpt.get();
            try {
                Address address = parseAddressOrThrow(program, addressString, toolOperation, args).block();
                function = functionManager.getFunctionAt(address);
                if (function == null && nameOpt.isEmpty() && symbolIdOpt.isEmpty()) {
                    throw new GhidraMcpException(GhidraMcpError.resourceNotFound()
                        .errorCode(GhidraMcpError.ErrorCode.FUNCTION_NOT_FOUND)
                        .message("No function exists at address " + addressString)
                        .context(new GhidraMcpError.ErrorContext(
                            toolOperation,
                            "function lookup by address",
                            args,
                            Map.of(ARG_ADDRESS, addressString),
                            Map.of("functionFound", false)))
                        .build());
                }
            } catch (GhidraMcpException e) {
                if (nameOpt.isEmpty() && symbolIdOpt.isEmpty()) {
                    throw e;
                }
            }
        }

        if (function == null && nameOpt.isPresent()) {
            String name = nameOpt.get();
            function = StreamSupport.stream(functionManager.getFunctions(true).spliterator(), false)
                .filter(f -> f.getName(true).equals(name))
                .findFirst()
                .orElse(null);
        }

        if (function == null) {
            List<String> suggestions = getFunctionNameSamples(functionManager, 10);
            Map<String, Object> criteria = new HashMap<>();
            symbolIdOpt.ifPresent(id -> criteria.put(ARG_FUNCTION_SYMBOL_ID, id));
            addressOpt.ifPresent(addr -> criteria.put(ARG_ADDRESS, addr));
            nameOpt.ifPresent(name -> criteria.put(ARG_FUNCTION_NAME, name));

            GhidraMcpError error = GhidraMcpError.resourceNotFound()
                .errorCode(GhidraMcpError.ErrorCode.FUNCTION_NOT_FOUND)
                .message("Function not found using provided identifiers")
                .context(new GhidraMcpError.ErrorContext(
                    toolOperation,
                    "function lookup",
                    args,
                    criteria,
                    Map.of("searchAttempted", true, "functionFound", false)))
                .relatedResources(suggestions)
                .suggestions(List.of(
                    new GhidraMcpError.ErrorSuggestion(
                        GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
                        "List available functions",
                        "Use search or list actions to review existing functions",
                        null,
                        null)))
                .build();
            throw new GhidraMcpException(error);
        }

        return function;
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
}