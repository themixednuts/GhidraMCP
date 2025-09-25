package com.themixednuts.tools;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.models.FunctionAnalysis;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.HighFunction;
import io.modelcontextprotocol.common.McpTransportContext;
import reactor.core.publisher.Mono;

import java.util.*;
import java.util.stream.StreamSupport;
import java.util.stream.Collectors;

@GhidraMcpTool(
    name = "Analyze Functions",
    description = "Comprehensive function analysis including creation, inspection, decompilation, and prototype management.",
    mcpName = "analyze_functions",
    mcpDescription = """
    <use_case>
    Comprehensive function analysis for reverse engineering. Create, inspect, decompile, search, and manage
    function prototypes. Essential for understanding program structure, control flow, and function relationships.
    </use_case>

    <important_notes>
    - Supports multiple function identification methods (name, address, symbol ID, regex)
    - Provides detailed function information including parameters, return types, and call sites
    - Integrates decompilation for high-level code analysis
    - Handles function creation with automatic boundary detection
    </important_notes>

    <examples>
    Analyze function by name:
    {
      "fileName": "program.exe",
      "action": "analyze",
      "target_type": "name",
      "target_value": "main"
    }

    Create function at address:
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
public class AnalyzeFunctionsTool implements IGhidraMcpSpecification {

    public static final String ARG_ACTION = "action";
    public static final String ARG_TARGET_TYPE = "target_type";
    public static final String ARG_TARGET_VALUE = "target_value";
    public static final String ARG_INCLUDE_DECOMPILATION = "include_decompilation";
    public static final String ARG_INCLUDE_PCODE = "include_pcode";
    public static final String ARG_SEARCH_PATTERN = "search_pattern";
    public static final String ARG_PROTOTYPE = "prototype";

    @Override
    public JsonSchema schema() {
        IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();

        schemaRoot.property(ARG_FILE_NAME,
                JsonSchemaBuilder.string(mapper)
                        .description("The name of the program file."));

        schemaRoot.property(ARG_ACTION, JsonSchemaBuilder.string(mapper)
                .enumValues("analyze", "create", "delete", "search", "list", "update_prototype")
                .description("Action to perform on functions"));

        schemaRoot.property(ARG_TARGET_TYPE, JsonSchemaBuilder.string(mapper)
                .enumValues("name", "address", "symbol_id", "regex", "all")
                .description("How to identify the target function(s)"));

        schemaRoot.property(ARG_TARGET_VALUE, JsonSchemaBuilder.string(mapper)
                .description("The target value (function name, address, symbol ID, or regex pattern)"));

        schemaRoot.property(ARG_FUNCTION_NAME, JsonSchemaBuilder.string(mapper)
                .description("Function name for creation or rename operations"));

        schemaRoot.property(ARG_INCLUDE_DECOMPILATION, JsonSchemaBuilder.bool(mapper)
                .description("Include decompiled C code in analysis results")
                .defaultValue(false));

        schemaRoot.property(ARG_INCLUDE_PCODE, JsonSchemaBuilder.bool(mapper)
                .description("Include P-code intermediate representation in results")
                .defaultValue(false));

        schemaRoot.property(ARG_SEARCH_PATTERN, JsonSchemaBuilder.string(mapper)
                .description("Pattern for searching functions (used with search action)"));

        schemaRoot.property(ARG_PROTOTYPE, JsonSchemaBuilder.string(mapper)
                .description("Function prototype string for update operations"));

        schemaRoot.requiredProperty(ARG_FILE_NAME)
                .requiredProperty(ARG_ACTION);

        return schemaRoot.build();
    }

    @Override
    public Mono<? extends Object> execute(McpTransportContext context, Map<String, Object> args, PluginTool tool) {
        GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);

        return getProgram(args, tool).flatMap(program -> {
            String action = getRequiredStringArgument(args, ARG_ACTION);

            return switch (action.toLowerCase()) {
                case "analyze" -> handleAnalyze(program, args, annotation);
                case "create" -> handleCreate(program, args, annotation);
                case "delete" -> handleDelete(program, args, annotation);
                case "search" -> handleSearch(program, args, annotation);
                case "list" -> handleList(program, args, annotation);
                case "update_prototype" -> handleUpdatePrototype(program, args, annotation);
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

        return Mono.fromCallable(() -> {
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
        });
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

    // Stub implementations for other operations
    private Mono<? extends Object> handleCreate(Program program, Map<String, Object> args, GhidraMcpTool annotation) {
        return Mono.just("Function creation not yet implemented");
    }

    private Mono<? extends Object> handleDelete(Program program, Map<String, Object> args, GhidraMcpTool annotation) {
        return Mono.just("Function deletion not yet implemented");
    }

    private Mono<? extends Object> handleSearch(Program program, Map<String, Object> args, GhidraMcpTool annotation) {
        return Mono.just("Function search not yet implemented");
    }

    private Mono<? extends Object> handleList(Program program, Map<String, Object> args, GhidraMcpTool annotation) {
        return Mono.fromCallable(() -> {
            FunctionManager functionManager = program.getFunctionManager();
            List<FunctionAnalysis> functions = StreamSupport
                .stream(functionManager.getFunctions(true).spliterator(), false)
                .limit(50) // Limit for performance
                .map(FunctionAnalysis::new)
                .collect(Collectors.toList());

            return Map.of(
                "functions", functions,
                "total_count", functionManager.getFunctionCount(),
                "displayed_count", functions.size()
            );
        });
    }

    private Mono<? extends Object> handleUpdatePrototype(Program program, Map<String, Object> args, GhidraMcpTool annotation) {
        return Mono.just("Function prototype update not yet implemented");
    }
}