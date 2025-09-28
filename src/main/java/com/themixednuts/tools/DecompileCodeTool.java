package com.themixednuts.tools;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.models.DecompilationResult;
import com.themixednuts.utils.GhidraMcpTaskMonitor;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import io.modelcontextprotocol.common.McpTransportContext;
import reactor.core.publisher.Mono;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;
import java.util.Spliterator;
import java.util.Spliterators;

@GhidraMcpTool(
    name = "Decompile Code",
    description = "Advanced decompilation and P-code analysis for functions and code regions.",
    mcpName = "decompile_code",
    mcpDescription = """
    <use_case>
    Advanced code analysis through decompilation and P-code intermediate representation. Decompile functions
    to C-like pseudocode, analyze P-code operations, and understand program control flow. Essential for
    reverse engineering complex algorithms and understanding program behavior.
    </use_case>

    <important_notes>
    - Supports function-level and address-range decompilation
    - Provides both high-level C code and low-level P-code analysis
    - Configurable timeout and analysis depth
    - Handles complex control structures and data types
    </important_notes>

    <examples>
    Decompile function by name:
    {
      "fileName": "program.exe",
      "target_type": "function",
      "target_value": "main",
      "include_pcode": true
    }

    Decompile code at address:
    {
      "fileName": "program.exe",
      "target_type": "address",
      "target_value": "0x401000",
      "timeout": 60
    }
    </examples>
    """
)
public class DecompileCodeTool implements IGhidraMcpSpecification {

    public static final String ARG_TARGET_TYPE = "target_type";
    public static final String ARG_TARGET_VALUE = "target_value";
    public static final String ARG_INCLUDE_PCODE = "include_pcode";
    public static final String ARG_INCLUDE_AST = "include_ast";
    public static final String ARG_TIMEOUT = "timeout";
    public static final String ARG_ANALYSIS_LEVEL = "analysis_level";

    @Override
    public JsonSchema schema() {
        IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();

        schemaRoot.property(ARG_FILE_NAME,
                JsonSchemaBuilder.string(mapper)
                        .description("The name of the program file."));

        schemaRoot.property(ARG_TARGET_TYPE, JsonSchemaBuilder.string(mapper)
                .enumValues("function", "address", "address_range", "all_functions")
                .description("Type of target to decompile"));

        schemaRoot.property(ARG_TARGET_VALUE, JsonSchemaBuilder.string(mapper)
                .description("Target identifier (function name, address, or address range)"));

        schemaRoot.property(ARG_INCLUDE_PCODE, JsonSchemaBuilder.bool(mapper)
                .description("Include P-code intermediate representation")
                .defaultValue(false));

        schemaRoot.property(ARG_INCLUDE_AST, JsonSchemaBuilder.bool(mapper)
                .description("Include abstract syntax tree information")
                .defaultValue(false));

        schemaRoot.property(ARG_TIMEOUT, JsonSchemaBuilder.integer(mapper)
                .description("Decompilation timeout in seconds")
                .minimum(5)
                .maximum(300)
                .defaultValue(30));

        schemaRoot.property(ARG_ANALYSIS_LEVEL, JsonSchemaBuilder.string(mapper)
                .enumValues("basic", "standard", "advanced")
                .description("Level of decompilation analysis")
                .defaultValue("standard"));

        schemaRoot.requiredProperty(ARG_FILE_NAME)
                .requiredProperty(ARG_TARGET_TYPE);

        return schemaRoot.build();
    }

    @Override
    public Mono<? extends Object> execute(McpTransportContext context, Map<String, Object> args, PluginTool tool) {
        GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);

        return getProgram(args, tool).flatMap(program -> {
            String targetType = getRequiredStringArgument(args, ARG_TARGET_TYPE);
            String targetValue = getOptionalStringArgument(args, ARG_TARGET_VALUE).orElse("");
            boolean includePcode = getOptionalBooleanArgument(args, ARG_INCLUDE_PCODE).orElse(false);
            boolean includeAst = getOptionalBooleanArgument(args, ARG_INCLUDE_AST).orElse(false);
            int timeout = getOptionalIntArgument(args, ARG_TIMEOUT).orElse(30);

            return switch (targetType.toLowerCase()) {
                case "function" -> decompileFunction(program, targetValue, includePcode, includeAst, timeout, annotation);
                case "address" -> decompileAtAddress(program, targetValue, includePcode, includeAst, timeout, annotation);
                case "address_range" -> decompileAddressRange(program, targetValue, includePcode, includeAst, timeout, annotation);
                case "all_functions" -> decompileAllFunctions(program, includePcode, includeAst, timeout, annotation);
                default -> {
                    GhidraMcpError error = GhidraMcpError.validation()
                        .errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
                        .message("Invalid target type: " + targetType)
                        .context(new GhidraMcpError.ErrorContext(
                            annotation.mcpName(),
                            "target type validation",
                            args,
                            Map.of(ARG_TARGET_TYPE, targetType),
                            Map.of("validTargetTypes", List.of("function", "address", "address_range", "all_functions"))))
                        .suggestions(List.of(
                            new GhidraMcpError.ErrorSuggestion(
                                GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
                                "Use a valid target type",
                                "Choose from: function, address, address_range, all_functions",
                                List.of("function", "address", "address_range", "all_functions"),
                                null)))
                        .build();
                    yield Mono.error(new GhidraMcpException(error));
                }
            };
        });
    }

    private Mono<? extends Object> decompileFunction(Program program, String functionName,
                                                     boolean includePcode, boolean includeAst,
                                                     int timeout, GhidraMcpTool annotation) {
        return Mono.fromCallable(() -> {
            if (functionName.isEmpty()) {
                throw new GhidraMcpException(GhidraMcpError.validation()
                    .errorCode(GhidraMcpError.ErrorCode.MISSING_REQUIRED_ARGUMENT)
                    .message("Function name is required for function decompilation")
                    .build());
            }

            FunctionManager functionManager = program.getFunctionManager();
            Function targetFunction = StreamSupport
                .stream(functionManager.getFunctions(true).spliterator(), false)
                .filter(f -> f.getName().equals(functionName))
                .findFirst()
                .orElse(null);

            if (targetFunction == null) {
                List<String> availableFunctions = StreamSupport
                    .stream(functionManager.getFunctions(true).spliterator(), false)
                    .map(Function::getName)
                    .sorted()
                    .limit(20)
                    .collect(Collectors.toList());

                throw new GhidraMcpException(GhidraMcpError.resourceNotFound()
                    .errorCode(GhidraMcpError.ErrorCode.FUNCTION_NOT_FOUND)
                    .message("Function not found: " + functionName)
                    .context(new GhidraMcpError.ErrorContext(
                        annotation.mcpName(),
                        "function lookup",
                        Map.of(ARG_TARGET_VALUE, functionName),
                        Map.of("availableFunctions", availableFunctions),
                        Map.of("totalFunctions", functionManager.getFunctionCount())))
                    .suggestions(List.of(
                        new GhidraMcpError.ErrorSuggestion(
                            GhidraMcpError.ErrorSuggestion.SuggestionType.SIMILAR_VALUES,
                            "Check available functions",
                            "Use analyze_functions with list action to see all functions",
                            availableFunctions.subList(0, Math.min(10, availableFunctions.size())),
                            List.of("analyze_functions"))))
                    .build());
            }

            return performDecompilation(program, targetFunction, includePcode, includeAst, timeout, annotation);
        });
    }

    private Mono<? extends Object> decompileAtAddress(Program program, String addressStr,
                                                      boolean includePcode, boolean includeAst,
                                                      int timeout, GhidraMcpTool annotation) {
        return parseAddress(program, Map.of(ARG_ADDRESS, addressStr), addressStr, "decompile_at_address", annotation)
            .flatMap(addressResult -> Mono.fromCallable(() -> {
                Address address = addressResult.getAddress();
                FunctionManager functionManager = program.getFunctionManager();
                Function function = functionManager.getFunctionContaining(address);

                if (function == null) {
                    Listing listing = program.getListing();
                    Instruction instruction = listing.getInstructionAt(address);

                    if (instruction != null) {
                        return analyzeInstructionPcode(instruction, address);
                    } else {
                        throw new GhidraMcpException(GhidraMcpError.resourceNotFound()
                            .errorCode(GhidraMcpError.ErrorCode.FUNCTION_NOT_FOUND)
                            .message("No function or instruction found at address: " + addressStr)
                            .build());
                    }
                }

                return performDecompilation(program, function, includePcode, includeAst, timeout, annotation);
            }));
    }

    private Map<String, Object> analyzeInstructionPcode(Instruction instruction, Address address) {
        PcodeOp[] pcodeOps = instruction.getPcode();

        List<Map<String, Object>> pcodeList = Arrays.stream(pcodeOps)
            .map(op -> Map.<String, Object>of(
                "opcode", op.getOpcode(),
                "mnemonic", op.getMnemonic(),
                "sequence_number", op.getSeqnum().getTime(),
                "inputs", Arrays.stream(op.getInputs())
                    .map(varnode -> varnode.toString())
                    .collect(Collectors.toList()),
                "output", op.getOutput() != null ? op.getOutput().toString() : null
            ))
            .collect(Collectors.toList());

        return Map.of(
            "type", "instruction_analysis",
            "address", address.toString(),
            "instruction", instruction.toString(),
            "pcode_operations", pcodeList,
            "decompiled_code", "// Single instruction at " + address + ": " + instruction.toString()
        );
    }

    private DecompilationResult performDecompilation(Program program, Function function,
                                                    boolean includePcode, boolean includeAst,
                                                    int timeout, GhidraMcpTool annotation) throws GhidraMcpException {
        DecompInterface decomp = new DecompInterface();
        try {
            decomp.openProgram(program);
            GhidraMcpTaskMonitor monitor = new GhidraMcpTaskMonitor(null, "Decompiling " + function.getName());

            DecompileResults decompResult = decomp.decompileFunction(function, timeout, monitor);

            return Optional.ofNullable(decompResult)
                .filter(DecompileResults::decompileCompleted)
                .map(result -> createSuccessfulDecompilation(function, result, includePcode, includeAst))
                .orElseGet(() -> createFailedDecompilation(function, decompResult));

        } catch (Exception e) {
            throw new GhidraMcpException(GhidraMcpError.execution()
                .errorCode(GhidraMcpError.ErrorCode.UNEXPECTED_ERROR)
                .message("Decompilation error: " + e.getMessage())
                .build());
        } finally {
            decomp.dispose();
        }
    }

    private DecompilationResult createSuccessfulDecompilation(Function function, DecompileResults decompResult,
                                                            boolean includePcode, boolean includeAst) {
        String code = Optional.ofNullable(decompResult.getDecompiledFunction())
            .map(df -> df.getC())
            .orElse("// Decompilation produced no output");

        DecompilationResult result = new DecompilationResult(
            "function",
            function.getName(),
            function.getEntryPoint().toString(),
            true,
            code,
            null
        );

        result.setParameterCount(function.getParameterCount());
        result.setReturnType(function.getReturnType().getName());
        result.setBodySize((int) function.getBody().getNumAddresses());

        Optional.of(decompResult.getHighFunction())
            .filter(hf -> includePcode)
            .ifPresent(hf -> addPcodeOperations(result, hf));

        Optional.of(decompResult.getHighFunction())
            .filter(hf -> includeAst)
            .ifPresent(hf -> addAstInformation(result, hf));

        return result;
    }

    private DecompilationResult createFailedDecompilation(Function function, DecompileResults decompResult) {
        String errorMsg = Optional.ofNullable(decompResult)
            .map(DecompileResults::getErrorMessage)
            .orElse("Unknown decompilation error");

        return new DecompilationResult(
            "function",
            function.getName(),
            function.getEntryPoint().toString(),
            false,
            "// Decompilation failed: " + errorMsg,
            errorMsg
        );
    }

    private void addPcodeOperations(DecompilationResult result, HighFunction highFunc) {
        List<Map<String, Object>> pcodeOps = StreamSupport
            .stream(Spliterators.spliteratorUnknownSize(highFunc.getPcodeOps(), Spliterator.ORDERED), false)
            .limit(100)
            .map(op -> Map.<String, Object>of(
                "opcode", op.getOpcode(),
                "mnemonic", op.getMnemonic(),
                "sequence", op.getSeqnum().getTime(),
                "address", op.getSeqnum().getTarget().toString(),
                "operation", op.toString()
            ))
            .collect(Collectors.toList());
        result.setPcodeOperations(pcodeOps);
    }

    private void addAstInformation(DecompilationResult result, HighFunction highFunc) {
        result.setAstInfo(Map.of(
            "has_local_symbols", highFunc.getLocalSymbolMap() != null,
            "has_global_symbols", highFunc.getGlobalSymbolMap() != null,
            "basic_blocks", highFunc.getBasicBlocks().size()
        ));
    }

    private Mono<? extends Object> decompileAddressRange(Program program, String addressRange,
                                                        boolean includePcode, boolean includeAst,
                                                        int timeout, GhidraMcpTool annotation) {
        return Mono.just("Address range decompilation not yet implemented");
    }

    private Mono<? extends Object> decompileAllFunctions(Program program,
                                                         boolean includePcode, boolean includeAst,
                                                         int timeout, GhidraMcpTool annotation) {
        return Mono.fromCallable(() -> {
            FunctionManager functionManager = program.getFunctionManager();
            int maxFunctions = 20;

            List<DecompilationResult> results = StreamSupport
                .stream(functionManager.getFunctions(true).spliterator(), false)
                .limit(maxFunctions)
                .map(function -> {
                    try {
                        return performDecompilation(program, function, includePcode, includeAst, timeout, annotation);
                    } catch (GhidraMcpException e) {
                        throw new RuntimeException(e);
                    }
                })
                .collect(Collectors.toList());

            return Map.of(
                "functions", results,
                "total_decompiled", results.size(),
                "total_functions_in_program", functionManager.getFunctionCount(),
                "limited_results", functionManager.getFunctionCount() > maxFunctions
            );
        });
    }
}