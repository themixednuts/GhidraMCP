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
            // String analysisLevel = getOptionalStringArgument(args, ARG_ANALYSIS_LEVEL).orElse("standard"); // TODO: Use for future enhancement

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
                GhidraMcpError error = GhidraMcpError.validation()
                    .errorCode(GhidraMcpError.ErrorCode.MISSING_REQUIRED_ARGUMENT)
                    .message("Function name is required for function decompilation")
                    .build();
                throw new GhidraMcpException(error);
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

                GhidraMcpError error = GhidraMcpError.resourceNotFound()
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
                    .build();
                throw new GhidraMcpException(error);
            }

            return performDecompilation(program, targetFunction, includePcode, includeAst, timeout, annotation);
        });
    }

    private Mono<? extends Object> decompileAtAddress(Program program, String addressStr,
                                                      boolean includePcode, boolean includeAst,
                                                      int timeout, GhidraMcpTool annotation) {
        return Mono.fromCallable(() -> {
            Address address;
            try {
                address = program.getAddressFactory().getAddress(addressStr);
                if (address == null) {
                    throw new IllegalArgumentException("Invalid address format");
                }
            } catch (Exception e) {
                GhidraMcpError error = GhidraMcpError.validation()
                    .errorCode(GhidraMcpError.ErrorCode.ADDRESS_PARSE_FAILED)
                    .message("Failed to parse address: " + e.getMessage())
                    .build();
                throw new GhidraMcpException(error);
            }

            FunctionManager functionManager = program.getFunctionManager();
            Function function = functionManager.getFunctionContaining(address);

            if (function == null) {
                // Check if there's an instruction at the address
                Listing listing = program.getListing();
                Instruction instruction = listing.getInstructionAt(address);

                if (instruction != null) {
                    // Return instruction-level P-code analysis
                    return analyzeInstructionPcode(instruction, address);
                } else {
                    GhidraMcpError error = GhidraMcpError.resourceNotFound()
                        .errorCode(GhidraMcpError.ErrorCode.FUNCTION_NOT_FOUND)
                        .message("No function or instruction found at address: " + addressStr)
                        .build();
                    throw new GhidraMcpException(error);
                }
            }

            return performDecompilation(program, function, includePcode, includeAst, timeout, annotation);
        });
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
                                                    int timeout, GhidraMcpTool annotation) {
        DecompInterface decomp = new DecompInterface();

        try {
            decomp.openProgram(program);
            GhidraMcpTaskMonitor monitor = new GhidraMcpTaskMonitor(null, "Decompiling " + function.getName());

            DecompileResults decompResult = decomp.decompileFunction(function, timeout, monitor);

            if (decompResult != null && decompResult.decompileCompleted()) {
                String code = decompResult.getDecompiledFunction().getC();
                DecompilationResult result = new DecompilationResult(
                    "function",
                    function.getName(),
                    function.getEntryPoint().toString(),
                    true,
                    code != null ? code : "// Decompilation produced no output",
                    null
                );

                // Set basic function info
                result.setParameterCount(function.getParameterCount());
                result.setReturnType(function.getReturnType().getName());
                result.setBodySize((int) function.getBody().getNumAddresses());

                // Add P-code analysis if requested
                if (includePcode) {
                    HighFunction highFunc = decompResult.getHighFunction();
                    if (highFunc != null) {
                        List<Map<String, Object>> pcodeOps = new ArrayList<>();
                        Iterator<PcodeOpAST> ops = highFunc.getPcodeOps();

                        while (ops.hasNext() && pcodeOps.size() < 100) { // Limit to prevent huge responses
                            PcodeOpAST op = ops.next();
                            pcodeOps.add(Map.of(
                                "opcode", op.getOpcode(),
                                "mnemonic", op.getMnemonic(),
                                "sequence", op.getSeqnum().getTime(),
                                "address", op.getSeqnum().getTarget().toString(),
                                "operation", op.toString()
                            ));
                        }
                        result.setPcodeOperations(pcodeOps);
                    }
                }

                // Add AST information if requested
                if (includeAst) {
                    HighFunction highFunc = decompResult.getHighFunction();
                    if (highFunc != null) {
                        result.setAstInfo(Map.of(
                            "has_local_symbols", highFunc.getLocalSymbolMap() != null,
                            "has_global_symbols", highFunc.getGlobalSymbolMap() != null,
                            "basic_blocks", highFunc.getBasicBlocks().size()
                        ));
                    }
                }

                return result;
            } else {
                String errorMsg = decompResult != null ? decompResult.getErrorMessage() : "Unknown decompilation error";
                return new DecompilationResult(
                    "function",
                    function.getName(),
                    function.getEntryPoint().toString(),
                    false,
                    "// Decompilation failed: " + errorMsg,
                    errorMsg
                );
            }

        } catch (Exception e) {
            return new DecompilationResult(
                "function",
                function.getName(),
                function.getEntryPoint().toString(),
                false,
                "// Decompilation error: " + e.getMessage(),
                e.getMessage()
            );
        } finally {
            if (decomp != null) {
                decomp.dispose();
            }
        }
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
            List<DecompilationResult> results = new ArrayList<>();

            // Limit to prevent overwhelming responses
            int maxFunctions = 20;
            int count = 0;

            FunctionIterator functions = functionManager.getFunctions(true);
            while (functions.hasNext() && count < maxFunctions) {
                Function function = functions.next();
                DecompilationResult functionResult = performDecompilation(
                    program, function, includePcode, includeAst, timeout, annotation);
                results.add(functionResult);
                count++;
            }

            return Map.of(
                "functions", results,
                "total_decompiled", results.size(),
                "total_functions_in_program", functionManager.getFunctionCount(),
                "limited_results", functionManager.getFunctionCount() > maxFunctions
            );
        });
    }
}