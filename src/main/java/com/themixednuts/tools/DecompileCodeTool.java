package com.themixednuts.tools;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.DecompilationResult;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.utils.GhidraMcpTaskMonitor;
import com.themixednuts.utils.jsonschema.JsonSchema;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.common.McpTransportContext;
import java.util.*;
import java.util.Spliterator;
import java.util.Spliterators;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;
import reactor.core.publisher.Mono;

@GhidraMcpTool(
    name = "Decompile Code",
    description = "Advanced decompilation and P-code analysis for functions and code regions.",
    mcpName = "decompile_code",
    title = "Decompile Code",
    readOnlyHint = true,
    idempotentHint = true,
    mcpDescription =
        """
                <use_case>
                Advanced code analysis through decompilation and P-code intermediate representation. Decompile functions
                to C-like pseudocode, analyze P-code operations, and understand program control flow. Essential for
                reverse engineering complex algorithms and understanding program behavior.
                </use_case>

                <important_notes>
                - Supports function-level and single-address decompilation
                - Provides both high-level C code and low-level P-code analysis
                - Configurable timeout and analysis depth
                - Handles complex control structures and data types
                </important_notes>

        <examples>
                Decompile function by name:
                {
                  "file_name": "program.exe",
                  "target_type": "function",
                  "target_value": "main",
                  "include_pcode": true
                }

                Decompile code at address:
                {
                  "file_name": "program.exe",
                  "target_type": "address",
                  "target_value": "0x401000",
                  "timeout": 60
                }
                </examples>
        """)
public class DecompileCodeTool extends BaseMcpTool {

  public static final String ARG_TARGET_TYPE = "target_type";
  public static final String ARG_TARGET_VALUE = "target_value";
  public static final String ARG_INCLUDE_PCODE = "include_pcode";
  public static final String ARG_INCLUDE_AST = "include_ast";
  public static final String ARG_TIMEOUT = "timeout";
  public static final String ARG_ANALYSIS_LEVEL = "analysis_level";

  /**
   * Defines the JSON input schema for decompiling code.
   *
   * @return The JsonSchema defining the expected input arguments
   */
  @Override
  public JsonSchema schema() {
    // Use Draft 7 builder for conditional support
    var schemaRoot = createDraft7SchemaNode();

    schemaRoot.property(
        ARG_FILE_NAME, schemaRoot.string().description("The name of the program file."));

    schemaRoot.property(
        ARG_TARGET_TYPE,
        schemaRoot
            .string()
            .enumValues("function", "address", "all_functions")
            .description("Type of target to decompile"));

    schemaRoot.property(
        ARG_TARGET_VALUE,
        schemaRoot
            .string()
            .description("Target identifier (function name, address, or address range)"));

    schemaRoot.property(
        ARG_INCLUDE_PCODE,
        schemaRoot
            .bool()
            .description("Include P-code intermediate representation")
            .defaultValue(false));

    schemaRoot.property(
        ARG_INCLUDE_AST,
        schemaRoot
            .bool()
            .description("Include abstract syntax tree information")
            .defaultValue(false));

    schemaRoot.property(
        ARG_TIMEOUT,
        schemaRoot
            .integer()
            .description("Decompilation timeout in seconds")
            .minimum(5)
            .maximum(300)
            .defaultValue(30));

    schemaRoot.property(
        ARG_ANALYSIS_LEVEL,
        schemaRoot
            .string()
            .enumValues("basic", "standard", "advanced")
            .description("Level of decompilation analysis")
            .defaultValue("standard"));

    schemaRoot.requiredProperty(ARG_FILE_NAME).requiredProperty(ARG_TARGET_TYPE);

    // Add conditional requirements (JSON Schema Draft 7)
    // When target_type is "function" or "address", target_value is required
    schemaRoot.allOf(
        schemaRoot
            .object()
            .ifThen(
                schemaRoot
                    .object()
                    .property(ARG_TARGET_TYPE, schemaRoot.string().constValue("function")),
                schemaRoot.object().requiredProperty(ARG_TARGET_VALUE)),
        schemaRoot
            .object()
            .ifThen(
                schemaRoot
                    .object()
                    .property(ARG_TARGET_TYPE, schemaRoot.string().constValue("address")),
                schemaRoot.object().requiredProperty(ARG_TARGET_VALUE)));

    return schemaRoot.build();
  }

  /**
   * Executes the code decompilation operation.
   *
   * @param context The MCP transport context
   * @param args The tool arguments containing file_name, target_type, target_value, and optional
   *     parameters
   * @param tool The Ghidra PluginTool context
   * @return A Mono emitting a DecompileResult object
   */
  @Override
  public Mono<? extends Object> execute(
      McpTransportContext context, Map<String, Object> args, PluginTool tool) {
    GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);

    return getProgram(args, tool)
        .flatMap(
            program -> {
              String targetType;
              try {
                targetType = getRequiredStringArgument(args, ARG_TARGET_TYPE);
              } catch (GhidraMcpException e) {
                return Mono.error(e);
              }
              String targetValue = getOptionalStringArgument(args, ARG_TARGET_VALUE).orElse("");
              boolean includePcode =
                  getOptionalBooleanArgument(args, ARG_INCLUDE_PCODE).orElse(false);
              boolean includeAst = getOptionalBooleanArgument(args, ARG_INCLUDE_AST).orElse(false);
              int timeout = getOptionalIntArgument(args, ARG_TIMEOUT).orElse(30);

              return switch (targetType.toLowerCase()) {
                case "function" ->
                    decompileFunction(
                        program, targetValue, includePcode, includeAst, timeout, annotation);
                case "address" ->
                    decompileAtAddress(
                        program, targetValue, includePcode, includeAst, timeout, annotation);
                case "all_functions" ->
                    decompileAllFunctions(program, includePcode, includeAst, timeout, annotation);
                default -> {
                  GhidraMcpError error =
                      GhidraMcpError.invalid(
                          ARG_TARGET_TYPE,
                          targetType,
                          "Must be one of: function, address, all_functions");
                  yield Mono.error(new GhidraMcpException(error));
                }
              };
            });
  }

  private Mono<? extends Object> decompileFunction(
      Program program,
      String functionName,
      boolean includePcode,
      boolean includeAst,
      int timeout,
      GhidraMcpTool annotation) {
    return Mono.fromCallable(
        () -> {
          if (functionName.isEmpty()) {
            throw new GhidraMcpException(GhidraMcpError.missing(ARG_TARGET_VALUE));
          }

          FunctionManager functionManager = program.getFunctionManager();
          Function targetFunction =
              StreamSupport.stream(functionManager.getFunctions(true).spliterator(), false)
                  .filter(f -> f.getName().equals(functionName))
                  .findFirst()
                  .orElse(null);

          if (targetFunction == null) {
            throw new GhidraMcpException(
                GhidraMcpError.notFound(
                    "function", functionName, "Use read_functions to see available functions"));
          }

          return performDecompilation(
              program, targetFunction, includePcode, includeAst, timeout, annotation);
        });
  }

  private Mono<? extends Object> decompileAtAddress(
      Program program,
      String addressStr,
      boolean includePcode,
      boolean includeAst,
      int timeout,
      GhidraMcpTool annotation) {
    return parseAddress(program, addressStr, "decompile_at_address")
        .flatMap(
            addressResult ->
                Mono.fromCallable(
                    () -> {
                      Address address = addressResult.getAddress();
                      FunctionManager functionManager = program.getFunctionManager();
                      Function function = functionManager.getFunctionContaining(address);

                      if (function == null) {
                        Listing listing = program.getListing();
                        Instruction instruction = listing.getInstructionAt(address);

                        if (instruction != null) {
                          return analyzeInstructionPcode(instruction, address);
                        } else {
                          throw new GhidraMcpException(
                              GhidraMcpError.notFound("function or instruction", addressStr));
                        }
                      }

                      return performDecompilation(
                          program, function, includePcode, includeAst, timeout, annotation);
                    }));
  }

  private Map<String, Object> analyzeInstructionPcode(Instruction instruction, Address address) {
    PcodeOp[] pcodeOps = instruction.getPcode();

    List<Map<String, Object>> pcodeList =
        Arrays.stream(pcodeOps)
            .map(
                op -> {
                  Map<String, Object> pcodeEntry = new LinkedHashMap<>();
                  pcodeEntry.put("opcode", op.getOpcode());
                  pcodeEntry.put("mnemonic", op.getMnemonic());
                  pcodeEntry.put("sequence_number", op.getSeqnum().getTime());
                  pcodeEntry.put(
                      "inputs",
                      Arrays.stream(op.getInputs())
                          .map(varnode -> varnode.toString())
                          .collect(Collectors.toList()));
                  if (op.getOutput() != null) {
                    pcodeEntry.put("output", op.getOutput().toString());
                  }
                  return pcodeEntry;
                })
            .collect(Collectors.toList());

    return Map.of(
        "type",
        "instruction_analysis",
        "address",
        address.toString(),
        "instruction",
        instruction.toString(),
        "pcode_operations",
        pcodeList,
        "decompiled_code",
        "// Single instruction at " + address + ": " + instruction.toString());
  }

  private DecompilationResult performDecompilation(
      Program program,
      Function function,
      boolean includePcode,
      boolean includeAst,
      int timeout,
      GhidraMcpTool annotation)
      throws GhidraMcpException {
    DecompInterface decomp = new DecompInterface();
    try {
      decomp.openProgram(program);
      TaskMonitor monitor = new GhidraMcpTaskMonitor(null, "Decompiling " + function.getName());

      DecompileResults decompResult = decomp.decompileFunction(function, timeout, monitor);

      return Optional.ofNullable(decompResult)
          .filter(DecompileResults::decompileCompleted)
          .map(result -> createSuccessfulDecompilation(function, result, includePcode, includeAst))
          .orElseGet(() -> createFailedDecompilation(function, decompResult));

    } catch (Exception e) {
      throw new GhidraMcpException(GhidraMcpError.failed("decompilation", e.getMessage()));
    } finally {
      decomp.dispose();
    }
  }

  private DecompilationResult createSuccessfulDecompilation(
      Function function, DecompileResults decompResult, boolean includePcode, boolean includeAst) {
    String code =
        Optional.ofNullable(decompResult.getDecompiledFunction())
            .map(df -> df.getC())
            .orElse("// Decompilation produced no output");

    DecompilationResult result =
        new DecompilationResult(
            "function", function.getName(), function.getEntryPoint().toString(), true, code, null);

    result.setParameterCount(function.getParameterCount());
    result.setReturnType(function.getReturnType().getName());
    result.setBodySize((int) function.getBody().getNumAddresses());

    Optional.ofNullable(decompResult.getHighFunction())
        .filter(hf -> includePcode)
        .ifPresent(hf -> addPcodeOperations(result, hf));

    Optional.ofNullable(decompResult.getHighFunction())
        .filter(hf -> includeAst)
        .ifPresent(hf -> addAstInformation(result, hf));

    return result;
  }

  private DecompilationResult createFailedDecompilation(
      Function function, DecompileResults decompResult) {
    String errorMsg =
        Optional.ofNullable(decompResult)
            .map(DecompileResults::getErrorMessage)
            .orElse("Unknown decompilation error");

    return new DecompilationResult(
        "function",
        function.getName(),
        function.getEntryPoint().toString(),
        false,
        "// Decompilation failed: " + errorMsg,
        errorMsg);
  }

  private void addPcodeOperations(DecompilationResult result, HighFunction highFunc) {
    List<Map<String, Object>> pcodeOps =
        StreamSupport.stream(
                Spliterators.spliteratorUnknownSize(highFunc.getPcodeOps(), Spliterator.ORDERED),
                false)
            .limit(100)
            .map(
                op ->
                    Map.<String, Object>of(
                        "opcode", op.getOpcode(),
                        "mnemonic", op.getMnemonic(),
                        "sequence", op.getSeqnum().getTime(),
                        "address", op.getSeqnum().getTarget().toString(),
                        "operation", op.toString()))
            .collect(Collectors.toList());
    result.setPcodeOperations(pcodeOps);
  }

  private void addAstInformation(DecompilationResult result, HighFunction highFunc) {
    result.setAstInfo(
        Map.of(
            "has_local_symbols", highFunc.getLocalSymbolMap() != null,
            "has_global_symbols", highFunc.getGlobalSymbolMap() != null,
            "basic_blocks", highFunc.getBasicBlocks().size()));
  }

  private Mono<? extends Object> decompileAllFunctions(
      Program program,
      boolean includePcode,
      boolean includeAst,
      int timeout,
      GhidraMcpTool annotation) {
    return Mono.fromCallable(
        () -> {
          FunctionManager functionManager = program.getFunctionManager();
          int maxFunctions = 20;

          List<DecompilationResult> results = new ArrayList<>();
          Iterator<Function> iterator = functionManager.getFunctions(true).iterator();
          while (iterator.hasNext() && results.size() < maxFunctions) {
            Function function = iterator.next();
            try {
              results.add(
                  performDecompilation(
                      program, function, includePcode, includeAst, timeout, annotation));
            } catch (GhidraMcpException e) {
              results.add(
                  new DecompilationResult(
                      "function",
                      function.getName(),
                      function.getEntryPoint().toString(),
                      false,
                      "// Decompilation failed: " + e.getMessage(),
                      e.getMessage()));
            }
          }

          return Map.of(
              "functions",
              results,
              "total_decompiled",
              results.size(),
              "total_functions_in_program",
              functionManager.getFunctionCount(),
              "limited_results",
              functionManager.getFunctionCount() > maxFunctions);
        });
  }
}
