package com.themixednuts.tools;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.DecompilationResult;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.models.ListingInfo;
import com.themixednuts.models.ReferenceInfo;
import com.themixednuts.utils.GhidraMcpTaskMonitor;
import com.themixednuts.utils.OpaqueCursorCodec;
import com.themixednuts.utils.PaginatedResult;
import com.themixednuts.utils.SymbolLookupHelper;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.draft7.SchemaBuilder;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.common.McpTransportContext;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Spliterator;
import java.util.Spliterators;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;
import reactor.core.publisher.Mono;

@GhidraMcpTool(
    name = "Inspect",
    description =
        "Inspect code at a location: decompile to C, view assembly listing, find cross-references.",
    mcpName = "inspect",
    readOnlyHint = true,
    idempotentHint = true,
    mcpDescription =
        """
        <use_case>
        Show me what's at this location. Decompile functions to C-like pseudocode, view assembly
        listing (disassembly), and find cross-references to or from addresses. Essential for
        reverse engineering, understanding program structure, and navigating code flow.
        </use_case>

        <important_notes>
        - Four actions: decompile, listing, references_to, references_from
        - decompile: Decompile a function by name/address/symbol_id to C pseudocode with optional P-code and AST
        - listing: View assembly instructions by address, address range, or function name
        - references_to: Find all cross-references pointing TO a given address
        - references_from: Find all cross-references going FROM a given address
        - Listing requires an explicit target (address, function name, or symbol_id)
        - Results are paginated where applicable
        </important_notes>

        <examples>
        Decompile function by name:
        {
          "file_name": "program.exe",
          "action": "decompile",
          "name": "main",
          "include_pcode": true
        }

        Decompile function at address:
        {
          "file_name": "program.exe",
          "action": "decompile",
          "address": "0x401000"
        }

        View assembly listing at address range:
        {
          "file_name": "program.exe",
          "action": "listing",
          "address": "0x401000",
          "end_address": "0x401050"
        }

        View listing for a function:
        {
          "file_name": "program.exe",
          "action": "listing",
          "name": "main"
        }

        Find references to an address:
        {
          "file_name": "program.exe",
          "action": "references_to",
          "address": "0x401000"
        }

        Find references from an address:
        {
          "file_name": "program.exe",
          "action": "references_from",
          "address": "0x401060"
        }
        </examples>
        """)
public class InspectTool extends BaseMcpTool {

  public static final String ARG_INCLUDE_PCODE = "include_pcode";
  public static final String ARG_INCLUDE_AST = "include_ast";
  public static final String ARG_TIMEOUT = "timeout";
  public static final String ARG_ANALYSIS_LEVEL = "analysis_level";
  public static final String ARG_END_ADDRESS = "end_address";
  public static final String ARG_MAX_LINES = "max_lines";
  public static final String ARG_REFERENCE_TYPE = "reference_type";

  private static final String ACTION_DECOMPILE = "decompile";
  private static final String ACTION_LISTING = "listing";
  private static final String ACTION_REFERENCES_TO = "references_to";
  private static final String ACTION_REFERENCES_FROM = "references_from";

  private static final int DEFAULT_MAX_LINES = 100;

  @Override
  public JsonSchema schema() {
    var schemaRoot = createDraft7SchemaNode();

    schemaRoot.property(
        ARG_FILE_NAME, SchemaBuilder.string(mapper).description("The name of the program file."));

    schemaRoot.property(
        ARG_ACTION,
        SchemaBuilder.string(mapper)
            .enumValues(
                ACTION_DECOMPILE, ACTION_LISTING, ACTION_REFERENCES_TO, ACTION_REFERENCES_FROM)
            .description("Inspection action to perform"));

    schemaRoot.requiredProperty(ARG_FILE_NAME).requiredProperty(ARG_ACTION);

    schemaRoot.allOf(
        // action=decompile: requires identifier (symbol_id, address, or name)
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_ACTION, SchemaBuilder.string(mapper).constValue(ACTION_DECOMPILE)),
                SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_SYMBOL_ID,
                        SchemaBuilder.integer(mapper)
                            .description("Function symbol ID to decompile"))
                    .property(
                        ARG_ADDRESS,
                        SchemaBuilder.string(mapper)
                            .description("Address of function or code to decompile")
                            .pattern("^(0x)?[0-9a-fA-F]+$"))
                    .property(
                        ARG_NAME,
                        SchemaBuilder.string(mapper)
                            .description("Function name to decompile (supports * and ? wildcards)"))
                    .property(
                        ARG_INCLUDE_PCODE,
                        SchemaBuilder.bool(mapper)
                            .description("Include P-code intermediate representation")
                            .defaultValue(false))
                    .property(
                        ARG_INCLUDE_AST,
                        SchemaBuilder.bool(mapper)
                            .description("Include abstract syntax tree information")
                            .defaultValue(false))
                    .property(
                        ARG_TIMEOUT,
                        SchemaBuilder.integer(mapper)
                            .description("Decompilation timeout in seconds")
                            .minimum(5)
                            .maximum(300)
                            .defaultValue(30))
                    .property(
                        ARG_ANALYSIS_LEVEL,
                        SchemaBuilder.string(mapper)
                            .enumValues("basic", "standard", "advanced")
                            .description("Level of decompilation analysis")
                            .defaultValue("standard"))
                    .anyOf(
                        SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_SYMBOL_ID),
                        SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_ADDRESS),
                        SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_NAME))),

        // action=listing: requires explicit target (address, name, or symbol_id)
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(ARG_ACTION, SchemaBuilder.string(mapper).constValue(ACTION_LISTING)),
                SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_ADDRESS,
                        SchemaBuilder.string(mapper)
                            .description("Start address to view listing for")
                            .pattern("^(0x)?[0-9a-fA-F]+$"))
                    .property(
                        ARG_END_ADDRESS,
                        SchemaBuilder.string(mapper)
                            .description("Optional end address for address range viewing")
                            .pattern("^(0x)?[0-9a-fA-F]+$"))
                    .property(
                        ARG_NAME,
                        SchemaBuilder.string(mapper)
                            .description("Function name to view listing for"))
                    .property(
                        ARG_SYMBOL_ID,
                        SchemaBuilder.integer(mapper)
                            .description("Function symbol ID to view listing for"))
                    .property(
                        ARG_MAX_LINES,
                        SchemaBuilder.integer(mapper)
                            .description("Maximum number of lines to return (default: 100)")
                            .minimum(1)
                            .maximum(1000)
                            .defaultValue(DEFAULT_MAX_LINES))
                    .property(
                        ARG_CURSOR,
                        SchemaBuilder.string(mapper)
                            .description(
                                "Pagination cursor from previous request (format:"
                                    + " v1:<base64url_listing_address>)"))
                    .anyOf(
                        SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_ADDRESS),
                        SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_NAME),
                        SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_SYMBOL_ID))),

        // action=references_to: requires address
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_ACTION, SchemaBuilder.string(mapper).constValue(ACTION_REFERENCES_TO)),
                SchemaBuilder.objectDraft7(mapper)
                    .requiredProperty(ARG_ADDRESS)
                    .property(
                        ARG_ADDRESS,
                        SchemaBuilder.string(mapper)
                            .description("Target address to find references to")
                            .pattern("^(0x)?[0-9a-fA-F]+$"))
                    .property(
                        ARG_REFERENCE_TYPE,
                        SchemaBuilder.string(mapper)
                            .description("Filter by reference type (e.g., 'DATA', 'CALL', 'JUMP')"))
                    .property(
                        ARG_CURSOR,
                        SchemaBuilder.string(mapper)
                            .description("Pagination cursor from previous request"))
                    .property(
                        ARG_PAGE_SIZE,
                        SchemaBuilder.integer(mapper)
                            .description(
                                "Number of references per page (default: "
                                    + DEFAULT_PAGE_LIMIT
                                    + ", max: "
                                    + MAX_PAGE_LIMIT
                                    + ")")
                            .minimum(1)
                            .maximum(MAX_PAGE_LIMIT))),

        // action=references_from: requires address
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_ACTION,
                        SchemaBuilder.string(mapper).constValue(ACTION_REFERENCES_FROM)),
                SchemaBuilder.objectDraft7(mapper)
                    .requiredProperty(ARG_ADDRESS)
                    .property(
                        ARG_ADDRESS,
                        SchemaBuilder.string(mapper)
                            .description("Source address to find references from")
                            .pattern("^(0x)?[0-9a-fA-F]+$"))
                    .property(
                        ARG_REFERENCE_TYPE,
                        SchemaBuilder.string(mapper)
                            .description("Filter by reference type (e.g., 'DATA', 'CALL', 'JUMP')"))
                    .property(
                        ARG_CURSOR,
                        SchemaBuilder.string(mapper)
                            .description("Pagination cursor from previous request"))
                    .property(
                        ARG_PAGE_SIZE,
                        SchemaBuilder.integer(mapper)
                            .description(
                                "Number of references per page (default: "
                                    + DEFAULT_PAGE_LIMIT
                                    + ", max: "
                                    + MAX_PAGE_LIMIT
                                    + ")")
                            .minimum(1)
                            .maximum(MAX_PAGE_LIMIT))));

    return schemaRoot.build();
  }

  @Override
  public Mono<? extends Object> execute(
      McpTransportContext context, Map<String, Object> args, PluginTool tool) {
    GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);

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
                case ACTION_DECOMPILE -> executeDecompile(program, args, annotation);
                case ACTION_LISTING -> executeListing(program, args, annotation);
                case ACTION_REFERENCES_TO -> executeReferences(program, args, annotation, true);
                case ACTION_REFERENCES_FROM -> executeReferences(program, args, annotation, false);
                default -> {
                  GhidraMcpError error =
                      GhidraMcpError.invalid(
                          ARG_ACTION,
                          action,
                          "Must be one of: decompile, listing, references_to, references_from");
                  yield Mono.error(new GhidraMcpException(error));
                }
              };
            });
  }

  // =================== Decompile Action ===================

  private Mono<? extends Object> executeDecompile(
      Program program, Map<String, Object> args, GhidraMcpTool annotation) {
    boolean includePcode = getOptionalBooleanArgument(args, ARG_INCLUDE_PCODE).orElse(false);
    boolean includeAst = getOptionalBooleanArgument(args, ARG_INCLUDE_AST).orElse(false);
    int timeout = getOptionalIntArgument(args, ARG_TIMEOUT).orElse(30);

    // Determine if we have an address-only target (no function name/symbol)
    Optional<Long> symbolId = getOptionalLongArgument(args, ARG_SYMBOL_ID);
    Optional<String> addressOpt =
        getOptionalStringArgument(args, ARG_ADDRESS).map(String::trim).filter(v -> !v.isEmpty());
    Optional<String> nameOpt =
        getOptionalStringArgument(args, ARG_NAME).map(String::trim).filter(v -> !v.isEmpty());

    // If only address is given (no name, no symbol_id), try address-mode decompile
    if (symbolId.isEmpty() && nameOpt.isEmpty() && addressOpt.isPresent()) {
      return decompileAtAddress(
          program, addressOpt.get(), includePcode, includeAst, timeout, annotation);
    }

    // Otherwise resolve as function
    return Mono.fromCallable(
        () -> {
          Function targetFunction = resolveFunctionForDecompilation(program, args);
          return performDecompilation(
              program, targetFunction, includePcode, includeAst, timeout, annotation);
        });
  }

  private Function resolveFunctionForDecompilation(Program program, Map<String, Object> args)
      throws GhidraMcpException {
    FunctionManager functionManager = program.getFunctionManager();
    SymbolTable symbolTable = program.getSymbolTable();

    Long symbolId = getOptionalLongArgument(args, ARG_SYMBOL_ID).orElse(null);
    String addressArg =
        getOptionalStringArgument(args, ARG_ADDRESS)
            .map(String::trim)
            .filter(v -> !v.isEmpty())
            .orElse(null);
    String nameArg =
        getOptionalStringArgument(args, ARG_NAME)
            .map(String::trim)
            .filter(v -> !v.isEmpty())
            .orElse(null);

    if (symbolId != null) {
      Symbol symbol = symbolTable.getSymbol(symbolId);
      if (symbol != null && symbol.getSymbolType() == SymbolType.FUNCTION) {
        Function function = functionManager.getFunctionAt(symbol.getAddress());
        if (function != null) {
          return function;
        }
      }
      throw new GhidraMcpException(GhidraMcpError.notFound("function", "symbol_id=" + symbolId));
    }

    if (addressArg != null) {
      Address functionAddress = program.getAddressFactory().getAddress(addressArg);
      if (functionAddress == null) {
        throw new GhidraMcpException(GhidraMcpError.parse("address", addressArg));
      }
      Function function = functionManager.getFunctionContaining(functionAddress);
      if (function != null) {
        return function;
      }
      throw new GhidraMcpException(GhidraMcpError.notFound("function", "address=" + addressArg));
    }

    if (nameArg != null && !nameArg.isBlank()) {
      return SymbolLookupHelper.resolveFunction(program, nameArg);
    }

    throw new GhidraMcpException(
        GhidraMcpError.of(
            "Decompile target is missing", "Provide one of: symbol_id, address, or name"));
  }

  private Mono<? extends Object> decompileAtAddress(
      Program program,
      String addressStr,
      boolean includePcode,
      boolean includeAst,
      int timeout,
      GhidraMcpTool annotation) {
    return parseAddress(program, addressStr, "inspect.decompile")
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

  // =================== Listing Action ===================

  private Mono<? extends Object> executeListing(
      Program program, Map<String, Object> args, GhidraMcpTool annotation) {
    // Determine which viewing mode: address-based or function-based
    if (args.containsKey(ARG_ADDRESS)) {
      if (args.containsKey(ARG_END_ADDRESS)) {
        return handleAddressRange(program, args, annotation);
      } else {
        return handleSingleAddress(program, args, annotation);
      }
    } else if (args.containsKey(ARG_NAME) || args.containsKey(ARG_SYMBOL_ID)) {
      return handleFunction(program, args, annotation);
    } else {
      // No silent default — require explicit target
      return Mono.error(
          new GhidraMcpException(
              GhidraMcpError.of(
                  "Listing target is missing", "Provide one of: address, name, or symbol_id")));
    }
  }

  private Mono<? extends Object> handleSingleAddress(
      Program program, Map<String, Object> args, GhidraMcpTool annotation) {
    String addressStr;
    try {
      addressStr = getRequiredStringArgument(args, ARG_ADDRESS);
    } catch (GhidraMcpException e) {
      return Mono.error(e);
    }
    return parseAddress(program, addressStr, "inspect.listing_single")
        .flatMap(
            addressResult ->
                Mono.fromCallable(
                    () -> {
                      Address address = addressResult.getAddress();
                      Listing listing = program.getListing();
                      CodeUnit codeUnit = listing.getCodeUnitAt(address);

                      if (codeUnit == null) {
                        throw new GhidraMcpException(
                            GhidraMcpError.resourceNotFound()
                                .errorCode(GhidraMcpError.ErrorCode.ADDRESS_NOT_FOUND)
                                .message("No code found at address: " + address)
                                .context(
                                    new GhidraMcpError.ErrorContext(
                                        annotation.mcpName(),
                                        "listing lookup",
                                        args,
                                        Map.of(ARG_ADDRESS, address.toString()),
                                        Map.of()))
                                .suggestions(
                                    List.of(
                                        new GhidraMcpError.ErrorSuggestion(
                                            GhidraMcpError.ErrorSuggestion.SuggestionType
                                                .CHECK_RESOURCES,
                                            "Try a different address",
                                            "Use memory (action: list_blocks) to find valid"
                                                + " addresses",
                                            null,
                                            List.of("memory"))))
                                .build());
                      }

                      return createListingInfo(program, codeUnit);
                    }));
  }

  private Mono<? extends Object> handleFunction(
      Program program, Map<String, Object> args, GhidraMcpTool annotation) {
    return Mono.fromCallable(
        () -> {
          FunctionManager functionManager = program.getFunctionManager();
          SymbolTable symbolTable = program.getSymbolTable();

          Optional<Long> symbolIdOpt = getOptionalLongArgument(args, ARG_SYMBOL_ID);
          String functionSelector =
              getOptionalStringArgument(args, ARG_NAME).map(String::trim).orElse("");

          Function function = null;

          if (symbolIdOpt.isPresent()) {
            Symbol symbol = symbolTable.getSymbol(symbolIdOpt.get());
            if (symbol != null && symbol.getSymbolType() == SymbolType.FUNCTION) {
              function = functionManager.getFunctionAt(symbol.getAddress());
            }
            if (function == null && functionSelector.isBlank()) {
              throw new GhidraMcpException(
                  GhidraMcpError.notFound("function", "symbol_id=" + symbolIdOpt.get()));
            }
          }

          if (function == null && functionSelector.isBlank()) {
            throw new GhidraMcpException(
                GhidraMcpError.of(
                    "Function target is missing",
                    "Provide one of: name (name/address/pattern) or symbol_id"));
          }

          if (function == null) {
            Address asAddress = program.getAddressFactory().getAddress(functionSelector);
            if (asAddress != null) {
              function = functionManager.getFunctionContaining(asAddress);
            }
          }

          if (function == null) {
            function = SymbolLookupHelper.resolveFunction(program, functionSelector);
          }

          return listListingInRange(
              program,
              function.getEntryPoint(),
              function.getBody().getMaxAddress(),
              args,
              annotation);
        });
  }

  private Mono<? extends Object> handleAddressRange(
      Program program, Map<String, Object> args, GhidraMcpTool annotation) {
    String startStr;
    String endStr;
    try {
      startStr = getRequiredStringArgument(args, ARG_ADDRESS);
      endStr = getRequiredStringArgument(args, ARG_END_ADDRESS);
    } catch (GhidraMcpException e) {
      return Mono.error(e);
    }

    Mono<AddressResult> startMono = parseAddress(program, startStr, "inspect.listing_range_start");
    Mono<AddressResult> endMono = parseAddress(program, endStr, "inspect.listing_range_end");

    return startMono.flatMap(
        startResult ->
            endMono.flatMap(
                endResult -> {
                  Address startAddr = startResult.getAddress();
                  Address endAddr = endResult.getAddress();

                  if (startAddr.compareTo(endAddr) > 0) {
                    return Mono.error(
                        new GhidraMcpException(
                            GhidraMcpError.validation()
                                .errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
                                .message("Start address is after end address")
                                .context(
                                    new GhidraMcpError.ErrorContext(
                                        annotation.mcpName(),
                                        "range validation",
                                        args,
                                        Map.of(
                                            ARG_ADDRESS, startStr,
                                            ARG_END_ADDRESS, endStr),
                                        Map.of()))
                                .suggestions(
                                    List.of(
                                        new GhidraMcpError.ErrorSuggestion(
                                            GhidraMcpError.ErrorSuggestion.SuggestionType
                                                .FIX_REQUEST,
                                            "Swap addresses if needed",
                                            "Ensure address <= end_address",
                                            null,
                                            null)))
                                .build()));
                  }

                  return Mono.fromCallable(
                      () -> listListingInRange(program, startAddr, endAddr, args, annotation));
                }));
  }

  private PaginatedResult<ListingInfo> listListingInRange(
      Program program,
      Address startAddr,
      Address endAddr,
      Map<String, Object> args,
      GhidraMcpTool annotation)
      throws GhidraMcpException {
    Listing listing = program.getListing();
    Optional<String> cursorOpt = getOptionalStringArgument(args, ARG_CURSOR);
    int maxLines = getOptionalIntArgument(args, ARG_MAX_LINES).orElse(DEFAULT_MAX_LINES);

    // Determine effective start address based on cursor
    Address effectiveStart = startAddr;
    if (cursorOpt.isPresent()) {
      String cursorValue = cursorOpt.get();
      String decodedCursorAddress =
          decodeOpaqueCursorSingleV1(cursorValue, ARG_CURSOR, "v1:<base64url_listing_address>");
      Address cursorAddr = program.getAddressFactory().getAddress(decodedCursorAddress);
      if (cursorAddr == null) {
        throw new GhidraMcpException(
            GhidraMcpError.invalid(ARG_CURSOR, cursorValue, "cursor must be a valid address"));
      }

      if (cursorAddr.compareTo(startAddr) < 0 || cursorAddr.compareTo(endAddr) > 0) {
        throw new GhidraMcpException(
            GhidraMcpError.invalid(
                ARG_CURSOR, cursorValue, "cursor is outside the requested address range"));
      }

      // Start from just after the cursor address (cursor points to last item returned)
      try {
        effectiveStart = cursorAddr.add(1);
      } catch (Exception e) {
        throw new GhidraMcpException(
            GhidraMcpError.invalid(
                ARG_CURSOR, cursorValue, "cursor cannot be advanced within this address space"));
      }
    }

    List<ListingInfo> results = new ArrayList<>();

    // Get the first code unit at or after the effective start
    CodeUnit codeUnit = listing.getCodeUnitContaining(effectiveStart);
    if (codeUnit == null) {
      codeUnit = listing.getCodeUnitAfter(effectiveStart);
    } else if (codeUnit.getMinAddress().compareTo(effectiveStart) < 0) {
      // Code unit contains effectiveStart but starts before it - get the next one
      codeUnit = listing.getCodeUnitAfter(codeUnit.getMaxAddress());
    }

    // Collect items up to maxLines + 1 to determine if there are more
    while (codeUnit != null
        && codeUnit.getMinAddress().compareTo(endAddr) <= 0
        && results.size() <= maxLines) {
      try {
        results.add(createListingInfo(program, codeUnit));
        codeUnit = listing.getCodeUnitAfter(codeUnit.getMaxAddress());
      } catch (Exception e) {
        throw new GhidraMcpException(
            GhidraMcpError.execution()
                .errorCode(GhidraMcpError.ErrorCode.OPERATION_FAILED)
                .message(
                    "Failed to read listing entry at address "
                        + codeUnit.getMinAddress()
                        + ": "
                        + e.getMessage())
                .context(
                    new GhidraMcpError.ErrorContext(
                        this.getMcpName(),
                        "list_listing_in_range",
                        args,
                        Map.of("failed_address", codeUnit.getMinAddress().toString()),
                        null))
                .build());
      }
    }

    // Determine if there are more results
    boolean hasMore = results.size() > maxLines;
    if (hasMore) {
      results = results.subList(0, maxLines);
    }

    String nextCursor = null;
    if (hasMore && !results.isEmpty()) {
      nextCursor = OpaqueCursorCodec.encodeV1(results.get(results.size() - 1).getAddress());
    }

    return new PaginatedResult<>(results, nextCursor);
  }

  private ListingInfo createListingInfo(Program program, CodeUnit codeUnit) {
    String address = codeUnit.getMinAddress().toString();
    String label = null;
    String instruction = null;
    String mnemonic = null;
    String operands = null;
    String dataRepresentation = null;
    String type;
    Integer length = codeUnit.getLength();
    String functionName = null;
    String comment = null;
    try {
      comment = codeUnit.getComment(CodeUnit.EOL_COMMENT);
    } catch (Exception e) {
      // Comment API may have changed, ignore
    }

    // Get function context
    FunctionManager functionManager = program.getFunctionManager();
    Function containingFunction = functionManager.getFunctionContaining(codeUnit.getMinAddress());
    if (containingFunction != null) {
      functionName = containingFunction.getName();
    }

    // Get label if exists
    ghidra.program.model.symbol.Symbol primarySymbol =
        program.getSymbolTable().getPrimarySymbol(codeUnit.getMinAddress());
    if (primarySymbol != null) {
      label = primarySymbol.getName();
    }

    if (codeUnit instanceof Instruction) {
      Instruction instr = (Instruction) codeUnit;
      type = "instruction";
      mnemonic = instr.getMnemonicString();
      instruction = instr.toString();
      // Extract operands from the full instruction string
      String fullStr = instr.toString();
      if (fullStr.contains(" ")) {
        operands = fullStr.substring(fullStr.indexOf(" ") + 1);
      }
    } else if (codeUnit instanceof Data) {
      Data data = (Data) codeUnit;
      type = "data";
      dataRepresentation = data.getDefaultValueRepresentation();
      instruction = dataRepresentation;
    } else {
      type = "unknown";
    }

    return new ListingInfo(
        address,
        label,
        instruction,
        mnemonic,
        operands,
        dataRepresentation,
        type,
        length,
        functionName,
        comment);
  }

  // =================== References Actions ===================

  private Mono<? extends Object> executeReferences(
      Program program,
      Map<String, Object> args,
      GhidraMcpTool annotation,
      boolean referencesToMode) {
    String addressStr;
    try {
      addressStr = getRequiredStringArgument(args, ARG_ADDRESS);
    } catch (GhidraMcpException e) {
      return Mono.error(e);
    }
    String referenceType = getOptionalStringArgument(args, ARG_REFERENCE_TYPE).orElse("");
    Optional<String> cursorOpt = getOptionalStringArgument(args, ARG_CURSOR);
    int pageSize = getPageSizeArgument(args, DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT);

    return parseAddress(program, addressStr, "inspect.references")
        .flatMap(
            addressResult -> {
              if (referencesToMode) {
                return findReferencesTo(
                    program,
                    addressResult.getAddress(),
                    referenceType,
                    cursorOpt,
                    pageSize,
                    args,
                    annotation);
              } else {
                return findReferencesFrom(
                    program,
                    addressResult.getAddress(),
                    referenceType,
                    cursorOpt,
                    pageSize,
                    args,
                    annotation);
              }
            });
  }

  private Mono<PaginatedResult<ReferenceInfo>> findReferencesTo(
      Program program,
      Address address,
      String referenceType,
      Optional<String> cursorOpt,
      int pageSize,
      Map<String, Object> args,
      GhidraMcpTool annotation) {
    return Mono.fromCallable(
        () -> {
          ReferenceManager refManager = program.getReferenceManager();

          // Use native hasReferencesTo() for early exit
          if (!refManager.hasReferencesTo(address)) {
            return new PaginatedResult<>(List.of(), null);
          }

          try {
            ReferenceIterator refIterator = refManager.getReferencesTo(address);
            List<ReferenceInfo> allReferences = new ArrayList<>();
            while (refIterator.hasNext()) {
              Reference ref = refIterator.next();

              // Apply reference type filter
              if (referenceType.isEmpty()
                  || ref.getReferenceType().toString().equalsIgnoreCase(referenceType)) {
                allReferences.add(new ReferenceInfo(program, ref));
              }
            }

            allReferences.sort(
                Comparator.comparing(ReferenceInfo::getFromAddress, String.CASE_INSENSITIVE_ORDER)
                    .thenComparing(ReferenceInfo::getToAddress, String.CASE_INSENSITIVE_ORDER)
                    .thenComparing(ReferenceInfo::getReferenceType, String.CASE_INSENSITIVE_ORDER));

            int startIndex = resolveCursorStartIndex(cursorOpt, allReferences, true);
            int endExclusive = Math.min(allReferences.size(), startIndex + pageSize + 1);
            List<ReferenceInfo> paginatedReferences =
                new ArrayList<>(allReferences.subList(startIndex, endExclusive));

            boolean hasMore = paginatedReferences.size() > pageSize;
            List<ReferenceInfo> results =
                hasMore
                    ? new ArrayList<>(paginatedReferences.subList(0, pageSize))
                    : new ArrayList<>(paginatedReferences);

            String nextCursor = null;
            if (hasMore && !results.isEmpty()) {
              nextCursor = buildReferencesToCursor(results.get(results.size() - 1));
            }

            return new PaginatedResult<>(results, nextCursor);
          } catch (GhidraMcpException e) {
            throw e;
          } catch (Exception e) {
            throw buildXrefAnalysisException(
                annotation, args, "references_to", address.toString(), 0, e);
          }
        });
  }

  private Mono<PaginatedResult<ReferenceInfo>> findReferencesFrom(
      Program program,
      Address address,
      String referenceType,
      Optional<String> cursorOpt,
      int pageSize,
      Map<String, Object> args,
      GhidraMcpTool annotation) {
    return Mono.fromCallable(
        () -> {
          ReferenceManager refManager = program.getReferenceManager();

          // Use native hasReferencesFrom() for early exit
          if (!refManager.hasReferencesFrom(address)) {
            return new PaginatedResult<>(List.of(), null);
          }

          Reference[] referencesArray = refManager.getReferencesFrom(address);

          try {
            List<ReferenceInfo> allReferences = new ArrayList<>();
            if (referencesArray != null) {
              for (Reference ref : referencesArray) {
                // Apply reference type filter
                if (referenceType.isEmpty()
                    || ref.getReferenceType().toString().equalsIgnoreCase(referenceType)) {
                  allReferences.add(new ReferenceInfo(program, ref));
                }
              }
            }

            allReferences.sort(
                Comparator.comparing(ReferenceInfo::getToAddress, String.CASE_INSENSITIVE_ORDER)
                    .thenComparing(ReferenceInfo::getFromAddress, String.CASE_INSENSITIVE_ORDER)
                    .thenComparing(ReferenceInfo::getReferenceType, String.CASE_INSENSITIVE_ORDER));

            int startIndex = resolveCursorStartIndex(cursorOpt, allReferences, false);
            int endExclusive = Math.min(allReferences.size(), startIndex + pageSize + 1);
            List<ReferenceInfo> paginatedReferences =
                new ArrayList<>(allReferences.subList(startIndex, endExclusive));

            boolean hasMore = paginatedReferences.size() > pageSize;
            List<ReferenceInfo> results =
                hasMore
                    ? new ArrayList<>(paginatedReferences.subList(0, pageSize))
                    : new ArrayList<>(paginatedReferences);

            String nextCursor = null;
            if (hasMore && !results.isEmpty()) {
              nextCursor = buildReferencesFromCursor(results.get(results.size() - 1));
            }

            return new PaginatedResult<>(results, nextCursor);
          } catch (GhidraMcpException e) {
            throw e;
          } catch (Exception e) {
            throw buildXrefAnalysisException(
                annotation, args, "references_from", address.toString(), 0, e);
          }
        });
  }

  private GhidraMcpException buildXrefAnalysisException(
      GhidraMcpTool annotation,
      Map<String, Object> args,
      String operation,
      String normalizedAddress,
      int referencesCollected,
      Exception cause) {
    return new GhidraMcpException(
        GhidraMcpError.execution()
            .errorCode(GhidraMcpError.ErrorCode.UNEXPECTED_ERROR)
            .message("Failed during cross-reference analysis: " + cause.getMessage())
            .context(
                new GhidraMcpError.ErrorContext(
                    annotation.mcpName(),
                    operation,
                    args,
                    Map.of(ARG_ADDRESS, normalizedAddress),
                    Map.of("references_collected", referencesCollected)))
            .suggestions(
                List.of(
                    new GhidraMcpError.ErrorSuggestion(
                        GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
                        "Verify program state and memory accessibility",
                        "Check that the program is properly loaded and the address is valid",
                        null,
                        null)))
            .build());
  }

  private int resolveCursorStartIndex(
      Optional<String> cursorOpt, List<ReferenceInfo> references, boolean referencesToMode) {
    if (cursorOpt.isEmpty()) {
      return 0;
    }

    String cursor = cursorOpt.get();
    List<String> cursorParts =
        decodeOpaqueCursorV1(
            cursor,
            3,
            ARG_CURSOR,
            "v1:<base64url_primary_address>:<base64url_secondary_address>"
                + ":<base64url_reference_type>");

    String cursorFirst = cursorParts.get(0);
    String cursorSecond = cursorParts.get(1);
    String cursorType = cursorParts.get(2);

    for (int i = 0; i < references.size(); i++) {
      ReferenceInfo info = references.get(i);

      String first = referencesToMode ? info.getFromAddress() : info.getToAddress();
      String second = referencesToMode ? info.getToAddress() : info.getFromAddress();
      String type = info.getReferenceType();

      if (first.equalsIgnoreCase(cursorFirst)
          && second.equalsIgnoreCase(cursorSecond)
          && type.equalsIgnoreCase(cursorType)) {
        return i + 1;
      }
    }

    throw new GhidraMcpException(
        GhidraMcpError.invalid(
            ARG_CURSOR, cursor, "cursor is invalid or no longer present in this reference set"));
  }

  private String buildReferencesToCursor(ReferenceInfo info) {
    return OpaqueCursorCodec.encodeV1(
        info.getFromAddress(), info.getToAddress(), info.getReferenceType());
  }

  private String buildReferencesFromCursor(ReferenceInfo info) {
    return OpaqueCursorCodec.encodeV1(
        info.getToAddress(), info.getFromAddress(), info.getReferenceType());
  }
}
