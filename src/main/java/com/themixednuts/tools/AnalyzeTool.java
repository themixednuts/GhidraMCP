package com.themixednuts.tools;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.models.RTTIAnalysisResult;
import com.themixednuts.utils.OpaqueCursorCodec;
import com.themixednuts.utils.PaginatedResult;
import com.themixednuts.utils.SymbolLookupHelper;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.draft7.SchemaBuilder;
import com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.IObjectSchemaBuilder;
import ghidra.app.cmd.data.TypeDescriptorModel;
import ghidra.app.cmd.data.rtti.Rtti1Model;
import ghidra.app.cmd.data.rtti.Rtti3Model;
import ghidra.app.cmd.data.rtti.Rtti4Model;
import ghidra.app.cmd.data.rtti.RttiUtil;
import ghidra.app.cmd.data.rtti.VfTableModel;
import ghidra.app.plugin.prototype.MicrosoftCodeAnalyzerPlugin.PEUtil;
import ghidra.app.util.bin.format.golang.rtti.GoItab;
import ghidra.app.util.bin.format.golang.rtti.GoModuledata;
import ghidra.app.util.bin.format.golang.rtti.GoRttiMapper;
import ghidra.app.util.bin.format.golang.rtti.types.GoType;
import ghidra.app.util.datatype.microsoft.DataValidationOptions;
import ghidra.app.util.datatype.microsoft.RTTI0DataType;
import ghidra.app.util.demangler.Demangled;
import ghidra.app.util.demangler.DemangledObject;
import ghidra.app.util.demangler.DemanglerUtil;
import ghidra.features.base.memsearch.bytesource.ProgramByteSource;
import ghidra.features.base.memsearch.format.SearchFormat;
import ghidra.features.base.memsearch.gui.SearchSettings;
import ghidra.features.base.memsearch.matcher.ByteMatcher;
import ghidra.features.base.memsearch.searcher.MemoryMatch;
import ghidra.features.base.memsearch.searcher.MemorySearcher;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.datastruct.ListAccumulator;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.common.McpTransportContext;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import java.util.regex.Pattern;
import mdemangler.MDMangGhidra;
import mdemangler.MDParsableItem;
import reactor.core.publisher.Mono;

@GhidraMcpTool(
    name = "Analyze",
    description =
        "Decode, visualize, and analyze structure — demangle symbols, analyze RTTI, list all RTTI"
            + " classes, visualize control flow graphs, extract call graphs.",
    mcpName = "analyze",
    readOnlyHint = true,
    idempotentHint = true,
    mcpDescription =
        """
        <use_case>
        Decode, visualize, and analyze structure. Demangle mangled C++ symbols, analyze RTTI
        metadata (Microsoft, Itanium, Go), list all RTTI classes with demangling/lambda
        method extraction/base class hierarchies, visualize control flow graphs of functions,
        and extract caller/callee call graphs. Use this tool when you need to understand symbol
        names, class hierarchies, function control flow, or call relationships.
        </use_case>

        <parameters_summary>
        - action: Operation to perform (demangle, rtti, list_rtti, graph, call_graph)
        - file_name: The program file to analyze (required)
        - mangled_symbol: (demangle) The mangled symbol to decode
        - address: (rtti, graph, call_graph) Address for analysis
        - backend: (rtti) Backend adapter: auto|microsoft|itanium|go
        - validate_referred_to_data: (rtti, microsoft-only) Validate referenced RTTI structures
        - ignore_instructions: (rtti, microsoft-only) Ignore existing instructions
        - ignore_defined_data: (rtti, microsoft-only) Ignore existing defined data
        - symbol_id: (graph, call_graph) Symbol ID to identify a function
        - name: (graph, call_graph) Function name for lookup
        - name_pattern: (list_rtti) Regex filter on class name
        - cursor: (list_rtti) Pagination cursor
        - page_size: (list_rtti) Results per page, default 100, max 500
        - depth: (call_graph) Traversal depth, default 3, max 10
        - direction: (call_graph) callers, callees, or both (default both)
        </parameters_summary>

        <return_value_summary>
        - demangle: DemangleResult with original/demangled symbol, type, namespace, class info
        - rtti: RTTIAnalysisResult with detected type, validity, class hierarchy
        - list_rtti: Paginated list of all MSVC RTTI classes (PE binaries only; Itanium ABI / _ZTI not supported) with demangled names, methods, base classes
        - graph: Control flow graph with nodes (basic blocks) and edges (flow connections)
        - call_graph: Call graph with function nodes and caller/callee edges
        </return_value_summary>

        <examples>
        Demangle a C++ symbol:
        { "file_name": "program.exe", "action": "demangle", "mangled_symbol": "_Z3fooi" }

        Analyze RTTI at an address:
        { "file_name": "program.exe", "action": "rtti", "address": "0x401000" }

        List all RTTI classes:
        { "file_name": "program.exe", "action": "list_rtti" }

        List RTTI classes matching a pattern:
        { "file_name": "program.exe", "action": "list_rtti", "name_pattern": "Weapon.*" }

        Get control flow graph of a function:
        { "file_name": "program.exe", "action": "graph", "name": "main" }

        Get call graph around a function:
        { "file_name": "program.exe", "action": "call_graph", "address": "0x401000",
          "depth": 2, "direction": "callees" }
        </examples>
        """)
public class AnalyzeTool extends BaseMcpTool {

  private static final String ACTION_DEMANGLE = "demangle";
  private static final String ACTION_RTTI = "rtti";
  private static final String ACTION_LIST_RTTI = "list_rtti";
  private static final String ACTION_GRAPH = "graph";
  private static final String ACTION_CALL_GRAPH = "call_graph";

  private static final String ARG_MANGLED_SYMBOL = "mangled_symbol";
  private static final String ARG_BACKEND = "backend";
  private static final String ARG_VALIDATE_REFERRED_TO_DATA = "validate_referred_to_data";
  private static final String ARG_IGNORE_INSTRUCTIONS = "ignore_instructions";
  private static final String ARG_IGNORE_DEFINED_DATA = "ignore_defined_data";
  private static final String ARG_FROM_VTABLE = "from_vtable";
  private static final String ARG_DEPTH = "depth";
  private static final String ARG_DIRECTION = "direction";
  private static final String ARG_MAX_RESULTS = "max_results";

  private static final String BACKEND_AUTO = "auto";
  private static final String BACKEND_MICROSOFT = "microsoft";
  private static final String BACKEND_ITANIUM = "itanium";
  private static final String BACKEND_GO = "go";

  private static final String DIRECTION_CALLERS = "callers";
  private static final String DIRECTION_CALLEES = "callees";
  private static final String DIRECTION_BOTH = "both";

  private static final int DEFAULT_DEPTH = 3;
  private static final int MAX_DEPTH = 10;

  private static final int LIST_RTTI_DEFAULT_PAGE_SIZE = 100;
  private static final int LIST_RTTI_MAX_PAGE_SIZE = 500;
  private static final int MAX_RTTI_SCAN = 50000;
  private static final int MAX_STRING_LENGTH = 512;

  @Override
  public JsonSchema schema() {
    IObjectSchemaBuilder schemaRoot = createDraft7SchemaNode();

    schemaRoot.property(
        ARG_FILE_NAME, SchemaBuilder.string(mapper).description("The name of the program file."));

    schemaRoot.property(
        ARG_ACTION,
        SchemaBuilder.string(mapper)
            .enumValues(
                ACTION_DEMANGLE, ACTION_RTTI, ACTION_LIST_RTTI, ACTION_GRAPH, ACTION_CALL_GRAPH)
            .description("Analysis operation to perform."));

    // Shared properties
    schemaRoot.property(
        ARG_ADDRESS,
        SchemaBuilder.string(mapper)
            .description("Target address for analysis.")
            .pattern("^([A-Za-z_][A-Za-z0-9_]*:)?(0x)?[0-9a-fA-F]+$"));

    // Demangle properties
    schemaRoot.property(
        ARG_MANGLED_SYMBOL,
        SchemaBuilder.string(mapper)
            .description("The mangled symbol to demangle (e.g., '_Z3fooi', '?foo@@YAXH@Z')."));

    // RTTI properties
    schemaRoot.property(
        ARG_BACKEND,
        SchemaBuilder.string(mapper)
            .description("Backend adapter to use: auto, microsoft, itanium, or go.")
            .enumValues(BACKEND_AUTO, BACKEND_MICROSOFT, BACKEND_ITANIUM, BACKEND_GO)
            .defaultValue(BACKEND_AUTO));

    schemaRoot.property(
        ARG_VALIDATE_REFERRED_TO_DATA,
        SchemaBuilder.bool(mapper)
            .description(
                "Microsoft-only: recursively validate referenced RTTI structures (default: false).")
            .defaultValue(false));

    schemaRoot.property(
        ARG_IGNORE_INSTRUCTIONS,
        SchemaBuilder.bool(mapper)
            .description(
                "Microsoft-only: ignore existing instructions during validation (default: true).")
            .defaultValue(true));

    schemaRoot.property(
        ARG_IGNORE_DEFINED_DATA,
        SchemaBuilder.bool(mapper)
            .description(
                "Microsoft-only: ignore existing defined data during validation (default: true).")
            .defaultValue(true));

    schemaRoot.property(
        ARG_FROM_VTABLE,
        SchemaBuilder.bool(mapper)
            .description(
                "If true, treat the address as a vtable and read vtable[-1] to find the RTTI4"
                    + " (Complete Object Locator) pointer, then analyze RTTI at that address"
                    + " (default: false).")
            .defaultValue(false));

    // Graph/call_graph identifier properties
    schemaRoot.property(
        ARG_SYMBOL_ID,
        SchemaBuilder.integer(mapper).description("Symbol ID to identify a specific function."));

    schemaRoot.property(
        ARG_NAME,
        SchemaBuilder.string(mapper)
            .description("Function name for lookup (supports * and ? wildcards)."));

    // List RTTI properties
    schemaRoot.property(
        ARG_NAME_PATTERN,
        SchemaBuilder.string(mapper).description("Regex filter on class name (list_rtti)."));

    schemaRoot.property(
        ARG_CURSOR, SchemaBuilder.string(mapper).description("Pagination cursor for list_rtti."));

    schemaRoot.property(
        ARG_PAGE_SIZE,
        SchemaBuilder.integer(mapper)
            .description("Results per page (list_rtti, default 100, max 500).")
            .minimum(1)
            .maximum(LIST_RTTI_MAX_PAGE_SIZE));

    schemaRoot.property(
        "custom_tags",
        SchemaBuilder.array(mapper)
            .description(
                "Agent-defined template patterns to tag classes. Each entry has 'template' (MSVC"
                    + " template name to match in RTTI entries) and 'tag' (label to apply)."
                    + " Example:"
                    + " [{\"template\":\"sp_ms_deleter\",\"tag\":\"smart_ptr_managed\"}]"));

    // Call graph properties
    schemaRoot.property(
        ARG_DEPTH,
        SchemaBuilder.integer(mapper)
            .description("Call graph traversal depth (default 3, max 10).")
            .minimum(1)
            .maximum(MAX_DEPTH));

    schemaRoot.property(
        ARG_DIRECTION,
        SchemaBuilder.string(mapper)
            .description("Call graph direction: callers, callees, or both (default both).")
            .enumValues(DIRECTION_CALLERS, DIRECTION_CALLEES, DIRECTION_BOTH)
            .defaultValue(DIRECTION_BOTH));

    schemaRoot.property(
        ARG_MAX_RESULTS,
        SchemaBuilder.integer(mapper)
            .description(
                "Maximum number of nodes to collect in call graph traversal (default 50, max 500).")
            .minimum(1)
            .maximum(500));

    schemaRoot.requiredProperty(ARG_FILE_NAME).requiredProperty(ARG_ACTION);

    schemaRoot.allOf(
        // demangle: requires mangled_symbol
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(ARG_ACTION, SchemaBuilder.string(mapper).constValue(ACTION_DEMANGLE)),
                SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_MANGLED_SYMBOL)),
        // rtti: requires address; microsoft-specific params conditional on backend
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(ARG_ACTION, SchemaBuilder.string(mapper).constValue(ACTION_RTTI)),
                SchemaBuilder.objectDraft7(mapper)
                    .requiredProperty(ARG_ADDRESS)
                    .allOf(
                        SchemaBuilder.objectDraft7(mapper)
                            .ifThen(
                                SchemaBuilder.objectDraft7(mapper)
                                    .property(
                                        ARG_BACKEND,
                                        SchemaBuilder.string(mapper).constValue(BACKEND_MICROSOFT)),
                                SchemaBuilder.objectDraft7(mapper)
                                    .property(
                                        ARG_VALIDATE_REFERRED_TO_DATA,
                                        SchemaBuilder.bool(mapper)
                                            .description(
                                                "Recursively validate referenced RTTI"
                                                    + " structures."))
                                    .property(
                                        ARG_IGNORE_INSTRUCTIONS,
                                        SchemaBuilder.bool(mapper)
                                            .description(
                                                "Ignore existing instructions during"
                                                    + " validation."))
                                    .property(
                                        ARG_IGNORE_DEFINED_DATA,
                                        SchemaBuilder.bool(mapper)
                                            .description(
                                                "Ignore existing defined data during"
                                                    + " validation."))))),
        // list_rtti: no additional required params (name_pattern, cursor, page_size all optional)
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_ACTION, SchemaBuilder.string(mapper).constValue(ACTION_LIST_RTTI)),
                SchemaBuilder.objectDraft7(mapper)),
        // graph: requires at least one identifier (symbol_id, address, name)
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(ARG_ACTION, SchemaBuilder.string(mapper).constValue(ACTION_GRAPH)),
                SchemaBuilder.objectDraft7(mapper)
                    .anyOf(
                        SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_SYMBOL_ID),
                        SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_ADDRESS),
                        SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_NAME))),
        // call_graph: identifier is optional (omit to use all functions)
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_ACTION, SchemaBuilder.string(mapper).constValue(ACTION_CALL_GRAPH)),
                SchemaBuilder.objectDraft7(mapper)));

    return schemaRoot.build();
  }

  @Override
  public Mono<? extends Object> execute(
      McpTransportContext context, Map<String, Object> args, PluginTool tool) {
    return getProgram(args, tool)
        .flatMap(
            program -> {
              String action;
              try {
                action = getRequiredStringArgument(args, ARG_ACTION);
              } catch (GhidraMcpException e) {
                return Mono.error(e);
              }

              return switch (action) {
                case ACTION_DEMANGLE -> handleDemangle(program, args);
                case ACTION_RTTI -> handleRtti(program, args);
                case ACTION_LIST_RTTI -> handleListRtti(program, args);
                case ACTION_GRAPH -> handleGraph(program, args);
                case ACTION_CALL_GRAPH -> handleCallGraph(program, args);
                default ->
                    Mono.error(
                        new GhidraMcpException(
                            GhidraMcpError.invalid(
                                ARG_ACTION,
                                action,
                                "must be one of: demangle, rtti, list_rtti, graph,"
                                    + " call_graph")));
              };
            });
  }

  // =================== Demangle Action ===================

  private Mono<DemangleResult> handleDemangle(Program program, Map<String, Object> args) {
    return Mono.fromCallable(
        () -> {
          String mangledSymbol = getRequiredStringArgument(args, ARG_MANGLED_SYMBOL);

          if (mangledSymbol.trim().isEmpty()) {
            throw new GhidraMcpException(
                GhidraMcpError.validation()
                    .errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
                    .message("Mangled symbol cannot be empty")
                    .context(
                        new GhidraMcpError.ErrorContext(
                            getMcpName(),
                            "mangled symbol validation",
                            args,
                            Map.of(ARG_MANGLED_SYMBOL, mangledSymbol),
                            Map.of("symbol_length", mangledSymbol.length())))
                    .build());
          }

          return performDemangling(program, mangledSymbol);
        });
  }

  public static class DemangleResult {
    private final String originalSymbol;
    private final String demangledSymbol;
    private final String demanglerUsed;
    private final boolean isValid;
    private final String demangledType;
    private final String namespace;
    private final String className;
    private final String functionName;
    private final List<String> parameters;
    private final String errorMessage;
    private final String symbolAnalysis;

    public DemangleResult(
        String originalSymbol,
        String demangledSymbol,
        String demanglerUsed,
        boolean isValid,
        String demangledType,
        String namespace,
        String className,
        String functionName,
        List<String> parameters) {
      this(
          originalSymbol,
          demangledSymbol,
          demanglerUsed,
          isValid,
          demangledType,
          namespace,
          className,
          functionName,
          parameters,
          null,
          null);
    }

    public DemangleResult(
        String originalSymbol,
        String demangledSymbol,
        String demanglerUsed,
        boolean isValid,
        String demangledType,
        String namespace,
        String className,
        String functionName,
        List<String> parameters,
        String errorMessage,
        String symbolAnalysis) {
      this.originalSymbol = originalSymbol;
      this.demangledSymbol = demangledSymbol;
      this.demanglerUsed = demanglerUsed;
      this.isValid = isValid;
      this.demangledType = demangledType;
      this.namespace = namespace;
      this.className = className;
      this.functionName = functionName;
      this.parameters = parameters;
      this.errorMessage = errorMessage;
      this.symbolAnalysis = symbolAnalysis;
    }

    public String getOriginalSymbol() {
      return originalSymbol;
    }

    public String getDemangledSymbol() {
      return demangledSymbol;
    }

    public String getDemanglerUsed() {
      return demanglerUsed;
    }

    public boolean isValid() {
      return isValid;
    }

    public String getDemangledType() {
      return demangledType;
    }

    public String getNamespace() {
      return namespace;
    }

    public String getClassName() {
      return className;
    }

    public String getFunctionName() {
      return functionName;
    }

    public List<String> getParameters() {
      return parameters;
    }

    public String getErrorMessage() {
      return errorMessage;
    }

    public String getSymbolAnalysis() {
      return symbolAnalysis;
    }
  }

  private DemangleResult performDemangling(Program program, String mangledSymbol)
      throws GhidraMcpException {
    try {
      // Step 1: Try MDMangGhidra (most capable — handles all MSVC symbols including
      // RTTI type descriptors, vtable symbols, constructors, operators, etc.)
      // Use structured AST for reliable field extraction.
      try {
        MDMangGhidra mdm = new MDMangGhidra();
        mdm.setMangledSymbol(mangledSymbol);
        MDParsableItem item = mdm.demangle();
        if (item != null) {
          String demangledStr = item.toString();
          if (demangledStr != null && !demangledStr.isBlank()) {
            String functionName = null;
            String className = null;
            String namespace = null;
            String demangledType = null;

            if (item instanceof mdemangler.object.MDObjectCPP cppObj) {
              functionName = cppObj.getName();
              demangledType =
                  cppObj.getQualifiedName() != null
                      ? (cppObj.getQualifiedName().isConstructor()
                          ? "Constructor"
                          : cppObj.getQualifiedName().isDestructor() ? "Destructor" : "Function")
                      : "Function";

              mdemangler.naming.MDQualification qual = cppObj.getQualification();
              if (qual != null) {
                StringBuilder nsBuilder = new StringBuilder();
                boolean first = true;
                for (var qualifier : qual) {
                  if (first) {
                    className = qualifier.toString();
                    first = false;
                  } else {
                    if (nsBuilder.length() > 0) nsBuilder.insert(0, "::");
                    nsBuilder.insert(0, qualifier.toString());
                  }
                }
                namespace = nsBuilder.length() > 0 ? nsBuilder.toString() : null;
              }
            }

            return new DemangleResult(
                mangledSymbol,
                demangledStr,
                "MDMang",
                true,
                demangledType,
                namespace,
                className,
                functionName,
                null,
                null,
                analyzeSymbol(mangledSymbol));
          }
        }
      } catch (Exception ignored) {
        // MDMang couldn't parse — fall through to Step 2
      }

      // Step 2: Try DemanglerUtil (handles Itanium/Go/other mangling schemes)
      var demangledList = DemanglerUtil.demangle(program, mangledSymbol, null);
      if (demangledList != null && !demangledList.isEmpty()) {
        Demangled demangled = demangledList.get(0);
        return buildResultFromDemangled(demangled, mangledSymbol, "Ghidra DemanglerUtil");
      }

      // Step 3: Nothing worked — return failure with symbol analysis hints
      String symbolAnalysis = analyzeSymbol(mangledSymbol);
      return new DemangleResult(
          mangledSymbol,
          null,
          "No demangler available",
          false,
          "Failed to demangle",
          null,
          null,
          null,
          null,
          "No demangler could process this symbol",
          symbolAnalysis);
    } catch (Exception e) {
      throw new GhidraMcpException(
          GhidraMcpError.execution()
              .errorCode(GhidraMcpError.ErrorCode.TRANSACTION_FAILED)
              .message("Failed to demangle symbol: " + e.getMessage())
              .context(
                  new GhidraMcpError.ErrorContext(
                      getMcpName(),
                      "demangling execution",
                      Map.of(ARG_MANGLED_SYMBOL, mangledSymbol),
                      null,
                      Map.of("program_name", program.getName())))
              .build());
    }
  }

  private DemangleResult buildResultFromDemangled(
      Demangled demangled, String mangledSymbol, String demanglerName) {
    String demangledString = demangled.toString();
    String demangledType = getDemangledType(demangled);
    String namespace = extractNamespace(demangled);
    String className = extractClassName(demangled);
    String functionName = extractFunctionName(demangled);
    List<String> parameters = extractParameters(demangled);

    return new DemangleResult(
        mangledSymbol,
        demangledString,
        demanglerName,
        true,
        demangledType,
        namespace,
        className,
        functionName,
        parameters,
        null,
        analyzeSymbol(mangledSymbol));
  }

  private String tryMDMangDemangle(String mangledSymbol) {
    try {
      MDMangGhidra mdm = new MDMangGhidra();
      mdm.setMangledSymbol(mangledSymbol);
      MDParsableItem item = mdm.demangle();
      if (item != null) {
        String result = item.toString();
        return (result != null && !result.isBlank()) ? result : null;
      }
      return null;
    } catch (Exception e) {
      return null;
    }
  }

  private String getDemangledType(Demangled demangled) {
    if (demangled == null) return "Unknown";
    String className = demangled.getClass().getSimpleName();
    if (className.startsWith("Demangled")) {
      className = className.substring("Demangled".length());
    }
    return className;
  }

  private String extractNamespace(Demangled demangled) {
    if (demangled instanceof DemangledObject obj) {
      String ns = obj.getNamespaceString();
      return (ns != null && !ns.isBlank()) ? ns : null;
    }
    return null;
  }

  private String extractClassName(Demangled demangled) {
    if (demangled instanceof DemangledObject obj) {
      String nsName = obj.getNamespaceName();
      return (nsName != null && !nsName.isBlank()) ? nsName : null;
    }
    return null;
  }

  private String extractFunctionName(Demangled demangled) {
    if (demangled instanceof DemangledObject obj) {
      String name = obj.getName();
      return (name != null && !name.isBlank()) ? name : null;
    }
    return null;
  }

  private List<String> extractParameters(Demangled demangled) {
    String signature = getDemangledSignature(demangled);
    if (signature == null) return null;

    int start = signature.indexOf('(');
    int end = signature.lastIndexOf(')');
    if (start < 0 || end <= start) return null;

    String parametersSection = signature.substring(start + 1, end).trim();
    if (parametersSection.isEmpty() || "void".equals(parametersSection)) return List.of();

    List<String> parameters = new ArrayList<>();
    StringBuilder current = new StringBuilder();
    int angleDepth = 0;
    int parenDepth = 0;
    int bracketDepth = 0;

    for (int i = 0; i < parametersSection.length(); i++) {
      char ch = parametersSection.charAt(i);
      switch (ch) {
        case '<' -> angleDepth++;
        case '>' -> angleDepth = Math.max(0, angleDepth - 1);
        case '(' -> parenDepth++;
        case ')' -> parenDepth = Math.max(0, parenDepth - 1);
        case '[' -> bracketDepth++;
        case ']' -> bracketDepth = Math.max(0, bracketDepth - 1);
        default -> {}
      }

      if (ch == ',' && angleDepth == 0 && parenDepth == 0 && bracketDepth == 0) {
        String parameter = current.toString().trim();
        if (!parameter.isEmpty()) {
          parameters.add(parameter);
        }
        current.setLength(0);
      } else {
        current.append(ch);
      }
    }

    String finalParameter = current.toString().trim();
    if (!finalParameter.isEmpty()) {
      parameters.add(finalParameter);
    }

    return parameters;
  }

  private String getDemangledSignature(Demangled demangled) {
    if (demangled == null) return null;
    String signature = demangled.toString();
    if (signature == null) return null;
    String trimmed = signature.trim();
    return trimmed.isEmpty() ? null : trimmed;
  }

  private String analyzeSymbol(String symbol) {
    if (symbol == null || symbol.trim().isEmpty()) return "Empty or null symbol";
    String trimmed = symbol.trim();
    if (trimmed.startsWith("_Z")) return "GCC/Itanium C++ ABI mangling detected";
    if (trimmed.startsWith("?")) return "Microsoft Visual C++ mangling detected";
    if (trimmed.startsWith("__")) return "Possible GCC/Clang internal symbol";
    if (trimmed.contains("@"))
      return "Symbol contains @ characters (possible MSVC or custom mangling)";
    if (trimmed.matches("^[a-zA-Z_][a-zA-Z0-9_]*$")) return "Plain symbol (not mangled)";
    if (trimmed.matches("^[0-9a-fA-F]+$")) return "Hexadecimal string (possible address or hash)";
    return "Unknown or custom symbol format";
  }

  // =================== RTTI Action ===================

  private Mono<? extends Object> handleRtti(Program program, Map<String, Object> args) {
    return Mono.fromCallable(
        () -> {
          String addressStr = getRequiredStringArgument(args, ARG_ADDRESS);
          boolean fromVtable = getOptionalBooleanArgument(args, ARG_FROM_VTABLE).orElse(false);
          RTTIAnalysisResult result = analyzeRTTIAtAddress(program, addressStr, args);

          if (fromVtable) {
            // Wrap result with vtable context info
            Map<String, Object> wrapped = new LinkedHashMap<>();
            wrapped.put("from_vtable", true);
            wrapped.put("vtable_address", addressStr);
            wrapped.put("result", result);
            return wrapped;
          }
          return result;
        });
  }

  private RTTIAnalysisResult analyzeRTTIAtAddress(
      Program program, String addressStr, Map<String, Object> args) throws GhidraMcpException {
    try {
      Address address = program.getAddressFactory().getAddress(addressStr);
      if (address == null) {
        throw new GhidraMcpException(
            GhidraMcpError.validation()
                .errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
                .message("Invalid address: " + addressStr)
                .build());
      }

      boolean fromVtable = getOptionalBooleanArgument(args, ARG_FROM_VTABLE).orElse(false);
      String vtableAddress = null;
      String rtti4PtrAddress = null;
      if (fromVtable) {
        // vtable[-1] points to RTTI4 Complete Object Locator
        vtableAddress = address.toString();
        int pointerSize = program.getDefaultPointerSize();
        Address colPtrAddr = address.subtract(pointerSize);
        rtti4PtrAddress = colPtrAddr.toString();
        Memory mem = program.getMemory();
        long colPtr;
        if (pointerSize == 8) {
          colPtr = mem.getLong(colPtrAddr);
        } else {
          colPtr = mem.getInt(colPtrAddr) & 0xFFFFFFFFL;
        }
        address = program.getAddressFactory().getDefaultAddressSpace().getAddress(colPtr);
        addressStr = address.toString();
      }

      String requestedBackend =
          getOptionalStringArgument(args, ARG_BACKEND)
              .orElse(BACKEND_AUTO)
              .toLowerCase(Locale.ROOT);
      List<RttiBackend> backends = selectBackends(requestedBackend);
      boolean forceSelectedBackend = !BACKEND_AUTO.equals(requestedBackend);

      Map<String, String> backendFailures = new LinkedHashMap<>();
      for (RttiBackend backend : backends) {
        if (!forceSelectedBackend && !backend.canAnalyzeProgram(program)) {
          backendFailures.put(backend.id(), "backend not applicable for current program");
          continue;
        }

        try {
          RTTIAnalysisResult result = backend.analyzeAtAddress(program, address, addressStr, args);
          if (result != null && result.isValid()) {
            return result;
          }
          backendFailures.put(backend.id(), extractInvalidReason(result));
        } catch (Exception e) {
          backendFailures.put(backend.id(), safeMessage(e));
        }
      }

      // Build section-aware guidance when RTTI analysis fails
      String failureSummary = buildBackendFailureSummary(backendFailures);
      String sectionHint = getSectionHint(program, address);
      if (sectionHint != null) {
        failureSummary = failureSummary + " " + sectionHint;
      }

      return RTTIAnalysisResult.invalid(
          RTTIAnalysisResult.RttiType.UNKNOWN, addressStr, failureSummary);

    } catch (GhidraMcpException e) {
      throw e;
    } catch (Exception e) {
      throw new GhidraMcpException(
          GhidraMcpError.execution()
              .errorCode(GhidraMcpError.ErrorCode.UNEXPECTED_ERROR)
              .message("Failed to analyze RTTI at address: " + safeMessage(e))
              .build());
    }
  }

  private List<RttiBackend> selectBackends(String requestedBackend) throws GhidraMcpException {
    RttiBackend microsoft = new MicrosoftRttiBackend();
    RttiBackend itanium = new ItaniumRttiBackend();
    RttiBackend go = new GoRttiBackend();

    return switch (requestedBackend) {
      case BACKEND_AUTO -> List.of(go, microsoft, itanium);
      case BACKEND_GO -> List.of(go);
      case BACKEND_MICROSOFT -> List.of(microsoft);
      case BACKEND_ITANIUM -> List.of(itanium);
      default ->
          throw new GhidraMcpException(
              GhidraMcpError.invalid(
                  ARG_BACKEND, requestedBackend, "must be one of: auto, microsoft, itanium, go"));
    };
  }

  private String extractInvalidReason(RTTIAnalysisResult result) {
    if (result instanceof RTTIAnalysisResult.InvalidResult invalid) {
      return safeMessage(new RuntimeException(invalid.error()));
    }
    return "no matching RTTI structure found";
  }

  private String buildBackendFailureSummary(Map<String, String> failures) {
    if (failures == null || failures.isEmpty()) {
      return "No valid RTTI structure found at address";
    }
    StringBuilder summary =
        new StringBuilder("No valid RTTI structure found at address. Backends: ");
    boolean first = true;
    for (Map.Entry<String, String> entry : failures.entrySet()) {
      if (!first) {
        summary.append("; ");
      }
      summary
          .append(entry.getKey())
          .append('=')
          .append(
              entry.getValue() == null || entry.getValue().isBlank()
                  ? "unknown error"
                  : entry.getValue());
      first = false;
    }
    return summary.toString();
  }

  private String getSectionHint(Program program, Address address) {
    MemoryBlock block = program.getMemory().getBlock(address);
    if (block == null) {
      return null;
    }
    String blockName = block.getName().toLowerCase(Locale.ROOT);
    if (blockName.equals(".rdata") || blockName.equals(".rodata")) {
      return "Hint: This address is in "
          + block.getName()
          + " — if it's a vtable, the RTTI4 (Complete Object Locator) is at address - "
          + program.getDefaultPointerSize()
          + ". Try analyzing that address instead, or use from_vtable=true.";
    }
    if (blockName.equals(".text") || block.isExecute()) {
      return "Hint: This address is in "
          + block.getName()
          + " (code section). RTTI structures are in .data/.rdata sections.";
    }
    return null;
  }

  private RTTIAnalysisResult analyzeMicrosoftRttiAtAddress(
      Program program, Address address, String addressStr, Map<String, Object> args)
      throws Exception {
    DataValidationOptions validationOptions = buildValidationOptions(args);
    Map<RTTIAnalysisResult.RttiType, String> failureReasons = new LinkedHashMap<>();

    RTTIAnalysisResult result =
        tryAnalyze(
            RTTIAnalysisResult.RttiType.RTTI4,
            addressStr,
            failureReasons,
            () -> {
              Rtti4Model model = new Rtti4Model(program, address, validationOptions);
              model.validate();
              return RTTIAnalysisResult.from(model, address);
            });
    if (result.isValid()) return result;

    result =
        tryAnalyze(
            RTTIAnalysisResult.RttiType.RTTI3,
            addressStr,
            failureReasons,
            () -> {
              Rtti3Model model = new Rtti3Model(program, address, validationOptions);
              model.validate();
              return RTTIAnalysisResult.from(model, address);
            });
    if (result.isValid()) return result;

    result =
        tryAnalyze(
            RTTIAnalysisResult.RttiType.RTTI1,
            addressStr,
            failureReasons,
            () -> {
              Rtti1Model model = new Rtti1Model(program, address, validationOptions);
              model.validate();
              return RTTIAnalysisResult.from(model, address);
            });
    if (result.isValid()) return result;

    result =
        tryAnalyze(
            RTTIAnalysisResult.RttiType.RTTI0,
            addressStr,
            failureReasons,
            () -> {
              DataTypeManager dtm = program.getDataTypeManager();
              TypeDescriptorModel typeDescriptorModel =
                  new TypeDescriptorModel(program, address, validationOptions);
              typeDescriptorModel.validate();
              RTTI0DataType rtti0 = new RTTI0DataType(dtm);
              return RTTIAnalysisResult.from(rtti0, program, address);
            });
    if (result.isValid()) return result;

    result =
        tryAnalyze(
            RTTIAnalysisResult.RttiType.VFTABLE,
            addressStr,
            failureReasons,
            () -> {
              VfTableModel model = new VfTableModel(program, address, validationOptions);
              model.validate();
              return RTTIAnalysisResult.from(model, address);
            });
    if (result.isValid()) return result;

    return RTTIAnalysisResult.invalid(
        RTTIAnalysisResult.RttiType.UNKNOWN, addressStr, buildFailureSummary(failureReasons));
  }

  private RTTIAnalysisResult analyzeItaniumRttiAtAddress(
      Program program, Address address, String addressStr) {
    Map<RTTIAnalysisResult.RttiType, String> failureReasons = new LinkedHashMap<>();

    RTTIAnalysisResult result =
        tryAnalyze(
            RTTIAnalysisResult.RttiType.ITANIUM_VTABLE,
            addressStr,
            failureReasons,
            () -> analyzeItaniumVtable(program, address));
    if (result.isValid()) return result;

    result =
        tryAnalyze(
            RTTIAnalysisResult.RttiType.ITANIUM_VMI_CLASS_TYPEINFO,
            addressStr,
            failureReasons,
            () ->
                analyzeItaniumTypeInfoAtAddress(
                    program, address, RTTIAnalysisResult.RttiType.ITANIUM_VMI_CLASS_TYPEINFO));
    if (result.isValid()) return result;

    result =
        tryAnalyze(
            RTTIAnalysisResult.RttiType.ITANIUM_SI_CLASS_TYPEINFO,
            addressStr,
            failureReasons,
            () ->
                analyzeItaniumTypeInfoAtAddress(
                    program, address, RTTIAnalysisResult.RttiType.ITANIUM_SI_CLASS_TYPEINFO));
    if (result.isValid()) return result;

    result =
        tryAnalyze(
            RTTIAnalysisResult.RttiType.ITANIUM_CLASS_TYPEINFO,
            addressStr,
            failureReasons,
            () ->
                analyzeItaniumTypeInfoAtAddress(
                    program, address, RTTIAnalysisResult.RttiType.ITANIUM_CLASS_TYPEINFO));
    if (result.isValid()) return result;

    return RTTIAnalysisResult.invalid(
        RTTIAnalysisResult.RttiType.UNKNOWN, addressStr, buildFailureSummary(failureReasons));
  }

  private RTTIAnalysisResult analyzeGoRttiAtAddress(
      Program program, Address address, String addressStr) throws Exception {
    GoRttiMapper goBinary = GoRttiMapper.getGoBinary(program, TaskMonitor.DUMMY);
    if (goBinary == null) {
      throw new IllegalArgumentException("program does not appear to contain Go RTTI metadata");
    }

    try {
      goBinary.init(TaskMonitor.DUMMY);

      Map<RTTIAnalysisResult.RttiType, String> failureReasons = new LinkedHashMap<>();
      RTTIAnalysisResult result =
          tryAnalyze(
              RTTIAnalysisResult.RttiType.GO_TYPE,
              addressStr,
              failureReasons,
              () -> analyzeGoType(goBinary, address));
      if (result.isValid()) return result;

      result =
          tryAnalyze(
              RTTIAnalysisResult.RttiType.GO_ITAB,
              addressStr,
              failureReasons,
              () -> analyzeGoItab(goBinary, address));
      if (result.isValid()) return result;

      return RTTIAnalysisResult.invalid(
          RTTIAnalysisResult.RttiType.UNKNOWN, addressStr, buildFailureSummary(failureReasons));
    } finally {
      goBinary.close();
    }
  }

  private RTTIAnalysisResult analyzeGoType(GoRttiMapper goBinary, Address address)
      throws Exception {
    GoType goType = goBinary.getGoTypes().getType(address.getOffset(), false);
    if (goType == null) {
      throw new IllegalArgumentException("address is not a Go runtime._type structure");
    }

    Address typeAddress = goType.getStructureContext().getStructureAddress();
    RTTIAnalysisResult.GoTypeInfo data =
        new RTTIAnalysisResult.GoTypeInfo(
            safeString(goType.getName()),
            safeString(goType.getFullyQualifiedName()),
            goType.getClass().getSimpleName(),
            goType.getClass().getName(),
            typeAddress != null ? typeAddress.toString() : address.toString(),
            goType.getTypeOffset(),
            nullableNonBlank(goType.getPackagePathString()),
            nullableNonBlank(goType.toString()),
            nullableNonBlank(goBinary.getGoVer() != null ? goBinary.getGoVer().toString() : null));

    return RTTIAnalysisResult.from(data, address);
  }

  private RTTIAnalysisResult analyzeGoItab(GoRttiMapper goBinary, Address address)
      throws Exception {
    GoItab targetItab = findGoItabAtAddress(goBinary, address);
    if (targetItab == null) {
      throw new IllegalArgumentException("address is not a Go runtime.itab structure");
    }

    GoType concreteGoType = targetItab.getType();
    GoType interfaceGoType = targetItab.getInterfaceType();
    RTTIAnalysisResult.GoItabInfo data =
        new RTTIAnalysisResult.GoItabInfo(
            address.toString(),
            concreteGoType != null ? concreteGoType.getFullyQualifiedName() : null,
            interfaceGoType != null ? interfaceGoType.getFullyQualifiedName() : null,
            targetItab.getFuncCount(),
            nullableNonBlank(goBinary.getGoVer() != null ? goBinary.getGoVer().toString() : null));

    return RTTIAnalysisResult.from(data, address);
  }

  private GoItab findGoItabAtAddress(GoRttiMapper goBinary, Address address) throws Exception {
    for (GoModuledata module : goBinary.getModules()) {
      for (GoItab itab : module.getItabs()) {
        Address itabAddress = itab.getStructureContext().getStructureAddress();
        if (itabAddress != null && itabAddress.equals(address)) {
          return itab;
        }
      }
    }
    return null;
  }

  private RTTIAnalysisResult analyzeItaniumTypeInfoAtAddress(
      Program program, Address address, RTTIAnalysisResult.RttiType expectedKind) throws Exception {
    Symbol typeInfoSymbol = getPrimaryOrFirstSymbol(program, address);
    String symbolName = typeInfoSymbol != null ? typeInfoSymbol.getName() : "";
    String demangledSymbol = tryDemangleSymbol(program, symbolName, address);

    if (!looksLikeItaniumTypeInfoSymbol(symbolName)
        && !looksLikeItaniumTypeInfoDemangled(demangledSymbol)) {
      throw new IllegalArgumentException("address does not look like an Itanium typeinfo symbol");
    }

    int pointerSize = program.getDefaultPointerSize();
    Address classTypeInfoVtableAddress = readPointerAddress(program, address);
    if (classTypeInfoVtableAddress == null) {
      throw new IllegalArgumentException("typeinfo vtable pointer is null");
    }

    Address typeNameAddress = readPointerAddress(program, address.add(pointerSize));
    String representedType = extractTypeFromDemangledTypeInfo(demangledSymbol);
    if (representedType == null && typeNameAddress != null) {
      representedType = readCString(program, typeNameAddress, 512);
    }

    Symbol classTypeInfoVtableSymbol =
        findClassTypeInfoVtableSymbol(program, classTypeInfoVtableAddress);
    String vtableSymbolName =
        classTypeInfoVtableSymbol != null ? classTypeInfoVtableSymbol.getName() : "";
    String demangledVtableSymbol =
        tryDemangleSymbol(program, vtableSymbolName, classTypeInfoVtableAddress);
    RTTIAnalysisResult.RttiType detectedKind =
        classifyItaniumTypeInfoKind(
            vtableSymbolName, demangledVtableSymbol != null ? demangledVtableSymbol : "");
    if (detectedKind == RTTIAnalysisResult.RttiType.UNKNOWN) {
      detectedKind = RTTIAnalysisResult.RttiType.ITANIUM_CLASS_TYPEINFO;
    }

    if (detectedKind != expectedKind) {
      throw new IllegalArgumentException(
          "detected " + detectedKind.name() + " but expected " + expectedKind.name());
    }

    String typeNameAddressStr = typeNameAddress != null ? typeNameAddress.toString() : null;
    String classTypeInfoVtableAddressStr = classTypeInfoVtableAddress.toString();

    if (detectedKind == RTTIAnalysisResult.RttiType.ITANIUM_CLASS_TYPEINFO) {
      RTTIAnalysisResult.ItaniumClassTypeInfo data =
          new RTTIAnalysisResult.ItaniumClassTypeInfo(
              symbolName,
              demangledSymbol,
              representedType,
              typeNameAddressStr,
              classTypeInfoVtableAddressStr);
      return RTTIAnalysisResult.from(data, address);
    }

    if (detectedKind == RTTIAnalysisResult.RttiType.ITANIUM_SI_CLASS_TYPEINFO) {
      Address baseTypeInfoAddress = readPointerAddress(program, address.add(pointerSize * 2L));
      RTTIAnalysisResult.ItaniumSiClassTypeInfo data =
          new RTTIAnalysisResult.ItaniumSiClassTypeInfo(
              symbolName,
              demangledSymbol,
              representedType,
              typeNameAddressStr,
              classTypeInfoVtableAddressStr,
              baseTypeInfoAddress != null ? baseTypeInfoAddress.toString() : null);
      return RTTIAnalysisResult.from(data, address);
    }

    if (detectedKind != RTTIAnalysisResult.RttiType.ITANIUM_VMI_CLASS_TYPEINFO) {
      throw new IllegalArgumentException("unsupported Itanium typeinfo layout");
    }

    long flags = readUnsignedInt(program, address.add(pointerSize * 2L));
    int numBaseClasses = (int) readUnsignedInt(program, address.add(pointerSize * 2L + 4));
    if (numBaseClasses < 0 || numBaseClasses > 512) {
      throw new IllegalArgumentException(
          "invalid __vmi_class_type_info base count: " + numBaseClasses);
    }

    List<RTTIAnalysisResult.ItaniumVmiBaseClass> baseClasses = new ArrayList<>();
    Address baseArrayAddress = address.add(pointerSize * 2L + 8);
    long baseEntrySize = pointerSize * 2L;

    for (int i = 0; i < numBaseClasses; i++) {
      Address baseEntryAddress = baseArrayAddress.add(baseEntrySize * i);
      Address baseTypeInfoAddress = readPointerAddress(program, baseEntryAddress);
      long offsetFlags = readPointerUnsignedValue(program, baseEntryAddress.add(pointerSize));
      boolean isVirtual = (offsetFlags & 0x1L) != 0;
      boolean isPublic = (offsetFlags & 0x2L) != 0;
      long offset = decodeItaniumBaseOffset(offsetFlags, pointerSize);

      baseClasses.add(
          new RTTIAnalysisResult.ItaniumVmiBaseClass(
              i,
              baseTypeInfoAddress != null ? baseTypeInfoAddress.toString() : null,
              isVirtual,
              isPublic,
              offset));
    }

    RTTIAnalysisResult.ItaniumVmiClassTypeInfo data =
        new RTTIAnalysisResult.ItaniumVmiClassTypeInfo(
            symbolName,
            demangledSymbol,
            representedType,
            typeNameAddressStr,
            classTypeInfoVtableAddressStr,
            flags,
            numBaseClasses,
            baseClasses);
    return RTTIAnalysisResult.from(data, address);
  }

  private RTTIAnalysisResult analyzeItaniumVtable(Program program, Address address)
      throws Exception {
    Symbol vtableSymbol = getPrimaryOrFirstSymbol(program, address);
    String symbolName = vtableSymbol != null ? vtableSymbol.getName() : "";
    String demangledSymbol = tryDemangleSymbol(program, symbolName, address);
    if (!looksLikeItaniumVtableSymbol(symbolName)
        && !looksLikeItaniumVtableDemangled(demangledSymbol)) {
      throw new IllegalArgumentException("address does not look like an Itanium vtable symbol");
    }

    int pointerSize = program.getDefaultPointerSize();
    long offsetToTop = readPointerSignedValue(program, address);
    Address typeInfoAddress = readPointerAddress(program, address.add(pointerSize));

    Map<Integer, String> virtualFunctionPointers = new LinkedHashMap<>();
    Address firstFunctionPointerAddress = address.add(pointerSize * 2L);
    for (int i = 0; i < 128; i++) {
      Address currentPointerAddress = firstFunctionPointerAddress.add((long) i * pointerSize);
      Address functionPointer = readPointerAddress(program, currentPointerAddress);
      if (functionPointer == null || !isLoadedAndInitializedAddress(program, functionPointer)) {
        break;
      }
      virtualFunctionPointers.put(i, functionPointer.toString());
    }

    RTTIAnalysisResult.ItaniumVtable data =
        new RTTIAnalysisResult.ItaniumVtable(
            symbolName,
            demangledSymbol,
            offsetToTop,
            typeInfoAddress != null ? typeInfoAddress.toString() : null,
            virtualFunctionPointers);
    return RTTIAnalysisResult.from(data, address);
  }

  static RTTIAnalysisResult.RttiType classifyItaniumTypeInfoKind(
      String vtableSymbolName, String demangledVtableName) {
    String combined = (vtableSymbolName + " " + demangledVtableName).toLowerCase();
    if (combined.contains("__vmi_class_type_info"))
      return RTTIAnalysisResult.RttiType.ITANIUM_VMI_CLASS_TYPEINFO;
    if (combined.contains("__si_class_type_info"))
      return RTTIAnalysisResult.RttiType.ITANIUM_SI_CLASS_TYPEINFO;
    if (combined.contains("__class_type_info"))
      return RTTIAnalysisResult.RttiType.ITANIUM_CLASS_TYPEINFO;
    return RTTIAnalysisResult.RttiType.UNKNOWN;
  }

  static boolean looksLikeItaniumTypeInfoSymbol(String symbolName) {
    return symbolName != null && (symbolName.startsWith("_ZTI") || symbolName.startsWith("__ZTI"));
  }

  static boolean looksLikeItaniumVtableSymbol(String symbolName) {
    return symbolName != null && (symbolName.startsWith("_ZTV") || symbolName.startsWith("__ZTV"));
  }

  static boolean looksLikeItaniumTypeInfoDemangled(String demangledName) {
    return demangledName != null && demangledName.toLowerCase().startsWith("typeinfo for ");
  }

  static boolean looksLikeItaniumVtableDemangled(String demangledName) {
    return demangledName != null && demangledName.toLowerCase().startsWith("vtable for ");
  }

  static String extractTypeFromDemangledTypeInfo(String demangledName) {
    if (demangledName == null) return null;
    String prefix = "typeinfo for ";
    if (!demangledName.toLowerCase().startsWith(prefix)) return null;
    String typeName = demangledName.substring(prefix.length()).trim();
    return typeName.isEmpty() ? null : typeName;
  }

  private Symbol findClassTypeInfoVtableSymbol(Program program, Address vtableAddress) {
    int pointerSize = program.getDefaultPointerSize();
    Symbol symbol = getPrimaryOrFirstSymbol(program, vtableAddress);
    if (symbol != null) return symbol;

    try {
      Address previous = vtableAddress.subtractNoWrap(pointerSize);
      symbol = getPrimaryOrFirstSymbol(program, previous);
      if (symbol != null) return symbol;
    } catch (AddressOverflowException ignored) {
      // ignored
    }

    try {
      Address twoBack = vtableAddress.subtractNoWrap(pointerSize * 2L);
      return getPrimaryOrFirstSymbol(program, twoBack);
    } catch (AddressOverflowException ignored) {
      return null;
    }
  }

  private Symbol getPrimaryOrFirstSymbol(Program program, Address address) {
    Symbol primary = program.getSymbolTable().getPrimarySymbol(address);
    if (primary != null) return primary;
    Symbol[] symbols = program.getSymbolTable().getSymbols(address);
    return symbols.length > 0 ? symbols[0] : null;
  }

  private String tryDemangleSymbol(Program program, String symbolName, Address address) {
    if (symbolName == null || symbolName.isBlank()) return null;
    try {
      var demangled = DemanglerUtil.demangle(program, symbolName, address);
      if (demangled == null || demangled.isEmpty() || demangled.get(0) == null) return null;
      String text = demangled.get(0).toString();
      if (text == null || text.isBlank()) return null;
      return text;
    } catch (Exception e) {
      return null;
    }
  }

  private String readCString(Program program, Address address, int maxLength) {
    if (address == null || maxLength <= 0 || !isLoadedAndInitializedAddress(program, address))
      return null;

    StringBuilder sb = new StringBuilder();
    Memory memory = program.getMemory();
    for (int i = 0; i < maxLength; i++) {
      try {
        byte value = memory.getByte(address.add(i));
        if (value == 0) break;
        int unsigned = Byte.toUnsignedInt(value);
        if (unsigned < 0x20 || unsigned > 0x7e) return null;
        sb.append((char) unsigned);
      } catch (Exception e) {
        return null;
      }
    }

    String text = sb.toString().trim();
    return text.isEmpty() ? null : text;
  }

  private boolean isLoadedAndInitializedAddress(Program program, Address address) {
    if (address == null) return false;
    return program.getMemory().getLoadedAndInitializedAddressSet().contains(address);
  }

  private Address readPointerAddress(Program program, Address address)
      throws MemoryAccessException, AddressOutOfBoundsException {
    long value = readPointerUnsignedValue(program, address);
    if (value == 0) return null;
    return toDefaultAddress(program, value);
  }

  private long readPointerUnsignedValue(Program program, Address address)
      throws MemoryAccessException, AddressOutOfBoundsException {
    int pointerSize = program.getDefaultPointerSize();
    Memory memory = program.getMemory();
    if (pointerSize == 8) return memory.getLong(address);
    if (pointerSize == 4) return Integer.toUnsignedLong(memory.getInt(address));
    throw new IllegalArgumentException("unsupported pointer size: " + pointerSize);
  }

  private long readPointerSignedValue(Program program, Address address)
      throws MemoryAccessException, AddressOutOfBoundsException {
    int pointerSize = program.getDefaultPointerSize();
    Memory memory = program.getMemory();
    if (pointerSize == 8) return memory.getLong(address);
    if (pointerSize == 4) return memory.getInt(address);
    throw new IllegalArgumentException("unsupported pointer size: " + pointerSize);
  }

  private long readUnsignedInt(Program program, Address address)
      throws MemoryAccessException, AddressOutOfBoundsException {
    return Integer.toUnsignedLong(program.getMemory().getInt(address));
  }

  private Address toDefaultAddress(Program program, long offset) {
    AddressSpace defaultSpace = program.getAddressFactory().getDefaultAddressSpace();
    try {
      return defaultSpace.getAddress(offset);
    } catch (Exception e) {
      return null;
    }
  }

  private long decodeItaniumBaseOffset(long offsetFlags, int pointerSize) {
    if (pointerSize == 4) {
      int signed = (int) (offsetFlags & 0xffff_ffffL);
      return signed >> 8;
    }
    return offsetFlags >> 8;
  }

  private String safeString(String value) {
    return value == null ? "" : value;
  }

  private String nullableNonBlank(String value) {
    if (value == null || value.isBlank()) return null;
    return value;
  }

  private boolean hasGoProgramSignal(Program program) {
    if (GoRttiMapper.isGolangProgram(program)) return true;
    List<String> sectionNames =
        Arrays.stream(program.getMemory().getBlocks()).map(MemoryBlock::getName).toList();
    return GoRttiMapper.hasGolangSections(sectionNames);
  }

  private interface RttiBackend {
    String id();

    boolean canAnalyzeProgram(Program program);

    RTTIAnalysisResult analyzeAtAddress(
        Program program, Address address, String addressStr, Map<String, Object> args)
        throws Exception;
  }

  private final class MicrosoftRttiBackend implements RttiBackend {
    @Override
    public String id() {
      return BACKEND_MICROSOFT;
    }

    @Override
    public boolean canAnalyzeProgram(Program program) {
      return PEUtil.isVisualStudioOrClangPe(program);
    }

    @Override
    public RTTIAnalysisResult analyzeAtAddress(
        Program program, Address address, String addressStr, Map<String, Object> args)
        throws Exception {
      return analyzeMicrosoftRttiAtAddress(program, address, addressStr, args);
    }
  }

  private final class ItaniumRttiBackend implements RttiBackend {
    @Override
    public String id() {
      return BACKEND_ITANIUM;
    }

    @Override
    public boolean canAnalyzeProgram(Program program) {
      return !PEUtil.isVisualStudioOrClangPe(program) && !hasGoProgramSignal(program);
    }

    @Override
    public RTTIAnalysisResult analyzeAtAddress(
        Program program, Address address, String addressStr, Map<String, Object> args) {
      return analyzeItaniumRttiAtAddress(program, address, addressStr);
    }
  }

  private final class GoRttiBackend implements RttiBackend {
    @Override
    public String id() {
      return BACKEND_GO;
    }

    @Override
    public boolean canAnalyzeProgram(Program program) {
      return hasGoProgramSignal(program);
    }

    @Override
    public RTTIAnalysisResult analyzeAtAddress(
        Program program, Address address, String addressStr, Map<String, Object> args)
        throws Exception {
      return analyzeGoRttiAtAddress(program, address, addressStr);
    }
  }

  static String buildFailureSummary(Map<RTTIAnalysisResult.RttiType, String> failureReasons) {
    if (failureReasons == null || failureReasons.isEmpty()) {
      return "No valid RTTI structure found at address";
    }
    StringBuilder summary =
        new StringBuilder("No valid RTTI structure found at address. Attempts: ");
    boolean first = true;
    for (Map.Entry<RTTIAnalysisResult.RttiType, String> entry : failureReasons.entrySet()) {
      if (!first) {
        summary.append("; ");
      }
      summary
          .append(entry.getKey().name())
          .append('=')
          .append(
              entry.getValue() == null || entry.getValue().isBlank()
                  ? "unknown error"
                  : entry.getValue());
      first = false;
    }
    return summary.toString();
  }

  private String safeMessage(Throwable t) {
    if (t == null || t.getMessage() == null || t.getMessage().isBlank()) return "unknown error";
    return t.getMessage();
  }

  private DataValidationOptions buildValidationOptions(Map<String, Object> args) {
    DataValidationOptions options = new DataValidationOptions();
    options.setValidateReferredToData(
        getOptionalBooleanArgument(args, ARG_VALIDATE_REFERRED_TO_DATA).orElse(false));
    options.setIgnoreInstructions(
        getOptionalBooleanArgument(args, ARG_IGNORE_INSTRUCTIONS).orElse(true));
    options.setIgnoreDefinedData(
        getOptionalBooleanArgument(args, ARG_IGNORE_DEFINED_DATA).orElse(true));
    return options;
  }

  private RTTIAnalysisResult tryAnalyze(
      RTTIAnalysisResult.RttiType attemptedType,
      String addressStr,
      Map<RTTIAnalysisResult.RttiType, String> failureReasons,
      RttiAnalyzer analyzer) {
    try {
      return analyzer.analyze();
    } catch (Exception e) {
      String message = safeMessage(e);
      failureReasons.putIfAbsent(attemptedType, message);
      return RTTIAnalysisResult.invalid(attemptedType, addressStr, message);
    }
  }

  @FunctionalInterface
  private interface RttiAnalyzer {
    RTTIAnalysisResult analyze() throws Exception;
  }

  // =================== List RTTI Action ===================

  @SuppressWarnings("unchecked")
  private Mono<PaginatedResult<Map<String, Object>>> handleListRtti(
      Program program, Map<String, Object> args) {
    return Mono.fromCallable(
        () -> {
          Optional<String> namePatternOpt = getOptionalStringArgument(args, ARG_NAME_PATTERN);
          Optional<String> cursorOpt = getOptionalStringArgument(args, ARG_CURSOR);
          int pageSize =
              getPageSizeArgument(args, LIST_RTTI_DEFAULT_PAGE_SIZE, LIST_RTTI_MAX_PAGE_SIZE);

          Pattern nameFilter = null;
          if (namePatternOpt.isPresent() && !namePatternOpt.get().isBlank()) {
            nameFilter = Pattern.compile(namePatternOpt.get(), Pattern.CASE_INSENSITIVE);
          }

          // Parse agent-defined custom tag patterns
          List<Map<String, Object>> customTagDefs =
              getOptionalListArgument(args, "custom_tags").orElse(null);
          Map<String, String> templateToTag = new LinkedHashMap<>();
          if (customTagDefs != null) {
            for (Map<String, Object> def : customTagDefs) {
              String template = def.get("template") != null ? def.get("template").toString() : null;
              String tag = def.get("tag") != null ? def.get("tag").toString() : null;
              if (template != null && tag != null) {
                // MSVC template args are encoded as TemplateName@V for class args
                templateToTag.put(template + "@V", tag);
              }
            }
          }

          int startIndex = 0;
          if (cursorOpt.isPresent()) {
            String decoded = decodeOpaqueCursorSingleV1(cursorOpt.get(), ARG_CURSOR, "v1:index");
            startIndex = Integer.parseInt(decoded);
          }

          Memory memory = program.getMemory();

          // Map from mangled name to class info
          Map<String, Map<String, Object>> classMap = new TreeMap<>();
          // Map from class name to list of methods discovered via lambda RTTI
          Map<String, List<Map<String, String>>> methodMap = new LinkedHashMap<>();
          Map<String, Set<String>> classCustomTags = new LinkedHashMap<>();

          // Restrict search to .data section where RTTI0 type descriptors live
          MemoryBlock dataBlock = memory.getBlock(".data");
          AddressSetView searchSet;
          if (dataBlock != null) {
            searchSet =
                program
                    .getMemory()
                    .getLoadedAndInitializedAddressSet()
                    .intersectRange(dataBlock.getStart(), dataBlock.getEnd());
          } else {
            searchSet = program.getMemory().getLoadedAndInitializedAddressSet();
          }

          DataValidationOptions validationOptions = new DataValidationOptions();

          // Try structured RTTI0 discovery via type_info vftable
          Address typeInfoVftable = null;
          try {
            typeInfoVftable = RttiUtil.findTypeInfoVftableAddress(program, TaskMonitor.DUMMY);
          } catch (Exception ignored) {
            // Fall back to byte pattern scan
          }

          if (typeInfoVftable != null) {
            // Search for vftable pointer occurrences — each match is an RTTI0 base address
            int pointerSize = program.getDefaultPointerSize();
            byte[] vftableBytes = addressToLittleEndianBytes(typeInfoVftable, pointerSize);
            String hexPattern = bytesToHexString(vftableBytes);

            SearchSettings settings = new SearchSettings();
            settings.withSearchFormat(SearchFormat.HEX);
            settings.withBigEndian(memory.isBigEndian());
            ByteMatcher matcher = SearchFormat.HEX.parse(hexPattern, settings);

            ProgramByteSource byteSource = new ProgramByteSource(program);
            MemorySearcher searcher =
                new MemorySearcher(byteSource, matcher, searchSet, MAX_RTTI_SCAN);

            ListAccumulator<MemoryMatch> accumulator = new ListAccumulator<>();
            searcher.findAll(accumulator, TaskMonitor.DUMMY);

            // Phase 1: Validate each RTTI0 using TypeDescriptorModel
            for (MemoryMatch match : accumulator) {
              Address rtti0Addr = match.getAddress();
              try {
                TypeDescriptorModel rtti0 =
                    new TypeDescriptorModel(program, rtti0Addr, validationOptions);
                rtti0.validate();
                String mangledName = rtti0.getTypeName();
                if (mangledName == null || mangledName.length() < 4) {
                  continue;
                }
                String typeKind = classifyTypeKind(mangledName);
                if (typeKind == null) {
                  continue;
                }

                // Process lambda RTTI for method discovery
                processLambdaRttiEntry(mangledName, methodMap);

                // Apply agent-defined custom tags
                applyCustomTags(mangledName, templateToTag, classCustomTags);

                if (!classMap.containsKey(mangledName)) {
                  // Use Ghidra's demangling from the model, fall back to MDMang
                  String demangled = rtti0.getDemangledTypeDescriptor();
                  if (demangled == null || demangled.isEmpty()) {
                    demangled = tryMDMangDemangle(mangledName);
                  }
                  String displayName = demangled != null ? demangled : mangledName;

                  Map<String, Object> classInfo = new LinkedHashMap<>();
                  classInfo.put("name", displayName);
                  classInfo.put("mangled", mangledName);
                  classInfo.put("type_kind", typeKind);
                  classInfo.put("rtti0_address", rtti0Addr.toString());
                  classMap.put(mangledName, classInfo);
                }
              } catch (Exception ignored) {
                // Invalid RTTI0 structure — skip
              }
            }
          } else {
            // Fallback: bulk search for ".?A" byte pattern (no type_info vftable found)
            SearchSettings settings = new SearchSettings();
            settings.withSearchFormat(SearchFormat.HEX);
            settings.withBigEndian(memory.isBigEndian());
            ByteMatcher matcher = SearchFormat.HEX.parse("2e 3f 41", settings);

            ProgramByteSource byteSource = new ProgramByteSource(program);
            MemorySearcher searcher =
                new MemorySearcher(byteSource, matcher, searchSet, MAX_RTTI_SCAN);

            ListAccumulator<MemoryMatch> accumulator = new ListAccumulator<>();
            searcher.findAll(accumulator, TaskMonitor.DUMMY);

            for (MemoryMatch match : accumulator) {
              Address found = match.getAddress();
              String mangledName = readCStringFromMemory(memory, found, MAX_STRING_LENGTH);
              if (mangledName != null && mangledName.length() >= 4) {
                String typeKind = classifyTypeKind(mangledName);
                if (typeKind != null) {
                  try {
                    Address rtti0Addr = found.subtract(16);

                    processLambdaRttiEntry(mangledName, methodMap);
                    applyCustomTags(mangledName, templateToTag, classCustomTags);

                    if (!classMap.containsKey(mangledName)) {
                      String demangled = tryMDMangDemangle(mangledName);
                      String displayName = demangled != null ? demangled : mangledName;

                      Map<String, Object> classInfo = new LinkedHashMap<>();
                      classInfo.put("name", displayName);
                      classInfo.put("mangled", mangledName);
                      classInfo.put("type_kind", typeKind);
                      classInfo.put("rtti0_address", rtti0Addr.toString());
                      classMap.put(mangledName, classInfo);
                    }
                  } catch (Exception ignored) {
                  }
                }
              }
            }
          }

          // Phase 3: Enrich with RTTI4 (Complete Object Locator) data
          enrichWithRtti4Data(program, memory, classMap);

          // Phase 4: Build the output class list, merging method info
          List<Map<String, Object>> allClasses = new ArrayList<>();
          for (var entry : classMap.entrySet()) {
            Map<String, Object> classInfo = new LinkedHashMap<>(entry.getValue());
            String mangledKey = entry.getKey();

            String className = extractClassNameFromMangled(mangledKey);
            String displayName = (String) classInfo.get("name");
            List<Map<String, String>> methods = new ArrayList<>();
            Set<String> seenMethods = new LinkedHashSet<>();
            if (className != null) {
              for (var methodEntry : methodMap.entrySet()) {
                String lambdaClassName = methodEntry.getKey();
                // Match on extracted class name directly
                boolean matches = lambdaClassName.equals(className);
                if (!matches && displayName != null && displayName.contains(lambdaClassName)) {
                  // Also match if the demangled display name contains the lambda's class name
                  // e.g., display "class Javelin::Weapon" contains lambda class "Weapon"
                  matches = true;
                }
                if (matches) {
                  // Deduplicate methods by name
                  for (Map<String, String> method : methodEntry.getValue()) {
                    String methodName = method.get("name");
                    if (methodName != null && seenMethods.add(methodName)) {
                      methods.add(method);
                    }
                  }
                }
              }
            }
            classInfo.put("methods", methods);

            // Merge agent-defined custom tags
            Set<String> tags = new LinkedHashSet<>();
            for (var tagEntry : classCustomTags.entrySet()) {
              String tagClass = tagEntry.getKey();
              if ((className != null && className.equals(tagClass))
                  || (displayName != null && displayName.contains(tagClass))) {
                tags.addAll(tagEntry.getValue());
              }
            }
            if (!tags.isEmpty()) {
              classInfo.put("custom_tags", new ArrayList<>(tags));
            }

            allClasses.add(classInfo);
          }

          // Add classes only discovered through lambda RTTI (not having their own RTTI0)
          for (var methodEntry : methodMap.entrySet()) {
            String className = methodEntry.getKey();
            boolean alreadyPresent = false;
            for (var entry : classMap.entrySet()) {
              String existingClassName = extractClassNameFromMangled(entry.getKey());
              String existingDisplayName = (String) entry.getValue().get("name");
              if (className.equals(existingClassName)
                  || (existingDisplayName != null && existingDisplayName.contains(className))) {
                alreadyPresent = true;
                break;
              }
            }
            if (!alreadyPresent) {
              Map<String, Object> classInfo = new LinkedHashMap<>();
              classInfo.put("name", className);
              classInfo.put("mangled", null);
              classInfo.put("type_kind", "class");
              classInfo.put("rtti0_address", null);
              classInfo.put("methods", methodEntry.getValue());
              allClasses.add(classInfo);
            }
          }

          // Phase 5: Apply name_pattern filter if provided
          if (nameFilter != null) {
            Pattern filter = nameFilter;
            allClasses.removeIf(
                cls -> {
                  String name = (String) cls.get("name");
                  String mangled = (String) cls.get("mangled");
                  boolean nameMatches = name != null && filter.matcher(name).find();
                  boolean mangledMatches = mangled != null && filter.matcher(mangled).find();
                  return !nameMatches && !mangledMatches;
                });
          }

          // Phase 6: Paginate
          int totalSize = allClasses.size();
          int endIndex = Math.min(startIndex + pageSize, totalSize);
          if (startIndex > totalSize) {
            startIndex = totalSize;
          }
          List<Map<String, Object>> page = allClasses.subList(startIndex, endIndex);

          String nextCursor = null;
          if (endIndex < totalSize) {
            nextCursor = OpaqueCursorCodec.encodeV1(String.valueOf(endIndex));
          }

          return new PaginatedResult<>(page, nextCursor);
        });
  }

  private String readCStringFromMemory(Memory memory, Address addr, int maxLen) {
    try {
      StringBuilder sb = new StringBuilder();
      for (int i = 0; i < maxLen; i++) {
        byte b = memory.getByte(addr.add(i));
        if (b == 0) {
          break;
        }
        sb.append((char) (b & 0xff));
      }
      return sb.toString();
    } catch (Exception e) {
      return null;
    }
  }

  /**
   * Extracts enclosing method information from lambda RTTI entries using MDMang (Ghidra's full MSVC
   * demangler) rather than manual parsing. Lambda RTTI type descriptors encode the enclosing
   * function's mangled name in their scope chain — MDMang handles all MSVC special names
   * (constructors, operators, templates, etc.) per spec.
   */
  /**
   * Applies agent-defined custom tags by matching MSVC template patterns in the mangled name. Each
   * pattern matches entries containing {@code TemplateName@VClassName} and tags the extracted
   * class.
   */
  private void applyCustomTags(
      String mangledName,
      Map<String, String> templateToTag,
      Map<String, Set<String>> classCustomTags) {
    for (var entry : templateToTag.entrySet()) {
      String templatePattern = entry.getKey(); // e.g., "sp_ms_deleter@V"
      String tag = entry.getValue();

      int idx = mangledName.indexOf(templatePattern);
      if (idx < 0) continue;

      // Extract the template argument class name
      String after = mangledName.substring(idx + templatePattern.length());
      int end = after.indexOf("@@");
      if (end <= 0) end = after.indexOf('@');
      if (end <= 0) continue;

      String rawClassName = after.substring(0, end);
      // Use MDMang structured AST to extract clean class name from template arg
      String className = rawClassName;
      try {
        String asRtti = ".?AV" + rawClassName + "@@";
        MDMangGhidra mdm = new MDMangGhidra();
        mdm.setMangledSymbol(asRtti);
        MDParsableItem parsed = mdm.demangle();
        if (parsed instanceof mdemangler.object.MDObjectCPP cppObj) {
          String name = cppObj.getName();
          if (name != null && !name.isEmpty()) {
            className = name;
          }
        }
      } catch (Exception ignored) {
        // Use raw name
      }
      classCustomTags.computeIfAbsent(className, k -> new LinkedHashSet<>()).add(tag);
    }
  }

  /**
   * Extracts enclosing method information from lambda RTTI entries using MDMang's structured AST.
   * Uses MDObjectCPP.getName() and getQualification() for reliable method/class extraction instead
   * of parsing demangled strings — handles all MSVC special names (operators, constructors,
   * templates) correctly per spec.
   */
  private void processLambdaRttiEntry(
      String mangledName, Map<String, List<Map<String, String>>> methodMap) {

    if (!mangledName.contains("<lambda")) {
      return;
    }

    // Find "??" that starts the enclosing function (skip the leading ".?AV" prefix)
    int searchFrom = 4;
    int qqIdx = mangledName.indexOf("??", searchFrom);
    while (qqIdx > 0) {
      String fragment = mangledName.substring(qqIdx + 1);
      // Strip trailing "@" (lambda scope terminator) that isn't part of the function mangling
      if (fragment.endsWith("@")) {
        fragment = fragment.substring(0, fragment.length() - 1);
      }
      String enclosingMangled = "?" + fragment;

      try {
        MDMangGhidra mdm = new MDMangGhidra();
        mdm.setMangledSymbol(enclosingMangled);
        MDParsableItem item = mdm.demangle();
        if (item == null) {
          qqIdx = mangledName.indexOf("??", qqIdx + 2);
          continue;
        }

        // Use structured AST for reliable extraction
        if (item instanceof mdemangler.object.MDObjectCPP cppObj) {
          String methodName = cppObj.getName();
          mdemangler.naming.MDQualification qualification = cppObj.getQualification();

          if (methodName != null && !methodName.isEmpty() && qualification != null) {
            // First qualifier is the immediate class (inner→outer order)
            String className = null;
            for (var qualifier : qualification) {
              className = qualifier.toString();
              break; // first one is the class
            }

            if (className != null && !className.isEmpty()) {
              String demangled = item.toString();
              Map<String, String> methodInfo = new LinkedHashMap<>();
              methodInfo.put("name", methodName);
              methodInfo.put("class", className);
              if (demangled != null) {
                methodInfo.put("demangled", demangled);
              }
              methodMap.computeIfAbsent(className, k -> new ArrayList<>()).add(methodInfo);
              return;
            }
          }
        }

        // Fallback: if we got a parseable item but not MDObjectCPP, use toString
        String demangled = item.toString();
        if (demangled != null && !demangled.isBlank()) {
          // Last resort: basic string extraction for non-CPP objects
          return;
        }
      } catch (Exception ignored) {
        // MDMang couldn't parse this fragment — try next ??
      }

      qqIdx = mangledName.indexOf("??", qqIdx + 2);
    }
  }

  private String extractClassNameFromMangled(String mangledName) {
    String prefix = null;
    if (mangledName.startsWith(".?AV")) {
      prefix = ".?AV";
    } else if (mangledName.startsWith(".?AU")) {
      prefix = ".?AU";
    } else if (mangledName.startsWith(".?AT")) {
      prefix = ".?AT";
    } else if (mangledName.startsWith(".?AW4")) {
      prefix = ".?AW4";
    }
    if (prefix == null) {
      return null;
    }

    String rest = mangledName.substring(prefix.length());
    int atIdx = rest.indexOf('@');
    if (atIdx > 0) {
      return rest.substring(0, atIdx);
    }
    return rest;
  }

  private void enrichWithRtti4Data(
      Program program, Memory memory, Map<String, Map<String, Object>> classMap) {
    try {
      Address imageBase = program.getImageBase();
      if (imageBase == null) {
        return;
      }

      int pointerSize = program.getDefaultPointerSize();
      if (pointerSize != 8) {
        // RTTI4 self-pointer validation only works on x64 (signature==1 + pSelf field)
        // x86 RTTI4 has signature==0 and no pSelf field — skip enrichment for now
        return;
      }

      MemoryBlock rdataBlock = findRdataBlock(memory);
      if (rdataBlock == null) {
        return;
      }

      DataValidationOptions validationOptions = new DataValidationOptions();
      AddressFactory addressFactory = program.getAddressFactory();

      // Single-pass: scan .rdata for RTTI4 candidate structures, validate with Rtti4Model,
      // build a map from RTTI0 address → validated RTTI4 addresses for O(1) lookups.
      // Multiple RTTI4s per RTTI0 = multiple inheritance (one vtable per base with virtuals).
      Map<Address, List<Address>> rtti0ToRtti4s = new LinkedHashMap<>();

      // Search for uint32 value 1 (x64 RTTI4 signature) in .rdata
      AddressSetView rdataSet =
          program
              .getMemory()
              .getLoadedAndInitializedAddressSet()
              .intersectRange(rdataBlock.getStart(), rdataBlock.getEnd());

      SearchSettings settings = new SearchSettings();
      settings.withSearchFormat(SearchFormat.HEX);
      settings.withBigEndian(memory.isBigEndian());
      ByteMatcher matcher = SearchFormat.HEX.parse("01 00 00 00", settings);

      ProgramByteSource byteSource = new ProgramByteSource(program);
      MemorySearcher searcher = new MemorySearcher(byteSource, matcher, rdataSet, 100000);

      ListAccumulator<MemoryMatch> accumulator = new ListAccumulator<>();
      searcher.findAll(accumulator, TaskMonitor.DUMMY);

      for (MemoryMatch match : accumulator) {
        try {
          Address rtti4Start = match.getAddress();
          Rtti4Model rtti4 = new Rtti4Model(program, rtti4Start, validationOptions);
          rtti4.validate();
          Address rtti0Addr = rtti4.getRtti0Address();
          if (rtti0Addr != null) {
            rtti0ToRtti4s.computeIfAbsent(rtti0Addr, k -> new ArrayList<>()).add(rtti4Start);
          }
        } catch (Exception ignored) {
          // Not a valid RTTI4 — skip
        }
      }

      // Now enrich each class with O(1) map lookup
      for (Map.Entry<String, Map<String, Object>> entry : classMap.entrySet()) {
        Map<String, Object> classInfo = entry.getValue();
        String rtti0AddrStr = (String) classInfo.get("rtti0_address");
        if (rtti0AddrStr == null) {
          continue;
        }
        try {
          Address rtti0Addr = addressFactory.getAddress(rtti0AddrStr);
          if (rtti0Addr == null) {
            continue;
          }
          List<Address> rtti4Addrs = rtti0ToRtti4s.get(rtti0Addr);
          if (rtti4Addrs == null || rtti4Addrs.isEmpty()) {
            continue;
          }

          // Build vtable info for each RTTI4 (multiple = multiple inheritance)
          List<Map<String, Object>> vtables = new ArrayList<>();
          List<String> baseClasses = null;

          for (Address rtti4Addr : rtti4Addrs) {
            try {
              Rtti4Model rtti4 = new Rtti4Model(program, rtti4Addr, validationOptions);
              Map<String, Object> vtableInfo = new LinkedHashMap<>();
              vtableInfo.put("rtti4_address", rtti4Addr.toString());
              vtableInfo.put("vtable_offset", rtti4.getVbTableOffset());
              vtables.add(vtableInfo);

              // Get base classes from the first valid RTTI4
              if (baseClasses == null) {
                baseClasses = readBaseClassHierarchyViaModels(rtti4);
              }
            } catch (Exception ignored) {
            }
          }

          if (vtables.size() == 1) {
            // Single vtable — flatten for simplicity
            classInfo.put("rtti4_address", vtables.get(0).get("rtti4_address"));
            classInfo.put("vtable_offset", vtables.get(0).get("vtable_offset"));
          } else if (vtables.size() > 1) {
            // Multiple vtables — multiple inheritance
            classInfo.put("vtables", vtables);
          }

          if (baseClasses != null && !baseClasses.isEmpty()) {
            classInfo.put("base_classes", baseClasses);
          }
        } catch (Exception ignored) {
        }
      }
    } catch (Exception e) {
      // RTTI4 enrichment is optional; silently skip on failure
    }
  }

  private MemoryBlock findRdataBlock(Memory memory) {
    MemoryBlock block = memory.getBlock(".rdata");
    if (block != null) {
      return block;
    }
    for (MemoryBlock b : memory.getBlocks()) {
      if (b.getName().toLowerCase(Locale.ROOT).contains("rdata") && b.isInitialized()) {
        return b;
      }
    }
    return null;
  }

  private List<String> readBaseClassHierarchyViaModels(Rtti4Model rtti4) {
    try {
      // getBaseClassTypes() returns the full list including the class itself at index 0
      List<String> allTypes = rtti4.getBaseClassTypes();
      if (allTypes == null || allTypes.size() <= 1) {
        return null;
      }
      // Skip index 0 (the class itself); return only base classes
      return new ArrayList<>(allTypes.subList(1, allTypes.size()));
    } catch (Exception e) {
      return null;
    }
  }

  private byte[] intToLittleEndianBytes(int value) {
    ByteBuffer buffer = ByteBuffer.allocate(4);
    buffer.order(ByteOrder.LITTLE_ENDIAN);
    buffer.putInt(value);
    return buffer.array();
  }

  private byte[] addressToLittleEndianBytes(Address addr, int pointerSize) {
    long value = addr.getOffset();
    ByteBuffer buffer = ByteBuffer.allocate(pointerSize);
    buffer.order(ByteOrder.LITTLE_ENDIAN);
    if (pointerSize == 8) {
      buffer.putLong(value);
    } else {
      buffer.putInt((int) value);
    }
    return buffer.array();
  }

  private String bytesToHexString(byte[] bytes) {
    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < bytes.length; i++) {
      if (i > 0) {
        sb.append(' ');
      }
      sb.append(String.format("%02x", bytes[i] & 0xff));
    }
    return sb.toString();
  }

  private String classifyTypeKind(String mangledName) {
    if (mangledName.startsWith(".?AV")) {
      return "class";
    } else if (mangledName.startsWith(".?AU")) {
      return "struct";
    } else if (mangledName.startsWith(".?AT")) {
      return "union";
    } else if (mangledName.startsWith(".?AW4")) {
      return "enum";
    }
    return null;
  }

  // =================== Graph Action (Control Flow) ===================

  private Mono<Map<String, Object>> handleGraph(Program program, Map<String, Object> args) {
    return Mono.fromCallable(
        () -> {
          Function function = resolveFunction(program, args);
          return buildControlFlowGraph(program, function);
        });
  }

  private Map<String, Object> buildControlFlowGraph(Program program, Function function)
      throws Exception {
    BasicBlockModel blockModel = new BasicBlockModel(program);
    List<Map<String, Object>> nodes = new ArrayList<>();
    List<Map<String, Object>> edges = new ArrayList<>();
    Map<Address, Integer> blockIdMap = new LinkedHashMap<>();
    int nodeId = 0;

    // Iterate code blocks within the function body
    CodeBlockIterator blockIter =
        blockModel.getCodeBlocksContaining(function.getBody(), TaskMonitor.DUMMY);
    while (blockIter.hasNext()) {
      CodeBlock block = blockIter.next();
      Address startAddr = block.getMinAddress();
      Address endAddr = block.getMaxAddress();

      int id = nodeId++;
      blockIdMap.put(startAddr, id);

      Map<String, Object> node = new LinkedHashMap<>();
      node.put("id", id);
      node.put("start_address", startAddr.toString());
      node.put("end_address", endAddr.toString());
      node.put("label", block.getName());
      nodes.add(node);
    }

    // Build edges by iterating destinations
    blockIter = blockModel.getCodeBlocksContaining(function.getBody(), TaskMonitor.DUMMY);
    while (blockIter.hasNext()) {
      CodeBlock block = blockIter.next();
      Address sourceAddr = block.getMinAddress();
      Integer sourceId = blockIdMap.get(sourceAddr);
      if (sourceId == null) continue;

      CodeBlockReferenceIterator destIter = block.getDestinations(TaskMonitor.DUMMY);
      while (destIter.hasNext()) {
        CodeBlockReference ref = destIter.next();
        Address destAddr = ref.getDestinationAddress();
        Integer destId = blockIdMap.get(destAddr);
        if (destId == null) continue;

        Map<String, Object> edge = new LinkedHashMap<>();
        edge.put("source_id", sourceId);
        edge.put("target_id", destId);
        edge.put("flow_type", ref.getFlowType().getName());
        edges.add(edge);
      }
    }

    Map<String, Object> result = new LinkedHashMap<>();
    result.put("function_name", function.getName());
    result.put("function_address", function.getEntryPoint().toString());
    result.put("nodes", nodes);
    result.put("edges", edges);
    return result;
  }

  // =================== Call Graph Action ===================

  private Mono<Map<String, Object>> handleCallGraph(Program program, Map<String, Object> args) {
    return Mono.fromCallable(
        () -> {
          int depth = getBoundedIntArgumentOrDefault(args, ARG_DEPTH, DEFAULT_DEPTH, 1, MAX_DEPTH);
          String direction =
              getOptionalStringArgument(args, ARG_DIRECTION)
                  .orElse(DIRECTION_BOTH)
                  .toLowerCase(Locale.ROOT);

          if (!DIRECTION_CALLERS.equals(direction)
              && !DIRECTION_CALLEES.equals(direction)
              && !DIRECTION_BOTH.equals(direction)) {
            throw new GhidraMcpException(
                GhidraMcpError.invalid(
                    ARG_DIRECTION, direction, "must be one of: callers, callees, both"));
          }

          // If identifier provided, resolve specific function; otherwise use all functions
          Optional<Long> symbolIdOpt = getOptionalLongArgument(args, ARG_SYMBOL_ID);
          Optional<String> addressOpt = getOptionalStringArgument(args, ARG_ADDRESS);
          Optional<String> nameOpt = getOptionalStringArgument(args, ARG_NAME);

          int maxResults = getBoundedIntArgumentOrDefault(args, ARG_MAX_RESULTS, 50, 1, 500);

          List<Function> roots = new ArrayList<>();
          if (symbolIdOpt.isPresent() || addressOpt.isPresent() || nameOpt.isPresent()) {
            roots.add(resolveFunction(program, args));
          } else {
            FunctionManager fm = program.getFunctionManager();
            fm.getFunctions(true).forEach(roots::add);
          }

          return buildCallGraph(roots, depth, direction, maxResults);
        });
  }

  private Map<String, Object> buildCallGraph(
      List<Function> roots, int depth, String direction, int maxResults) {
    Set<String> visitedAddresses = new LinkedHashSet<>();
    Map<String, Map<String, Object>> nodeMap = new LinkedHashMap<>();
    List<Map<String, Object>> edges = new ArrayList<>();
    boolean truncated = false;

    Deque<FunctionDepth> queue = new ArrayDeque<>();
    for (Function root : roots) {
      String rootAddr = root.getEntryPoint().toString();
      if (visitedAddresses.add(rootAddr)) {
        nodeMap.put(rootAddr, createCallGraphNode(root));
        queue.add(new FunctionDepth(root, 0));
      }
      if (nodeMap.size() >= maxResults) {
        truncated = true;
        break;
      }
    }

    while (!queue.isEmpty() && !truncated) {
      FunctionDepth current = queue.poll();
      if (current.depth >= depth) continue;

      Function func = current.function;
      String funcAddr = func.getEntryPoint().toString();

      if (DIRECTION_CALLEES.equals(direction) || DIRECTION_BOTH.equals(direction)) {
        for (Function callee : func.getCalledFunctions(TaskMonitor.DUMMY)) {
          String calleeAddr = callee.getEntryPoint().toString();
          if (!nodeMap.containsKey(calleeAddr)) {
            if (nodeMap.size() >= maxResults) {
              truncated = true;
              break;
            }
            nodeMap.put(calleeAddr, createCallGraphNode(callee));
          }

          Map<String, Object> edge = new LinkedHashMap<>();
          edge.put("source_address", funcAddr);
          edge.put("target_address", calleeAddr);
          edge.put("type", "calls");
          edges.add(edge);

          if (visitedAddresses.add(calleeAddr)) {
            queue.add(new FunctionDepth(callee, current.depth + 1));
          }
        }
        if (truncated) continue;
      }

      if (DIRECTION_CALLERS.equals(direction) || DIRECTION_BOTH.equals(direction)) {
        for (Function caller : func.getCallingFunctions(TaskMonitor.DUMMY)) {
          String callerAddr = caller.getEntryPoint().toString();
          if (!nodeMap.containsKey(callerAddr)) {
            if (nodeMap.size() >= maxResults) {
              truncated = true;
              break;
            }
            nodeMap.put(callerAddr, createCallGraphNode(caller));
          }

          Map<String, Object> edge = new LinkedHashMap<>();
          edge.put("source_address", callerAddr);
          edge.put("target_address", funcAddr);
          edge.put("type", "calls");
          edges.add(edge);

          if (visitedAddresses.add(callerAddr)) {
            queue.add(new FunctionDepth(caller, current.depth + 1));
          }
        }
      }
    }

    Map<String, Object> result = new LinkedHashMap<>();
    result.put("nodes", new ArrayList<>(nodeMap.values()));
    result.put("edges", edges);
    result.put("truncated", truncated);
    return result;
  }

  private Map<String, Object> createCallGraphNode(Function function) {
    Map<String, Object> node = new LinkedHashMap<>();
    node.put("name", function.getName());
    node.put("address", function.getEntryPoint().toString());
    node.put("is_external", function.isExternal());
    return node;
  }

  private record FunctionDepth(Function function, int depth) {}

  // =================== Shared Function Resolution ===================

  private Function resolveFunction(Program program, Map<String, Object> args)
      throws GhidraMcpException {
    Optional<Long> symbolIdOpt = getOptionalLongArgument(args, ARG_SYMBOL_ID);
    Optional<String> addressOpt = getOptionalStringArgument(args, ARG_ADDRESS);
    Optional<String> nameOpt = getOptionalStringArgument(args, ARG_NAME);

    FunctionManager functionManager = program.getFunctionManager();

    if (symbolIdOpt.isPresent()) {
      long symbolId = symbolIdOpt.get();
      Symbol symbol = program.getSymbolTable().getSymbol(symbolId);
      if (symbol != null && symbol.getSymbolType() == SymbolType.FUNCTION) {
        Function function = functionManager.getFunctionAt(symbol.getAddress());
        if (function != null) return function;
      }
      throw new GhidraMcpException(GhidraMcpError.notFound("function", "symbol_id=" + symbolId));
    }

    if (addressOpt.isPresent()) {
      String addressStr = addressOpt.get();
      Address address = program.getAddressFactory().getAddress(addressStr);
      if (address != null) {
        Function function = getOrCreateFunction(program, address);
        if (function != null) return function;
      }
      throw new GhidraMcpException(GhidraMcpError.notFound("function", "address=" + addressStr));
    }

    if (nameOpt.isPresent()) {
      return SymbolLookupHelper.resolveFunction(program, nameOpt.get());
    }

    throw new GhidraMcpException(
        GhidraMcpError.validation()
            .errorCode(GhidraMcpError.ErrorCode.MISSING_REQUIRED_ARGUMENT)
            .message("At least one identifier required: symbol_id, address, or name")
            .build());
  }
}
