package com.themixednuts.tools;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.models.SymbolInfo;
import com.themixednuts.utils.GhidraMcpErrorUtils;
import com.themixednuts.utils.OpaqueCursorCodec;
import com.themixednuts.utils.PaginatedResult;
import com.themixednuts.utils.SymbolLookupHelper;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.draft7.SchemaBuilder;
import ghidra.app.cmd.label.AddLabelCmd;
import ghidra.app.cmd.label.RenameLabelCmd;
import ghidra.app.util.NamespaceUtils;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.util.exception.InvalidInputException;
import io.modelcontextprotocol.common.McpTransportContext;
import java.util.*;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import java.util.stream.Collectors;
import reactor.core.publisher.Mono;

@GhidraMcpTool(
    name = "Symbols",
    description =
        "Symbol lifecycle: list, get, create, update, and convert symbols, labels, and namespaces.",
    mcpName = "symbols",
    mcpDescription =
        """
         <use_case>
         Symbol lifecycle operations for reverse engineering workflows. List and browse symbols
         with filtering and pagination, get detailed symbol info by identifier, create labels and
         namespaces, rename symbols, update symbol properties, and convert namespaces to classes.
         </use_case>

         <important_notes>
         - Supports multiple symbol identification methods (name, address, symbol_id)
         - List mode supports regex filtering by name_pattern and cursor-based pagination
         - Get mode returns detailed SymbolInfo by symbol_id, address, or name (with wildcard support)
         - Handles namespace organization and symbol scoping
         - Validates symbol names according to Ghidra rules
         - Can convert existing namespaces to classes using the convert_to_class action
         - Namespace to class conversion requires the namespace to not be within a function
         - For deleting symbols, use the `delete` tool (action: symbol) instead
         - For browsing all symbols without filtering, use the ghidra://program/{name}/symbols resource
         </important_notes>

        <examples>
        List all symbols (first page):
        {
          "file_name": "program.exe",
          "action": "list"
        }

        List symbols matching regex pattern:
        {
          "file_name": "program.exe",
          "action": "list",
          "name_pattern": ".*decrypt.*"
        }

        Get a symbol by ID:
        {
          "file_name": "program.exe",
          "action": "get",
          "symbol_id": 12345
        }

        Get a symbol at an address:
        {
          "file_name": "program.exe",
          "action": "get",
          "address": "0x401000"
        }

        Get a symbol by name:
        {
          "file_name": "program.exe",
          "action": "get",
          "name": "main"
        }

        Create a label at a specific address:
        {
          "file_name": "program.exe",
          "action": "create",
          "symbol_type": "label",
          "address": "0x401000",
          "name": "main_entry"
        }

        Create a namespace:
        {
          "file_name": "program.exe",
          "action": "create",
          "symbol_type": "namespace",
          "name": "MyNamespace",
          "namespace": "ParentNamespace"
        }

        Rename a symbol by its current name:
        {
          "file_name": "program.exe",
          "action": "update",
          "current_name": "FUN_00401000",
          "new_name": "main_function"
        }

        Convert a namespace to a class:
        {
          "file_name": "program.exe",
          "action": "convert_to_class",
          "name": "AutoClass3",
          "namespace": "optional::parent::namespace"
        }
        </examples>
        """)
public class SymbolsTool extends BaseMcpTool {

  public static final String ARG_SYMBOL_TYPE = "symbol_type";
  public static final String ARG_SOURCE_TYPE = "source_type";

  private static final String ACTION_LIST = "list";
  private static final String ACTION_GET = "get";
  private static final String ACTION_CREATE = "create";
  private static final String ACTION_UPDATE = "update";
  private static final String ACTION_CONVERT_TO_CLASS = "convert_to_class";
  private static final String ACTION_CONVERT_TO_NAMESPACE = "convert_to_namespace";

  /**
   * Defines the JSON input schema for symbol operations.
   *
   * @return The JsonSchema defining the expected input arguments
   */
  @Override
  public JsonSchema schema() {
    var schemaRoot = createDraft7SchemaNode();

    // Global properties (always available)
    schemaRoot.property(
        ARG_FILE_NAME, SchemaBuilder.string(mapper).description("The name of the program file."));

    schemaRoot.property(
        ARG_ACTION,
        SchemaBuilder.string(mapper)
            .enumValues(
                ACTION_LIST,
                ACTION_GET,
                ACTION_CREATE,
                ACTION_UPDATE,
                ACTION_CONVERT_TO_CLASS,
                ACTION_CONVERT_TO_NAMESPACE)
            .description("Action to perform on symbols"));

    schemaRoot.property(
        ARG_NAMESPACE,
        SchemaBuilder.string(mapper)
            .description("Namespace for symbol organization (optional for all actions)"));

    schemaRoot.requiredProperty(ARG_FILE_NAME).requiredProperty(ARG_ACTION);

    // Add conditional requirements based on action (JSON Schema Draft 7)
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
                            .description("Optional regex pattern to filter symbol names"))
                    .property(
                        ARG_SYMBOL_TYPE,
                        SchemaBuilder.string(mapper)
                            .description(
                                "Filter by symbol type (e.g., FUNCTION, LABEL, PARAMETER,"
                                    + " LOCAL_VAR)"))
                    .property(
                        ARG_SOURCE_TYPE,
                        SchemaBuilder.string(mapper)
                            .description(
                                "Filter by source type (e.g., USER_DEFINED, IMPORTED, ANALYSIS)"))
                    .property(
                        ARG_CURSOR,
                        SchemaBuilder.string(mapper)
                            .description(
                                "Pagination cursor from previous request (format:"
                                    + " v1:<base64url_symbol_name>:<base64url_address>)"))
                    .property(
                        ARG_PAGE_SIZE,
                        SchemaBuilder.integer(mapper)
                            .description(
                                "Number of symbols to return per page (default: "
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
                            .description("Symbol ID to identify a specific symbol"))
                    .property(
                        ARG_ADDRESS,
                        SchemaBuilder.string(mapper)
                            .description("Memory address to identify a specific symbol")
                            .pattern("^(0x)?[0-9a-fA-F]+$"))
                    .property(
                        ARG_NAME,
                        SchemaBuilder.string(mapper)
                            .description("Symbol name for lookup (supports * and ? wildcards)"))
                    .anyOf(
                        SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_SYMBOL_ID),
                        SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_ADDRESS),
                        SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_NAME))),
        // action=create: requires symbol_type, name; allows address, namespace
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(ARG_ACTION, SchemaBuilder.string(mapper).constValue(ACTION_CREATE)),
                SchemaBuilder.objectDraft7(mapper)
                    .requiredProperty(ARG_SYMBOL_TYPE)
                    .requiredProperty(ARG_NAME)
                    .property(
                        ARG_SYMBOL_TYPE,
                        SchemaBuilder.string(mapper)
                            .enumValues(
                                "label",
                                "function",
                                "parameter",
                                "local_variable",
                                "global_variable",
                                "namespace",
                                "class")
                            .description("Type of symbol to create"))
                    .property(
                        ARG_NAME,
                        SchemaBuilder.string(mapper).description("Name for the new symbol"))
                    .property(
                        ARG_ADDRESS,
                        SchemaBuilder.string(mapper)
                            .description(
                                "Memory address (required for labels, optional for"
                                    + " class/namespace)")
                            .pattern("^(0x)?[0-9a-fA-F]+$"))),
        // symbol_type=label requires address (when creating labels)
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(ARG_SYMBOL_TYPE, SchemaBuilder.string(mapper).constValue("label")),
                SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_ADDRESS)),
        // action=update: requires new_name; allows symbol_id, current_name, address,
        // namespace
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(ARG_ACTION, SchemaBuilder.string(mapper).constValue(ACTION_UPDATE)),
                SchemaBuilder.objectDraft7(mapper)
                    .requiredProperty(ARG_NEW_NAME)
                    .property(
                        ARG_NEW_NAME,
                        SchemaBuilder.string(mapper).description("New name for the symbol"))
                    .property(
                        ARG_SYMBOL_ID,
                        SchemaBuilder.integer(mapper)
                            .description(
                                "Symbol ID for identification (use one of: symbol_id, current_name,"
                                    + " or address)"))
                    .property(
                        ARG_CURRENT_NAME,
                        SchemaBuilder.string(mapper)
                            .description(
                                "Current symbol name for identification (use one of: symbol_id,"
                                    + " current_name, or address)"))
                    .property(
                        ARG_ADDRESS,
                        SchemaBuilder.string(mapper)
                            .description(
                                "Address for symbol identification (use one of: symbol_id,"
                                    + " current_name, or address)")
                            .pattern("^(0x)?[0-9a-fA-F]+$"))),
        // action=convert_to_class: requires name; allows namespace
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_ACTION,
                        SchemaBuilder.string(mapper).constValue(ACTION_CONVERT_TO_CLASS)),
                SchemaBuilder.objectDraft7(mapper)
                    .requiredProperty(ARG_NAME)
                    .property(
                        ARG_NAME,
                        SchemaBuilder.string(mapper)
                            .description("Name of the namespace to convert to a class"))),
        // action=convert_to_namespace: requires name; allows namespace parent
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_ACTION,
                        SchemaBuilder.string(mapper).constValue(ACTION_CONVERT_TO_NAMESPACE)),
                SchemaBuilder.objectDraft7(mapper)
                    .requiredProperty(ARG_NAME)
                    .property(
                        ARG_NAME,
                        SchemaBuilder.string(mapper)
                            .description("Name of the class to convert back to a namespace"))));

    return schemaRoot.build();
  }

  /**
   * Executes the symbol operation.
   *
   * @param context The MCP transport context
   * @param args The tool arguments containing file_name, action, and action-specific parameters
   * @param tool The Ghidra PluginTool context
   * @return A Mono emitting the result of the symbol operation
   */
  @Override
  public Mono<? extends Object> execute(
      McpTransportContext context, Map<String, Object> args, PluginTool tool) {
    GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);

    return getProgram(args, tool)
        .flatMap(
            program -> {
              String action = getRequiredStringArgument(args, ARG_ACTION);

              return switch (action.toLowerCase(Locale.ROOT)) {
                // Aliases for name-based lookup; canonical form is `list` with a name_pattern.
                case ACTION_LIST, "find", "resolve", "search" -> handleList(program, args);
                case ACTION_GET -> handleGet(program, args);
                case ACTION_CREATE -> handleCreate(program, args, annotation);
                case ACTION_UPDATE -> handleUpdate(program, args, annotation);
                case ACTION_CONVERT_TO_CLASS -> handleConvertToClass(program, args, annotation);
                case ACTION_CONVERT_TO_NAMESPACE ->
                    handleConvertToNamespace(program, args, annotation);
                default -> {
                  Map<String, String> aliases =
                      Map.of(
                          "rename", ACTION_UPDATE,
                          "delete", "use `delete` tool",
                          "remove", "use `delete` tool",
                          "label", ACTION_CREATE,
                          "demangle", "use `analyze` (action: demangle)");
                  GhidraMcpError error =
                      GhidraMcpErrorUtils.invalidAction(
                          action,
                          List.of(
                              ACTION_LIST,
                              ACTION_GET,
                              ACTION_CREATE,
                              ACTION_UPDATE,
                              ACTION_CONVERT_TO_CLASS,
                              ACTION_CONVERT_TO_NAMESPACE),
                          aliases);
                  yield Mono.error(new GhidraMcpException(error));
                }
              };
            });
  }

  // ---------------------------------------------------------------------------
  // action = list
  // ---------------------------------------------------------------------------

  private Mono<PaginatedResult<SymbolInfo>> handleList(Program program, Map<String, Object> args) {
    return Mono.fromCallable(() -> listSymbols(program, args));
  }

  private PaginatedResult<SymbolInfo> listSymbols(Program program, Map<String, Object> args)
      throws GhidraMcpException {
    SymbolTable symbolTable = program.getSymbolTable();
    int pageSize = getPageSizeArgument(args, DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT);

    Optional<String> namePatternOpt = getOptionalStringArgument(args, ARG_NAME_PATTERN);
    Optional<String> symbolTypeOpt = getOptionalStringArgument(args, ARG_SYMBOL_TYPE);
    Optional<String> sourceTypeOpt = getOptionalStringArgument(args, ARG_SOURCE_TYPE);
    Optional<String> namespaceOpt = getOptionalStringArgument(args, ARG_NAMESPACE);
    Optional<String> cursorOpt = getOptionalStringArgument(args, ARG_CURSOR);

    SymbolType symbolTypeFilter = symbolTypeOpt.map(this::parseSymbolType).orElse(null);

    SymbolCursorPosition cursor =
        cursorOpt.map(value -> parseSymbolCursor(program, value)).orElse(null);

    Pattern namePattern = null;
    if (namePatternOpt.isPresent()) {
      try {
        namePattern = Pattern.compile(namePatternOpt.get());
      } catch (PatternSyntaxException e) {
        throw new GhidraMcpException(
            GhidraMcpError.invalid(ARG_NAME_PATTERN, namePatternOpt.get(), e.getMessage()));
      }
    }

    String normalizedSourceType = sourceTypeOpt.map(String::toLowerCase).orElse(null);
    String normalizedNamespace = namespaceOpt.map(String::toLowerCase).orElse(null);

    // Stream-select the next pageSize+1 candidates instead of materializing every match.
    // We keep at most pageSize+1 Symbols in a max-heap ordered by (name, address); when the
    // heap overflows we evict the largest. This avoids O(n log n) sorting on multi-million-
    // symbol tables when only a single page is needed.
    int heapCapacity = pageSize + 1;
    Comparator<Symbol> symbolOrder =
        Comparator.<Symbol, String>comparing(Symbol::getName, String.CASE_INSENSITIVE_ORDER)
            .thenComparing(s -> s.getAddress().toString(), String.CASE_INSENSITIVE_ORDER);
    PriorityQueue<Symbol> heap = new PriorityQueue<>(heapCapacity, symbolOrder.reversed());

    boolean cursorMatched = cursor == null;
    SymbolIterator symbolIterator = symbolTable.getAllSymbols(true);
    while (symbolIterator.hasNext()) {
      Symbol symbol = symbolIterator.next();

      if (symbolTypeFilter != null && symbol.getSymbolType() != symbolTypeFilter) {
        continue;
      }

      if (normalizedSourceType != null
          && !symbol.getSource().toString().toLowerCase().equals(normalizedSourceType)) {
        continue;
      }

      if (normalizedNamespace != null
          && !symbol
              .getParentNamespace()
              .getName(false)
              .toLowerCase()
              .equals(normalizedNamespace)) {
        continue;
      }

      if (namePattern != null && !namePattern.matcher(symbol.getName()).matches()) {
        continue;
      }

      if (cursor != null) {
        int cmp = compareCursor(symbol, cursor);
        if (cmp == 0) {
          cursorMatched = true;
          continue;
        }
        if (cmp < 0) {
          continue;
        }
      }

      // Heap admission: keep only the smallest pageSize+1 elements seen so far.
      if (heap.size() < heapCapacity) {
        heap.offer(symbol);
      } else if (symbolOrder.compare(symbol, heap.peek()) < 0) {
        heap.poll();
        heap.offer(symbol);
      }
    }

    if (!cursorMatched) {
      throw new GhidraMcpException(
          GhidraMcpError.invalid(
              ARG_CURSOR,
              cursor.toCursorString(),
              "cursor is invalid or no longer present in this symbol listing"));
    }

    List<Symbol> ordered = new ArrayList<>(heap);
    ordered.sort(symbolOrder);

    boolean hasMore = ordered.size() > pageSize;
    List<Symbol> pageSymbols = hasMore ? ordered.subList(0, pageSize) : ordered;
    List<SymbolInfo> results = new ArrayList<>(pageSymbols.size());
    for (Symbol s : pageSymbols) {
      results.add(new SymbolInfo(s));
    }

    String nextCursor = null;
    if (hasMore && !results.isEmpty()) {
      SymbolInfo lastItem = results.get(results.size() - 1);
      nextCursor = encodeSymbolCursor(lastItem.getName(), lastItem.getAddress());
    }

    return new PaginatedResult<>(results, nextCursor);
  }

  private static int compareCursor(Symbol symbol, SymbolCursorPosition cursor) {
    int byName = String.CASE_INSENSITIVE_ORDER.compare(symbol.getName(), cursor.name);
    if (byName != 0) {
      return byName;
    }
    return String.CASE_INSENSITIVE_ORDER.compare(symbol.getAddress().toString(), cursor.address);
  }

  private SymbolType parseSymbolType(String typeStr) {
    if (typeStr == null) {
      return null;
    }

    return switch (typeStr.toUpperCase(Locale.ROOT)) {
      case "NAMESPACE" -> SymbolType.NAMESPACE;
      case "CLASS" -> SymbolType.CLASS;
      case "FUNCTION" -> SymbolType.FUNCTION;
      case "LABEL" -> SymbolType.LABEL;
      case "PARAMETER" -> SymbolType.PARAMETER;
      case "LOCAL_VAR" -> SymbolType.LOCAL_VAR;
      case "GLOBAL_VAR" -> SymbolType.GLOBAL_VAR;
      case "GLOBAL" -> SymbolType.GLOBAL;
      case "LIBRARY" -> SymbolType.LIBRARY;
      default ->
          throw new GhidraMcpException(
              GhidraMcpError.invalid(
                  ARG_SYMBOL_TYPE,
                  typeStr,
                  "must be one of: NAMESPACE, CLASS, FUNCTION, LABEL, PARAMETER, LOCAL_VAR,"
                      + " GLOBAL_VAR, GLOBAL, LIBRARY"));
    };
  }

  private SymbolCursorPosition parseSymbolCursor(Program program, String cursorValue) {
    List<String> parts =
        decodeOpaqueCursorV1(
            cursorValue, 2, ARG_CURSOR, "v1:<base64url_symbol_name>:<base64url_address>");
    String decodedName = parts.get(0);
    String decodedAddress = parts.get(1);

    if (program.getAddressFactory().getAddress(decodedAddress) == null) {
      throw new GhidraMcpException(
          GhidraMcpError.invalid(ARG_CURSOR, cursorValue, "contains an invalid address component"));
    }

    return new SymbolCursorPosition(decodedName, decodedAddress, cursorValue);
  }

  private String encodeSymbolCursor(String symbolName, String address) {
    return OpaqueCursorCodec.encodeV1(symbolName, address);
  }

  private static final class SymbolCursorPosition {
    private final String name;
    private final String address;
    private final String rawCursor;

    private SymbolCursorPosition(String name, String address, String rawCursor) {
      this.name = name;
      this.address = address;
      this.rawCursor = rawCursor;
    }

    private String toCursorString() {
      return rawCursor;
    }
  }

  // ---------------------------------------------------------------------------
  // action = get
  // ---------------------------------------------------------------------------

  private Mono<? extends Object> handleGet(Program program, Map<String, Object> args) {
    return Mono.fromCallable(
        () -> {
          SymbolTable symbolTable = program.getSymbolTable();

          // Apply precedence: symbol_id > address > name
          if (args.containsKey(ARG_SYMBOL_ID)) {
            Object rawSymbolId = args.get(ARG_SYMBOL_ID);
            Long symbolId =
                getOptionalLongArgument(args, ARG_SYMBOL_ID)
                    .orElseThrow(
                        () ->
                            new GhidraMcpException(
                                GhidraMcpError.invalid(
                                    ARG_SYMBOL_ID,
                                    rawSymbolId,
                                    "must be an integer symbol identifier")));
            Symbol symbol = symbolTable.getSymbol(symbolId);
            if (symbol != null) {
              return new SymbolInfo(symbol);
            }
            throw new GhidraMcpException(
                GhidraMcpError.notFound("symbol", "symbol_id", symbolId.toString()));
          } else if (args.containsKey(ARG_ADDRESS)) {
            String address = getOptionalStringArgument(args, ARG_ADDRESS).orElse(null);
            if (address != null && !address.trim().isEmpty()) {
              try {
                Address addr = program.getAddressFactory().getAddress(address);
                if (addr != null) {
                  Symbol[] symbols = symbolTable.getSymbols(addr);
                  if (symbols.length > 0) {
                    return new SymbolInfo(symbols[0]);
                  }
                }
                throw new GhidraMcpException(GhidraMcpError.notFound("symbol", "address", address));
              } catch (GhidraMcpException e) {
                throw e;
              } catch (Exception e) {
                throw new GhidraMcpException(GhidraMcpError.parse("address", address));
              }
            }
            throw new GhidraMcpException(GhidraMcpError.missing("symbol_id, address, or name"));
          } else if (args.containsKey(ARG_NAME)) {
            String name = getOptionalStringArgument(args, ARG_NAME).orElse(null);
            if (name != null && !name.trim().isEmpty()) {
              return new SymbolInfo(SymbolLookupHelper.resolveSymbol(program, name));
            }
            throw new GhidraMcpException(GhidraMcpError.missing("symbol_id, address, or name"));
          } else {
            throw new GhidraMcpException(GhidraMcpError.missing("symbol_id, address, or name"));
          }
        });
  }

  // ---------------------------------------------------------------------------
  // action = create
  // ---------------------------------------------------------------------------

  private Mono<? extends Object> handleCreate(
      Program program, Map<String, Object> args, GhidraMcpTool annotation) {
    String symbolType = getRequiredStringArgument(args, ARG_SYMBOL_TYPE);
    String name = getRequiredStringArgument(args, ARG_NAME);
    Optional<String> namespaceOpt = getOptionalStringArgument(args, ARG_NAMESPACE);

    // Address is optional for class and namespace symbols (they use NO_ADDRESS)
    String addressStr =
        (symbolType.equalsIgnoreCase("class") || symbolType.equalsIgnoreCase("namespace"))
            ? null
            : getRequiredStringArgument(args, ARG_ADDRESS);

    return executeInTransaction(
        program,
        "MCP - Create " + symbolType + " " + name,
        () -> {
          // Validate symbol name
          try {
            SymbolUtilities.validateName(name);
          } catch (InvalidInputException e) {
            throw new GhidraMcpException(GhidraMcpError.invalid(ARG_NAME, name, e.getMessage()));
          }

          // Parse address (skip for class symbols)
          Address address = null;
          if (addressStr != null) {
            try {
              address = program.getAddressFactory().getAddress(addressStr);
              if (address == null) {
                throw new IllegalArgumentException("Invalid address format");
              }
            } catch (Exception e) {
              throw new GhidraMcpException(GhidraMcpError.parse("address", addressStr));
            }
          }

          // Create symbol based on type
          return switch (symbolType.toLowerCase()) {
            case "label" -> createLabel(program, name, address, namespaceOpt, annotation);
            case "class" -> createClass(program, name, namespaceOpt, annotation);
            case "namespace" -> createNamespace(program, name, namespaceOpt, annotation);
            default -> {
              throw new GhidraMcpException(
                  GhidraMcpError.invalid(
                      ARG_SYMBOL_TYPE, symbolType, "Unsupported symbol type for creation"));
            }
          };
        });
  }

  private Object createLabel(
      Program program,
      String name,
      Address address,
      Optional<String> namespaceOpt,
      GhidraMcpTool annotation)
      throws GhidraMcpException {
    AddLabelCmd cmd = new AddLabelCmd(address, name, SourceType.USER_DEFINED);

    if (!cmd.applyTo(program)) {
      throw new GhidraMcpException(
          GhidraMcpError.failed(
              "create label", cmd.getStatusMsg() + " - check if label already exists at address"));
    }

    // Get the created symbol to return its info
    Symbol[] symbols = program.getSymbolTable().getSymbols(address);
    Symbol createdSymbol = null;
    for (Symbol symbol : symbols) {
      if (symbol.getName().equals(name)) {
        createdSymbol = symbol;
        break;
      }
    }

    if (createdSymbol == null) {
      // This shouldn't happen if creation succeeded, but handle it
      throw new GhidraMcpException(
          GhidraMcpError.internal("Symbol created but could not be retrieved"));
    }

    return new SymbolInfo(createdSymbol);
  }

  private Object createClass(
      Program program, String name, Optional<String> namespaceOpt, GhidraMcpTool annotation)
      throws GhidraMcpException {
    SymbolTable symbolTable = program.getSymbolTable();

    // Support hierarchical class creation with namespace path
    try {
      Namespace parentNamespace;
      if (namespaceOpt.isPresent()) {
        parentNamespace = resolveTargetNamespace(symbolTable, program, namespaceOpt);
      } else {
        parentNamespace = program.getGlobalNamespace();
      }

      // Use NamespaceUtils for clean hierarchical class creation:
      // 1. Create full namespace hierarchy (even for simple names)
      // 2. Convert the final namespace to a class
      Namespace namespace =
          NamespaceUtils.createNamespaceHierarchy(
              name, parentNamespace, program, SourceType.USER_DEFINED);

      // Convert the namespace to a class
      Namespace classNamespace = NamespaceUtils.convertNamespaceToClass(namespace);
      Symbol classSymbol = classNamespace.getSymbol();
      return new SymbolInfo(classSymbol);
    } catch (InvalidInputException e) {
      throw new GhidraMcpException(
          GhidraMcpError.invalid(
              ARG_NAME,
              name,
              "Invalid class name: " + e.getMessage() + ". Use '::' to create nested classes."));
    } catch (GhidraMcpException e) {
      throw e;
    } catch (Exception e) {
      throw new GhidraMcpException(
          GhidraMcpError.failed(
              "create class", e.getMessage() + " - check if class already exists"));
    }
  }

  private Object createNamespace(
      Program program, String name, Optional<String> namespaceOpt, GhidraMcpTool annotation)
      throws GhidraMcpException {
    SymbolTable symbolTable = program.getSymbolTable();

    // Support hierarchical namespace creation (e.g., "Outer::Middle::Inner")
    try {
      Namespace parentNamespace;
      if (namespaceOpt.isPresent()) {
        parentNamespace = resolveTargetNamespace(symbolTable, program, namespaceOpt);
      } else {
        parentNamespace = program.getGlobalNamespace();
      }

      // Use NamespaceUtils to create namespace hierarchy if needed
      Namespace namespace =
          NamespaceUtils.createNamespaceHierarchy(
              name, parentNamespace, program, SourceType.USER_DEFINED);

      Symbol namespaceSymbol = namespace.getSymbol();
      return new SymbolInfo(namespaceSymbol);
    } catch (InvalidInputException e) {
      throw new GhidraMcpException(
          GhidraMcpError.invalid(
              ARG_NAME,
              name,
              "Invalid namespace name: "
                  + e.getMessage()
                  + ". Use '::' to create nested namespaces."));
    } catch (GhidraMcpException e) {
      throw e;
    } catch (Exception e) {
      throw new GhidraMcpException(
          GhidraMcpError.failed(
              "create namespace", e.getMessage() + " - check if namespace already exists"));
    }
  }

  // ---------------------------------------------------------------------------
  // action = update
  // ---------------------------------------------------------------------------

  private Mono<? extends Object> handleUpdate(
      Program program, Map<String, Object> args, GhidraMcpTool annotation) {
    Optional<Long> symbolIdOpt = getOptionalLongArgument(args, ARG_SYMBOL_ID);
    Optional<String> currentNameOpt = getOptionalStringArgument(args, ARG_CURRENT_NAME);
    Optional<String> addressOpt = getOptionalStringArgument(args, ARG_ADDRESS);
    Optional<String> namespaceOpt = getOptionalStringArgument(args, ARG_NAMESPACE);
    String newName = getRequiredStringArgument(args, ARG_NEW_NAME);

    boolean hasSymbolId = symbolIdOpt.isPresent();
    boolean hasCurrentName = currentNameOpt.filter(name -> !name.isBlank()).isPresent();
    boolean hasAddress = addressOpt.filter(addr -> !addr.isBlank()).isPresent();

    // Count provided identifiers
    int identifierCount = (hasSymbolId ? 1 : 0) + (hasCurrentName ? 1 : 0) + (hasAddress ? 1 : 0);

    if (identifierCount > 1) {
      return Mono.error(multipleIdentifierError(symbolIdOpt, currentNameOpt, addressOpt));
    }

    if (identifierCount == 0) {
      return Mono.error(missingIdentifierError());
    }

    return executeInTransaction(
        program,
        "MCP - Rename Symbol",
        () -> {
          SymbolTable symbolTable = program.getSymbolTable();
          SymbolResolveResult resolveResult =
              resolveSymbolForRename(
                  symbolTable,
                  program,
                  args,
                  symbolIdOpt,
                  currentNameOpt,
                  addressOpt,
                  namespaceOpt);

          // Check if the new name already exists in the target namespace
          SymbolIterator existingSymbolIterator = symbolTable.getSymbolIterator(newName, true);
          List<Symbol> existingSymbols = new ArrayList<>();
          while (existingSymbolIterator.hasNext()) {
            Symbol existingSymbol = existingSymbolIterator.next();
            if (existingSymbol.getParentNamespace().equals(resolveResult.targetNamespace())) {
              existingSymbols.add(existingSymbol);
            }
          }

          // If there's already a symbol with the same name in the target namespace,
          // provide detailed info
          if (!existingSymbols.isEmpty()) {
            List<String> conflictingNames =
                existingSymbols.stream()
                    .map(s -> s.getName() + " (ID=" + s.getID() + ", addr=" + s.getAddress() + ")")
                    .collect(Collectors.toList());
            throw new GhidraMcpException(
                GhidraMcpError.conflict(
                    "Symbol '"
                        + newName
                        + "' already exists in namespace '"
                        + resolveResult.targetNamespace().getName(false)
                        + "': "
                        + conflictingNames));
          }

          RenameLabelCmd cmd =
              new RenameLabelCmd(
                  resolveResult.symbol(),
                  newName,
                  resolveResult.targetNamespace(),
                  SourceType.USER_DEFINED);
          if (!cmd.applyTo(program)) {
            throw new GhidraMcpException(
                GhidraMcpError.failed("rename symbol", cmd.getStatusMsg()));
          }

          // Return the updated symbol info
          return new SymbolInfo(resolveResult.symbol());
        });
  }

  private SymbolResolveResult resolveSymbolForRename(
      SymbolTable symbolTable,
      Program program,
      Map<String, Object> args,
      Optional<Long> symbolIdOpt,
      Optional<String> currentNameOpt,
      Optional<String> addressOpt,
      Optional<String> namespaceOpt)
      throws GhidraMcpException {

    if (symbolIdOpt.isPresent()) {
      Symbol symbol = symbolTable.getSymbol(symbolIdOpt.get());
      if (symbol == null) {
        throw new GhidraMcpException(GhidraMcpError.notFound("symbol", "id=" + symbolIdOpt.get()));
      }

      Namespace targetNamespace = resolveTargetNamespace(symbolTable, program, namespaceOpt);
      return new SymbolResolveResult(symbol, symbol.getName(false), targetNamespace);
    }

    if (addressOpt.isPresent()) {
      try {
        Address address = program.getAddressFactory().getAddress(addressOpt.get());
        if (address == null) {
          throw new IllegalArgumentException("Invalid address format: " + addressOpt.get());
        }

        Symbol primarySymbol = symbolTable.getPrimarySymbol(address);
        if (primarySymbol == null) {
          throw new GhidraMcpException(
              GhidraMcpError.notFound("symbol", "address=" + addressOpt.get()));
        }

        Namespace targetNamespace = resolveTargetNamespace(symbolTable, program, namespaceOpt);
        return new SymbolResolveResult(
            primarySymbol, primarySymbol.getName(false), targetNamespace);
      } catch (GhidraMcpException e) {
        throw e;
      } catch (Exception e) {
        throw new GhidraMcpException(GhidraMcpError.parse("address", addressOpt.get()));
      }
    }

    String currentName = currentNameOpt.map(String::trim).orElse("");

    Symbol resolvedSymbol = SymbolLookupHelper.resolveSymbol(program, currentName);

    // Use explicitly provided namespace if given, otherwise keep the symbol's current namespace
    Namespace targetNamespace =
        namespaceOpt.isPresent()
            ? resolveTargetNamespace(symbolTable, program, namespaceOpt)
            : resolvedSymbol.getParentNamespace();

    return new SymbolResolveResult(resolvedSymbol, resolvedSymbol.getName(), targetNamespace);
  }

  private Namespace resolveTargetNamespace(
      SymbolTable symbolTable, Program program, Optional<String> namespaceOpt)
      throws GhidraMcpException {
    if (namespaceOpt.isEmpty()
        || namespaceOpt.get().isBlank()
        || namespaceOpt.get().equalsIgnoreCase("global")) {
      return program.getGlobalNamespace();
    }

    String namespacePath = namespaceOpt.get();

    // Try to resolve namespace by path (supports hierarchical paths like
    // "Outer::Inner")
    try {
      List<Namespace> namespaces =
          NamespaceUtils.getNamespaceByPath(program, program.getGlobalNamespace(), namespacePath);

      if (namespaces != null && !namespaces.isEmpty()) {
        return namespaces.get(0);
      }
    } catch (Exception e) {
      // Fall through to auto-create
    }

    // Auto-create the namespace hierarchy if it doesn't exist.
    // Create the leaf as a class namespace (common for C++ RE workflows).
    try {
      Namespace created =
          NamespaceUtils.createNamespaceHierarchy(
              namespacePath, program.getGlobalNamespace(), program, SourceType.USER_DEFINED);
      // Convert the leaf namespace to a class (agents typically work with classes)
      if (created != null && !(created instanceof ghidra.program.model.listing.GhidraClass)) {
        try {
          created = NamespaceUtils.convertNamespaceToClass(created);
        } catch (Exception ignored) {
          // Conversion failed — return as namespace, still usable
        }
      }
      return created;
    } catch (Exception e) {
      throw new GhidraMcpException(
          GhidraMcpError.failed("create namespace", namespacePath + ": " + e.getMessage()));
    }
  }

  private GhidraMcpException multipleIdentifierError(
      Optional<Long> symbolIdOpt, Optional<String> currentNameOpt, Optional<String> addressOpt) {
    List<String> providedIdentifiers = new ArrayList<>();

    if (symbolIdOpt.isPresent()) {
      providedIdentifiers.add(ARG_SYMBOL_ID + "=" + symbolIdOpt.get());
    }
    if (currentNameOpt.filter(name -> !name.isBlank()).isPresent()) {
      providedIdentifiers.add(ARG_CURRENT_NAME + "=" + currentNameOpt.get());
    }
    if (addressOpt.filter(addr -> !addr.isBlank()).isPresent()) {
      providedIdentifiers.add(ARG_ADDRESS + "=" + addressOpt.get());
    }

    return new GhidraMcpException(
        GhidraMcpError.conflict(
            "Provide only one identifier, but got: " + String.join(", ", providedIdentifiers)));
  }

  private GhidraMcpException missingIdentifierError() {
    return new GhidraMcpException(
        GhidraMcpError.missing(
            "symbol_id, current_name, or address (provide one to identify the symbol)"));
  }

  private record SymbolResolveResult(
      Symbol symbol, String originalDisplayName, Namespace targetNamespace) {}

  // ---------------------------------------------------------------------------
  // action = convert_to_class
  // ---------------------------------------------------------------------------

  private Mono<? extends Object> handleConvertToClass(
      Program program, Map<String, Object> args, GhidraMcpTool annotation) {
    String name = getRequiredStringArgument(args, ARG_NAME);
    Optional<String> namespaceOpt = getOptionalStringArgument(args, ARG_NAMESPACE);

    return executeInTransaction(
        program,
        "MCP - Convert Namespace to Class: " + name,
        () -> {
          SymbolTable symbolTable = program.getSymbolTable();

          Namespace parentNamespace;
          if (namespaceOpt.isPresent()) {
            parentNamespace = resolveTargetNamespace(symbolTable, program, namespaceOpt);
          } else {
            parentNamespace = program.getGlobalNamespace();
          }

          Namespace namespaceToConvert =
              NamespaceUtils.getFirstNonFunctionNamespace(parentNamespace, name, program);

          if (namespaceToConvert == null) {
            throw new GhidraMcpException(
                GhidraMcpError.notFound(
                    "namespace", name + " (in parent: " + parentNamespace.getName() + ")"));
          }

          try {
            Namespace classNamespace = NamespaceUtils.convertNamespaceToClass(namespaceToConvert);
            Symbol classSymbol = classNamespace.getSymbol();
            return new SymbolInfo(classSymbol);
          } catch (InvalidInputException e) {
            throw new GhidraMcpException(
                GhidraMcpError.invalid(
                    ARG_NAME,
                    name,
                    "Cannot convert namespace to class: "
                        + e.getMessage()
                        + ". Namespace cannot be within a function."));
          }
        });
  }

  // ---------------------------------------------------------------------------
  // action = convert_to_namespace
  // ---------------------------------------------------------------------------

  private Mono<? extends Object> handleConvertToNamespace(
      Program program, Map<String, Object> args, GhidraMcpTool annotation) {
    String name = getRequiredStringArgument(args, ARG_NAME);
    Optional<String> namespaceOpt = getOptionalStringArgument(args, ARG_NAMESPACE);

    return executeInTransaction(
        program,
        "MCP - Convert Class to Namespace: " + name,
        () -> {
          SymbolTable symbolTable = program.getSymbolTable();

          Namespace parentNamespace;
          if (namespaceOpt.isPresent()) {
            parentNamespace = resolveTargetNamespace(symbolTable, program, namespaceOpt);
          } else {
            parentNamespace = program.getGlobalNamespace();
          }

          Namespace target =
              NamespaceUtils.getFirstNonFunctionNamespace(parentNamespace, name, program);

          if (target == null) {
            throw new GhidraMcpException(
                GhidraMcpError.notFound(
                    "class", name + " (in parent: " + parentNamespace.getName() + ")"));
          }

          if (!(target instanceof ghidra.program.model.listing.GhidraClass)) {
            throw new GhidraMcpException(
                GhidraMcpError.invalid(ARG_NAME, name, "is already a namespace, not a class"));
          }

          try {
            Namespace ns =
                program
                    .getSymbolTable()
                    .createNameSpace(
                        target.getParentNamespace(), target.getName(), SourceType.USER_DEFINED);
            return new SymbolInfo(ns.getSymbol());
          } catch (Exception e) {
            throw new GhidraMcpException(
                GhidraMcpError.failed("convert class to namespace", name + ": " + e.getMessage()));
          }
        });
  }
}
