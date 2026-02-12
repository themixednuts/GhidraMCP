package com.themixednuts.tools;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.models.SymbolInfo;
import com.themixednuts.utils.PaginatedResult;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.google.SchemaBuilder;
import com.themixednuts.utils.jsonschema.google.SchemaBuilder.IObjectSchemaBuilder;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import io.modelcontextprotocol.common.McpTransportContext;
import java.util.*;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import reactor.core.publisher.Mono;

@GhidraMcpTool(
    name = "Read Symbols",
    description =
        "Read a single symbol or list symbols in a Ghidra program with pagination and filtering options.",
    mcpName = "read_symbols",
    mcpDescription =
        """
        <use_case>
        Read a single symbol by identifier (symbol_id, address, name) or browse/list symbols
        in Ghidra programs with optional filtering by name pattern, symbol type, source type,
        and namespace. Returns detailed symbol information including addresses, types, and metadata.
        </use_case>

        <important_notes>
        - Supports two modes: single symbol read (provide symbol_id/address/name) or list mode (no identifiers)
        - When reading a single symbol, returns SymbolInfo object directly
        - When listing symbols, returns paginated results with cursor support
        - Supports filtering by name patterns, symbol types, and namespaces in list mode
        - Symbols are sorted by name for consistent ordering
        - Name-based lookup supports regex matching with disambiguation
        </important_notes>

        <examples>
        Read a single symbol by ID:
        {
          "file_name": "program.exe",
          "symbol_id": 12345
        }

        Read a single symbol at an address:
        {
          "file_name": "program.exe",
          "address": "0x401000"
        }

        Read a single symbol by name:
        {
          "file_name": "program.exe",
          "name": "main"
        }

        List all symbols (first page):
        {
          "file_name": "program.exe"
        }

        List symbols with name filter:
        {
          "file_name": "program.exe",
          "name_filter": "decrypt"
        }

        Get next page of results:
        {
          "file_name": "program.exe",
          "cursor": "main:0x401000"
        }
        </examples>
        """)
public class ReadSymbolsTool extends BaseMcpTool {

  public static final String ARG_NAME_FILTER = "name_filter";
  public static final String ARG_SYMBOL_TYPE = "symbol_type";
  public static final String ARG_SOURCE_TYPE = "source_type";

  @Override
  public JsonSchema schema() {
    IObjectSchemaBuilder schemaRoot = createBaseSchemaNode();

    schemaRoot.property(
        ARG_FILE_NAME, SchemaBuilder.string(mapper).description("The name of the program file."));

    schemaRoot.property(
        ARG_SYMBOL_ID,
        SchemaBuilder.integer(mapper)
            .description("Symbol ID to identify a specific symbol (single read mode)"));

    schemaRoot.property(
        ARG_ADDRESS,
        SchemaBuilder.string(mapper)
            .description("Memory address to identify a specific symbol (single read mode)")
            .pattern("^(0x)?[0-9a-fA-F]+$"));

    schemaRoot.property(
        ARG_NAME,
        SchemaBuilder.string(mapper)
            .description("Symbol name for single symbol lookup (supports regex matching)"));

    schemaRoot.property(
        ARG_NAME_FILTER,
        SchemaBuilder.string(mapper)
            .description("Filter symbols by name (case-insensitive substring match, list mode)"));

    schemaRoot.property(
        ARG_SYMBOL_TYPE,
        SchemaBuilder.string(mapper)
            .description("Filter by symbol type (e.g., FUNCTION, LABEL, PARAMETER, LOCAL_VAR)"));

    schemaRoot.property(
        ARG_SOURCE_TYPE,
        SchemaBuilder.string(mapper)
            .description("Filter by source type (e.g., USER_DEFINED, IMPORTED, ANALYSIS)"));

    schemaRoot.property(
        ARG_NAMESPACE,
        SchemaBuilder.string(mapper)
            .description("Filter by namespace (e.g., 'Global', function names)"));

    schemaRoot.property(
        ARG_CURSOR,
        SchemaBuilder.string(mapper).description("Pagination cursor from previous request"));

    schemaRoot.property(
        ARG_PAGE_SIZE,
        SchemaBuilder.integer(mapper)
            .description(
                "Number of symbols to return per page (default: "
                    + DEFAULT_PAGE_LIMIT
                    + ", max: "
                    + MAX_PAGE_LIMIT
                    + ")")
            .minimum(1)
            .maximum(MAX_PAGE_LIMIT));

    schemaRoot.requiredProperty(ARG_FILE_NAME);

    return schemaRoot.build();
  }

  @Override
  public Mono<? extends Object> execute(
      McpTransportContext context, Map<String, Object> args, PluginTool tool) {
    return getProgram(args, tool)
        .flatMap(
            program -> {
              // Check if this is a single symbol read or a list operation
              boolean hasSingleIdentifier =
                  args.containsKey(ARG_SYMBOL_ID)
                      || args.containsKey(ARG_ADDRESS)
                      || args.containsKey(ARG_NAME);

              if (hasSingleIdentifier) {
                return handleRead(program, args);
              } else {
                return Mono.fromCallable(() -> listSymbols(program, args));
              }
            });
  }

  private Mono<? extends Object> handleRead(Program program, Map<String, Object> args) {
    return Mono.fromCallable(
        () -> {
          SymbolTable symbolTable = program.getSymbolTable();
          GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);

          // Apply precedence: symbol_id > address > name
          if (args.containsKey(ARG_SYMBOL_ID)) {
            Long symbolId = getOptionalLongArgument(args, ARG_SYMBOL_ID).orElse(null);
            if (symbolId != null) {
              Symbol symbol = symbolTable.getSymbol(symbolId);
              if (symbol != null) {
                return new SymbolInfo(symbol);
              }
            }
            throw new GhidraMcpException(
                createSymbolNotFoundError(annotation.mcpName(), "symbol_id", symbolId.toString()));
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
                throw new GhidraMcpException(
                    createSymbolNotFoundError(annotation.mcpName(), "address", address));
              } catch (Exception e) {
                throw new GhidraMcpException(createInvalidAddressError(address, e));
              }
            }
            throw new GhidraMcpException(createMissingParameterError(annotation.mcpName()));
          } else if (args.containsKey(ARG_NAME)) {
            String name = getOptionalStringArgument(args, ARG_NAME).orElse(null);
            if (name != null && !name.trim().isEmpty()) {
              // Use native SymbolTable.getSymbols() for efficient exact name lookup
              SymbolIterator exactIter = symbolTable.getSymbols(name);
              if (exactIter.hasNext()) {
                return new SymbolInfo(exactIter.next());
              }

              // Try wildcard search using SymbolTable's native * and ? support
              if (name.contains("*") || name.contains("?")) {
                SymbolIterator wildcardIter = symbolTable.getSymbolIterator(name, false);
                Symbol firstMatch = null;
                int matchCount = 0;

                while (wildcardIter.hasNext()) {
                  Symbol symbol = wildcardIter.next();
                  if (firstMatch == null) {
                    firstMatch = symbol;
                  }
                  matchCount++;
                  if (matchCount > 1) {
                    throw new GhidraMcpException(
                        GhidraMcpError.conflict(
                            "Multiple symbols found for wildcard pattern: " + name));
                  }
                }

                if (firstMatch != null) {
                  return new SymbolInfo(firstMatch);
                }
              }

              // Fallback: try as regex pattern (for backwards compatibility)
              try {
                Pattern pattern = Pattern.compile(name);
                Symbol firstMatch = null;
                int matchCount = 0;

                SymbolIterator allIter = symbolTable.getAllSymbols(true);
                while (allIter.hasNext()) {
                  Symbol symbol = allIter.next();
                  if (pattern.matcher(symbol.getName()).matches()) {
                    if (firstMatch == null) {
                      firstMatch = symbol;
                    }
                    matchCount++;
                    if (matchCount > 1) {
                      throw new GhidraMcpException(
                          GhidraMcpError.conflict(
                              "Multiple symbols found for regex pattern: " + name));
                    }
                  }
                }

                if (firstMatch != null) {
                  return new SymbolInfo(firstMatch);
                }
              } catch (PatternSyntaxException e) {
                throw new GhidraMcpException(createInvalidRegexError(name, e));
              } catch (GhidraMcpException e) {
                throw e;
              }

              throw new GhidraMcpException(
                  createSymbolNotFoundError(annotation.mcpName(), "name", name));
            }
            throw new GhidraMcpException(createMissingParameterError(annotation.mcpName()));
          } else {
            throw new GhidraMcpException(createMissingParameterError(annotation.mcpName()));
          }
        });
  }

  private PaginatedResult<SymbolInfo> listSymbols(Program program, Map<String, Object> args)
      throws GhidraMcpException {
    SymbolTable symbolTable = program.getSymbolTable();
    int pageSize =
        getOptionalIntArgument(args, ARG_PAGE_SIZE)
            .filter(size -> size > 0)
            .map(size -> Math.min(size, MAX_PAGE_LIMIT))
            .orElse(DEFAULT_PAGE_LIMIT);

    Optional<String> nameFilterOpt = getOptionalStringArgument(args, ARG_NAME_FILTER);
    Optional<String> symbolTypeOpt = getOptionalStringArgument(args, ARG_SYMBOL_TYPE);
    Optional<String> sourceTypeOpt = getOptionalStringArgument(args, ARG_SOURCE_TYPE);
    Optional<String> namespaceOpt = getOptionalStringArgument(args, ARG_NAMESPACE);
    Optional<String> cursorOpt = getOptionalStringArgument(args, ARG_CURSOR);

    // Map symbol type string to SymbolType enum
    SymbolType symbolTypeFilter = symbolTypeOpt.map(this::parseSymbolType).orElse(null);

    // Parse cursor to get starting name
    String cursorName = null;
    String cursorAddress = null;
    if (cursorOpt.isPresent()) {
      String[] parts = cursorOpt.get().split(":", 2);
      cursorName = parts[0];
      cursorAddress = parts.length > 1 ? parts[1] : null;
    }

    final String finalCursorName = cursorName;
    final String finalCursorAddress = cursorAddress;

    String normalizedNameFilter = nameFilterOpt.map(String::toLowerCase).orElse(null);
    String normalizedSourceType = sourceTypeOpt.map(String::toLowerCase).orElse(null);
    String normalizedNamespace = namespaceOpt.map(String::toLowerCase).orElse(null);

    List<SymbolInfo> allMatches = new ArrayList<>();
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

      if (normalizedNameFilter != null
          && !symbol.getName().toLowerCase().contains(normalizedNameFilter)) {
        continue;
      }

      allMatches.add(new SymbolInfo(symbol));
    }

    allMatches.sort(
        Comparator.comparing(SymbolInfo::getName, String.CASE_INSENSITIVE_ORDER)
            .thenComparing(SymbolInfo::getAddress, String.CASE_INSENSITIVE_ORDER));

    List<SymbolInfo> paginatedMatches =
        allMatches.stream()
            .dropWhile(
                symbolInfo -> {
                  if (finalCursorName == null || finalCursorName.isEmpty()) {
                    return false;
                  }

                  int nameCompare = symbolInfo.getName().compareToIgnoreCase(finalCursorName);
                  if (nameCompare < 0) {
                    return true;
                  }
                  if (nameCompare > 0) {
                    return false;
                  }

                  if (finalCursorAddress == null || finalCursorAddress.isEmpty()) {
                    return true;
                  }

                  return symbolInfo.getAddress().compareToIgnoreCase(finalCursorAddress) <= 0;
                })
            .limit(pageSize + 1L)
            .toList();

    boolean hasMore = paginatedMatches.size() > pageSize;
    List<SymbolInfo> results =
        hasMore
            ? new ArrayList<>(paginatedMatches.subList(0, pageSize))
            : new ArrayList<>(paginatedMatches);

    String nextCursor = null;
    if (hasMore && !results.isEmpty()) {
      SymbolInfo lastItem = results.get(results.size() - 1);
      nextCursor = lastItem.getName() + ":" + lastItem.getAddress();
    }

    return new PaginatedResult<>(results, nextCursor);
  }

  private SymbolType parseSymbolType(String typeStr) {
    if (typeStr == null) return null;
    String upperType = typeStr.toUpperCase();
    switch (upperType) {
      case "NAMESPACE":
        return SymbolType.NAMESPACE;
      case "CLASS":
        return SymbolType.CLASS;
      case "FUNCTION":
        return SymbolType.FUNCTION;
      case "LABEL":
        return SymbolType.LABEL;
      case "PARAMETER":
        return SymbolType.PARAMETER;
      case "LOCAL_VAR":
        return SymbolType.LOCAL_VAR;
      case "GLOBAL_VAR":
        return SymbolType.GLOBAL_VAR;
      case "GLOBAL":
        return SymbolType.GLOBAL;
      case "LIBRARY":
        return SymbolType.LIBRARY;
      default:
        return null;
    }
  }

  private GhidraMcpError createSymbolNotFoundError(
      String toolOperation, String searchType, String searchValue) {
    return GhidraMcpError.notFound(
        "symbol", searchValue, "Verify the symbol exists using " + searchType);
  }

  private GhidraMcpError createInvalidAddressError(String addressStr, Exception cause) {
    return GhidraMcpError.parse("address", addressStr);
  }

  private GhidraMcpError createInvalidRegexError(String pattern, Exception cause) {
    return GhidraMcpError.invalid(
        ARG_NAME, pattern, "Invalid regex pattern: " + cause.getMessage());
  }

  private GhidraMcpError createMissingParameterError(String toolOperation) {
    return GhidraMcpError.of(
        "No search parameters provided", "Provide symbol_id, address, or name parameter");
  }
}
