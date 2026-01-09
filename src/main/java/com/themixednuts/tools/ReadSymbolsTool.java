package com.themixednuts.tools;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.models.SymbolInfo;
import com.themixednuts.utils.PaginatedResult;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.google.SchemaBuilder;
import com.themixednuts.utils.jsonschema.google.SchemaBuilder.IObjectSchemaBuilder;

import generic.FilteredIterator;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import io.modelcontextprotocol.common.McpTransportContext;
import reactor.core.publisher.Mono;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

@GhidraMcpTool(name = "Read Symbols", description = "Read a single symbol or list symbols in a Ghidra program with pagination and filtering options.", mcpName = "read_symbols", mcpDescription = """
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
          "fileName": "program.exe",
          "symbol_id": 12345
        }

        Read a single symbol at an address:
        {
          "fileName": "program.exe",
          "address": "0x401000"
        }

        Read a single symbol by name:
        {
          "fileName": "program.exe",
          "name": "main"
        }

        List all symbols (first page):
        {
          "fileName": "program.exe"
        }

        List symbols with name filter:
        {
          "fileName": "program.exe",
          "name_filter": "decrypt"
        }

        Get next page of results:
        {
          "fileName": "program.exe",
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

        schemaRoot.property(ARG_FILE_NAME,
                SchemaBuilder.string(mapper)
                        .description("The name of the program file."));

        schemaRoot.property(ARG_SYMBOL_ID, SchemaBuilder.integer(mapper)
                .description("Symbol ID to identify a specific symbol (single read mode)"));

        schemaRoot.property(ARG_ADDRESS, SchemaBuilder.string(mapper)
                .description("Memory address to identify a specific symbol (single read mode)")
                .pattern("^(0x)?[0-9a-fA-F]+$"));

        schemaRoot.property(ARG_NAME, SchemaBuilder.string(mapper)
                .description("Symbol name for single symbol lookup (supports regex matching)"));

        schemaRoot.property(ARG_NAME_FILTER,
                SchemaBuilder.string(mapper)
                        .description("Filter symbols by name (case-insensitive substring match, list mode)"));

        schemaRoot.property(ARG_SYMBOL_TYPE,
                SchemaBuilder.string(mapper)
                        .description("Filter by symbol type (e.g., FUNCTION, LABEL, PARAMETER, LOCAL_VAR)"));

        schemaRoot.property(ARG_SOURCE_TYPE,
                SchemaBuilder.string(mapper)
                        .description("Filter by source type (e.g., USER_DEFINED, IMPORTED, ANALYSIS)"));

        schemaRoot.property(ARG_NAMESPACE,
                SchemaBuilder.string(mapper)
                        .description("Filter by namespace (e.g., 'Global', function names)"));

        schemaRoot.property(ARG_CURSOR,
                SchemaBuilder.string(mapper)
                        .description("Pagination cursor from previous request"));

        schemaRoot.requiredProperty(ARG_FILE_NAME);

        return schemaRoot.build();
    }

    @Override
    public Mono<? extends Object> execute(McpTransportContext context, Map<String, Object> args, PluginTool tool) {
        return getProgram(args, tool).flatMap(program -> {
            // Check if this is a single symbol read or a list operation
            boolean hasSingleIdentifier = args.containsKey(ARG_SYMBOL_ID) ||
                    args.containsKey(ARG_ADDRESS) ||
                    args.containsKey(ARG_NAME);

            if (hasSingleIdentifier) {
                return handleRead(program, args);
            } else {
                return Mono.fromCallable(() -> listSymbols(program, args));
            }
        });
    }

    private Mono<? extends Object> handleRead(Program program, Map<String, Object> args) {
        return Mono.fromCallable(() -> {
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
                    // First try exact match
                    SymbolIterator exactIter = symbolTable.getSymbolIterator(name, true);
                    if (exactIter.hasNext()) {
                        return new SymbolInfo(exactIter.next());
                    }

                    // Then try regex
                    try {
                        Symbol firstMatch = StreamSupport.stream(symbolTable.getAllSymbols(true).spliterator(), false)
                                .filter(s -> s.getName().matches(name))
                                .findFirst()
                                .orElse(null);

                        if (firstMatch != null) {
                            return new SymbolInfo(firstMatch);
                        }
                        throw new GhidraMcpException(createSymbolNotFoundError(annotation.mcpName(), "name", name));
                    } catch (Exception e) {
                        throw new GhidraMcpException(createInvalidRegexError(name, e));
                    }
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

        Optional<String> nameFilterOpt = getOptionalStringArgument(args, ARG_NAME_FILTER);
        Optional<String> symbolTypeOpt = getOptionalStringArgument(args, ARG_SYMBOL_TYPE);
        Optional<String> sourceTypeOpt = getOptionalStringArgument(args, ARG_SOURCE_TYPE);
        Optional<String> namespaceOpt = getOptionalStringArgument(args, ARG_NAMESPACE);
        Optional<String> cursorOpt = getOptionalStringArgument(args, ARG_CURSOR);

        // Map symbol type string to SymbolType enum by direct comparison
        Optional<SymbolType> symbolTypeEnumOpt = symbolTypeOpt.map(typeStr -> {
            String upperType = typeStr.toUpperCase();
            if (upperType.equals("NAMESPACE"))
                return SymbolType.NAMESPACE;
            if (upperType.equals("CLASS"))
                return SymbolType.CLASS;
            if (upperType.equals("FUNCTION"))
                return SymbolType.FUNCTION;
            if (upperType.equals("LABEL"))
                return SymbolType.LABEL;
            if (upperType.equals("PARAMETER"))
                return SymbolType.PARAMETER;
            if (upperType.equals("LOCAL_VAR"))
                return SymbolType.LOCAL_VAR;
            if (upperType.equals("GLOBAL_VAR"))
                return SymbolType.GLOBAL_VAR;
            if (upperType.equals("GLOBAL"))
                return SymbolType.GLOBAL;
            if (upperType.equals("LIBRARY"))
                return SymbolType.LIBRARY;
            return null;
        });

        // Use FilteredIterator to apply all filters efficiently
        SymbolIterator allSymbolsIterator = symbolTable.getAllSymbols(false);

        FilteredIterator<Symbol> filteredIterator = new FilteredIterator<>(allSymbolsIterator, symbol -> {
            // Apply name filter
            if (nameFilterOpt.isPresent() && !nameFilterOpt.get().isEmpty()) {
                if (!symbol.getName().toLowerCase().contains(nameFilterOpt.get().toLowerCase())) {
                    return false;
                }
            }

            // Apply symbol type filter using enum comparison
            if (symbolTypeEnumOpt.isPresent()) {
                if (symbolTypeEnumOpt.get() == null || symbol.getSymbolType() != symbolTypeEnumOpt.get()) {
                    return false;
                }
            }

            // Apply source type filter
            if (sourceTypeOpt.isPresent() && !sourceTypeOpt.get().isEmpty()) {
                if (!symbol.getSource().toString().equalsIgnoreCase(sourceTypeOpt.get())) {
                    return false;
                }
            }

            // Apply namespace filter
            if (namespaceOpt.isPresent() && !namespaceOpt.get().isEmpty()) {
                if (!symbol.getParentNamespace().getName(false).equalsIgnoreCase(namespaceOpt.get())) {
                    return false;
                }
            }

            return true;
        });

        // Convert filtered iterator to stream for processing
        List<SymbolInfo> allSymbols = StreamSupport
                .stream(Spliterators.spliteratorUnknownSize(filteredIterator, Spliterator.ORDERED), false)
                .map(SymbolInfo::new)
                .sorted((s1, s2) -> s1.getName().compareToIgnoreCase(s2.getName()))
                .collect(Collectors.toList());

        // Apply cursor-based pagination
        final String finalCursorStr = cursorOpt.orElse(null);

        List<SymbolInfo> paginatedSymbols = allSymbols.stream()
                .dropWhile(symbolInfo -> {
                    if (finalCursorStr == null)
                        return false;

                    // Cursor format: "name:address"
                    String[] parts = finalCursorStr.split(":", 2);
                    String cursorName = parts[0];
                    String cursorAddress = parts.length > 1 ? parts[1] : "";

                    int nameCompare = symbolInfo.getName().compareToIgnoreCase(cursorName);
                    if (nameCompare < 0)
                        return true;
                    if (nameCompare == 0) {
                        return symbolInfo.getAddress().compareTo(cursorAddress) <= 0;
                    }
                    return false;
                })
                .limit(DEFAULT_PAGE_LIMIT + 1)
                .collect(Collectors.toList());

        boolean hasMore = paginatedSymbols.size() > DEFAULT_PAGE_LIMIT;
        List<SymbolInfo> resultsForPage = paginatedSymbols.subList(0,
                Math.min(paginatedSymbols.size(), DEFAULT_PAGE_LIMIT));

        String nextCursor = null;
        if (hasMore && !resultsForPage.isEmpty()) {
            SymbolInfo lastItem = resultsForPage.get(resultsForPage.size() - 1);
            nextCursor = lastItem.getName() + ":" + lastItem.getAddress();
        }

        return new PaginatedResult<>(resultsForPage, nextCursor);
    }

    private GhidraMcpError createSymbolNotFoundError(String toolOperation, String searchType, String searchValue) {
        return GhidraMcpError.notFound("symbol", searchValue,
                "Verify the symbol exists using " + searchType);
    }

    private GhidraMcpError createInvalidAddressError(String addressStr, Exception cause) {
        return GhidraMcpError.parse("address", addressStr);
    }

    private GhidraMcpError createInvalidRegexError(String pattern, Exception cause) {
        return GhidraMcpError.invalid(ARG_NAME, pattern, "Invalid regex pattern: " + cause.getMessage());
    }

    private GhidraMcpError createMissingParameterError(String toolOperation) {
        return GhidraMcpError.of("No search parameters provided",
                "Provide symbol_id, address, or name parameter");
    }
}
