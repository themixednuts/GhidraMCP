package com.themixednuts.tools;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.SymbolInfo;
import com.themixednuts.utils.PaginatedResult;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import generic.FilteredIterator;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import io.modelcontextprotocol.common.McpTransportContext;
import reactor.core.publisher.Mono;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;
import java.util.Spliterator;
import java.util.Spliterators;

@GhidraMcpTool(
    name = "List Symbols",
    description = "List symbols in a Ghidra program with pagination and filtering options.",
    mcpName = "list_symbols",
    mcpDescription = """
    <use_case>
    Browse and list symbols in Ghidra programs with optional filtering by name pattern,
    symbol type, source type, and namespace. Returns paginated results with symbol details
    including addresses, types, and metadata.
    </use_case>

    <important_notes>
    - Results are paginated to prevent overwhelming responses
    - Supports filtering by name patterns, symbol types, and namespaces
    - Symbols are sorted by name for consistent ordering
    - Returns detailed symbol information including addresses and types
    </important_notes>

    <examples>
    List first page of symbols:
    {
      "fileName": "program.exe"
    }

    List symbols with name filter:
    {
      "fileName": "program.exe",
      "nameFilter": "decrypt"
    }

    Get next page of results:
    {
      "fileName": "program.exe",
      "cursor": "main:0x401000"
    }
    </examples>
    """
)
public class ListSymbolsTool implements IGhidraMcpSpecification {

    public static final String ARG_NAME_FILTER = "nameFilter";
    public static final String ARG_SYMBOL_TYPE = "symbolType";
    public static final String ARG_SOURCE_TYPE = "sourceType";
    public static final String ARG_NAMESPACE = "namespace";
    public static final String ARG_CURSOR = "cursor";

    private static final int DEFAULT_PAGE_LIMIT = 50;

    /**
     * Defines the JSON input schema for listing symbols.
     * 
     * @return The JsonSchema defining the expected input arguments
     */
    @Override
    public JsonSchema schema() {
        IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();

        schemaRoot.property(ARG_FILE_NAME,
                JsonSchemaBuilder.string(mapper)
                        .description("The name of the program file."));

        schemaRoot.property(ARG_NAME_FILTER,
                JsonSchemaBuilder.string(mapper)
                        .description("Filter symbols by name (case-insensitive substring match)"));

        schemaRoot.property(ARG_SYMBOL_TYPE,
                JsonSchemaBuilder.string(mapper)
                        .description("Filter by symbol type (e.g., FUNCTION, LABEL, PARAMETER, LOCAL_VAR)"));

        schemaRoot.property(ARG_SOURCE_TYPE,
                JsonSchemaBuilder.string(mapper)
                        .description("Filter by source type (e.g., USER_DEFINED, IMPORTED, ANALYSIS)"));

        schemaRoot.property(ARG_NAMESPACE,
                JsonSchemaBuilder.string(mapper)
                        .description("Filter by namespace (e.g., 'Global', function names)"));

        schemaRoot.property(ARG_CURSOR,
                JsonSchemaBuilder.string(mapper)
                        .description("Pagination cursor from previous request"));

        schemaRoot.requiredProperty(ARG_FILE_NAME);

        return schemaRoot.build();
    }

    /**
     * Executes the symbol listing operation.
     * 
     * @param context The MCP transport context
     * @param args The tool arguments containing fileName and optional filters
     * @param tool The Ghidra PluginTool context
     * @return A Mono emitting a PaginatedResult containing SymbolInfo objects
     */
    @Override
    public Mono<? extends Object> execute(McpTransportContext context, Map<String, Object> args, PluginTool tool) {
        return getProgram(args, tool).flatMap(program -> {
            return Mono.fromCallable(() -> listSymbols(program, args));
        });
    }

    /**
     * Lists symbols in the program with optional filtering and pagination.
     * 
     * @param program The Ghidra program to list symbols from
     * @param args The arguments containing optional filters and cursor
     * @return A PaginatedResult containing SymbolInfo objects
     * @throws GhidraMcpException If there's an error processing the symbols
     */
    private PaginatedResult<SymbolInfo> listSymbols(Program program, Map<String, Object> args) throws GhidraMcpException {
        SymbolTable symbolTable = program.getSymbolTable();

        Optional<String> nameFilterOpt = getOptionalStringArgument(args, ARG_NAME_FILTER);
        Optional<String> symbolTypeOpt = getOptionalStringArgument(args, ARG_SYMBOL_TYPE);
        Optional<String> sourceTypeOpt = getOptionalStringArgument(args, ARG_SOURCE_TYPE);
        Optional<String> namespaceOpt = getOptionalStringArgument(args, ARG_NAMESPACE);
        Optional<String> cursorOpt = getOptionalStringArgument(args, ARG_CURSOR);

        // Map symbol type string to SymbolType enum by direct comparison
        Optional<SymbolType> symbolTypeEnumOpt = symbolTypeOpt.map(typeStr -> {
            String upperType = typeStr.toUpperCase();
            if (upperType.equals("NAMESPACE")) return SymbolType.NAMESPACE;
            if (upperType.equals("CLASS")) return SymbolType.CLASS;
            if (upperType.equals("FUNCTION")) return SymbolType.FUNCTION;
            if (upperType.equals("LABEL")) return SymbolType.LABEL;
            if (upperType.equals("PARAMETER")) return SymbolType.PARAMETER;
            if (upperType.equals("LOCAL_VAR")) return SymbolType.LOCAL_VAR;
            if (upperType.equals("GLOBAL_VAR")) return SymbolType.GLOBAL_VAR;
            if (upperType.equals("GLOBAL")) return SymbolType.GLOBAL;
            if (upperType.equals("LIBRARY")) return SymbolType.LIBRARY;
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
                if (finalCursorStr == null) return false;

                // Cursor format: "name:address"
                String[] parts = finalCursorStr.split(":", 2);
                String cursorName = parts[0];
                String cursorAddress = parts.length > 1 ? parts[1] : "";

                int nameCompare = symbolInfo.getName().compareToIgnoreCase(cursorName);
                if (nameCompare < 0) return true;
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
}