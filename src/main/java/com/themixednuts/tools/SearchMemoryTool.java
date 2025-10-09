package com.themixednuts.tools;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import ghidra.util.task.TaskMonitor;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.google.SchemaBuilder;
import com.themixednuts.utils.jsonschema.google.SchemaBuilder.IObjectSchemaBuilder;
import com.themixednuts.utils.PaginatedResult;

import ghidra.features.base.memsearch.bytesource.ProgramByteSource;
import ghidra.features.base.memsearch.format.SearchFormat;
import ghidra.features.base.memsearch.gui.SearchSettings;
import ghidra.features.base.memsearch.matcher.ByteMatcher;
import ghidra.features.base.memsearch.searcher.MemoryMatch;
import ghidra.features.base.memsearch.searcher.MemorySearcher;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.datastruct.ListAccumulator;
import io.modelcontextprotocol.common.McpTransportContext;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Search Memory", description = "Search program memory for various data types and patterns using Ghidra's search mechanisms", mcpName = "search_memory", mcpDescription = """
        <use_case>
        Search program memory for various data types and patterns using Ghidra's native search algorithms.
        Supports string search, byte patterns, regular expressions, and numeric values.
        Use this when you need to find specific patterns, values, or strings in the program's memory.
        </use_case>

        <ghidra_specific_notes>
        - Uses Ghidra's Memory.findBytes and StringSearcher for efficient pattern matching
        - Supports string, regex, hex byte, binary, and numeric searches
        - Searches only in initialized memory regions by default
        - Results are paginated to handle large search results efficiently
        - Requires an active program to search through its memory
        </ghidra_specific_notes>

        <parameters_summary>
        - 'searchType': Type of search (string, hex, binary, decimal, float, double, regex)
        - 'searchValue': The pattern/value to search for (format depends on search type)
        - 'caseSensitive': Whether string/regex searches are case sensitive (default false)
        - 'maxResults': Maximum number of results to return (default 100, max 1000)
        </parameters_summary>

        <agent_response_guidance>
        Present search results in a clear, structured format showing addresses and found content.
        Include the search type and value in your response. If many results are found, mention
        the total count and suggest refining the search criteria if needed.
        </agent_response_guidance>
        """)
public class SearchMemoryTool implements IGhidraMcpSpecification {

    /**
     * Enumeration of supported memory search types.
     */
    public enum SearchType {
        STRING("string", "Text string search"),
        HEX("hex", "Hexadecimal byte pattern search"),
        BINARY("binary", "Binary pattern search"),
        DECIMAL("decimal", "Decimal number search"),
        FLOAT("float", "32-bit floating point search"),
        DOUBLE("double", "64-bit floating point search"),
        REGEX("regex", "Regular expression pattern search");

        private final String value;
        private final String description;

        SearchType(String value, String description) {
            this.value = value;
            this.description = description;
        }

        public String getValue() {
            return value;
        }

        public String getDescription() {
            return description;
        }

        public static SearchType fromValue(String value) throws GhidraMcpException {
            return Arrays.stream(values())
                    .filter(type -> type.value.equalsIgnoreCase(value))
                    .findFirst()
                    .orElseThrow(() -> new GhidraMcpException(GhidraMcpError.validation()
                            .errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
                            .message("Invalid search type: " + value)
                            .build()));
        }

        public static String[] getValidValues() {
            return Arrays.stream(values())
                    .map(SearchType::getValue)
                    .toArray(String[]::new);
        }

        public SearchFormat getSearchFormat() {
            return switch (this) {
                case STRING -> SearchFormat.STRING;
                case BINARY -> SearchFormat.BINARY;
                case DECIMAL -> SearchFormat.DECIMAL;
                case FLOAT -> SearchFormat.FLOAT;
                case DOUBLE -> SearchFormat.DOUBLE;
                case REGEX -> SearchFormat.REG_EX;
                default -> SearchFormat.HEX;
            };
        }
    }

    public static final String ARG_SEARCH_TYPE = "searchType";
    public static final String ARG_SEARCH_VALUE = "searchValue";
    public static final String ARG_CASE_SENSITIVE = "caseSensitive";
    public static final String ARG_MAX_RESULTS = "maxResults";

    /**
     * Defines the JSON input schema for memory searching.
     * 
     * @return The JsonSchema defining the expected input arguments
     */
    @Override
    public JsonSchema schema() {
        IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();

        schemaRoot.property(ARG_FILE_NAME,
                SchemaBuilder.string(mapper)
                        .description("The name of the program file."));

        schemaRoot.property(ARG_SEARCH_TYPE,
                SchemaBuilder.string(mapper)
                        .description("Type of search to perform")
                        .enumValues(SearchType.getValidValues()));

        schemaRoot.property(ARG_SEARCH_VALUE,
                SchemaBuilder.string(mapper)
                        .description(
                                "Value to search for. Format depends on search type:\n" +
                                        "- string: text to find (e.g., 'hello')\n" +
                                        "- hex: space-separated hex bytes (e.g., '48 65 6c 6c 6f' for 'Hello')\n" +
                                        "- binary: space-separated binary bytes (e.g., '01001000 01100101')\n" +
                                        "- decimal: decimal number (e.g., '12345')\n" +
                                        "- float: floating point number (e.g., '3.14159')\n" +
                                        "- double: double precision number (e.g., '2.718281828')\n" +
                                        "- regex: regular expression pattern"));

        schemaRoot.property(ARG_CASE_SENSITIVE,
                SchemaBuilder.bool(mapper)
                        .description("Whether string/regex searches are case sensitive (default false)"));

        schemaRoot.property(ARG_MAX_RESULTS,
                SchemaBuilder.integer(mapper)
                        .description("Maximum number of results to return (default/max: " + DEFAULT_PAGE_LIMIT + ")")
                        .minimum(1)
                        .maximum(DEFAULT_PAGE_LIMIT));

        schemaRoot.requiredProperty(ARG_FILE_NAME);
        schemaRoot.requiredProperty(ARG_SEARCH_TYPE);
        schemaRoot.requiredProperty(ARG_SEARCH_VALUE);

        return schemaRoot.build();
    }

    public static class SearchResult {
        private final String address;
        private final byte[] bytes;
        private final int length;
        private final String searchType;

        public SearchResult(String address, byte[] bytes, int length, String searchType) {
            this.address = address;
            this.bytes = bytes;
            this.length = length;
            this.searchType = searchType;
        }

        public String getAddress() {
            return address;
        }

        public byte[] getBytes() {
            return bytes;
        }

        public int getLength() {
            return length;
        }

        public String getSearchType() {
            return searchType;
        }
    }

    private static record SearchContext(
            Program program,
            SearchType searchType,
            String searchValue,
            boolean caseSensitive,
            int maxResults) {
    }

    /**
     * Executes the memory search operation.
     * 
     * @param ex   The MCP transport context
     * @param args The tool arguments containing fileName, searchType, searchValue,
     *             and optional parameters
     * @param tool The Ghidra PluginTool context
     * @return A Mono emitting a SearchResult object
     */
    @Override
    public Mono<? extends Object> execute(McpTransportContext ex, Map<String, Object> args, PluginTool tool) {
        return getProgram(args, tool)
                .flatMap(program -> Mono.fromCallable(() -> {
                    String searchTypeStr = getRequiredStringArgument(args, ARG_SEARCH_TYPE);
                    SearchType searchType = SearchType.fromValue(searchTypeStr);

                    String searchValue = getRequiredStringArgument(args, ARG_SEARCH_VALUE);
                    boolean caseSensitive = getOptionalBooleanArgument(args, ARG_CASE_SENSITIVE).orElse(false);
                    int maxResults = getOptionalIntArgument(args, ARG_MAX_RESULTS).orElse(DEFAULT_PAGE_LIMIT);

                    if (searchValue.trim().isEmpty()) {
                        throw new GhidraMcpException(GhidraMcpError.validation()
                                .errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
                                .message("Search value cannot be empty")
                                .context(new GhidraMcpError.ErrorContext(
                                        getMcpName(),
                                        "search value validation",
                                        args,
                                        Map.of(ARG_SEARCH_VALUE, searchValue),
                                        Map.of("valueLength", searchValue.length())))
                                .build());
                    }

                    // Validate hex format and provide helpful suggestions
                    if (searchType == SearchType.HEX) {
                        validateHexFormat(searchValue, args);
                    }

                    SearchContext context = new SearchContext(program, searchType, searchValue, caseSensitive,
                            maxResults);

                    TaskMonitor monitor = TaskMonitor.DUMMY;

                    List<SearchResult> results = search(context, monitor);

                    return new PaginatedResult<>(results, null);
                }));
    }

    private List<SearchResult> search(SearchContext context, TaskMonitor monitor) throws GhidraMcpException {
        Program program = context.program();
        SearchType searchType = context.searchType();
        String searchValue = context.searchValue();
        boolean caseSensitive = context.caseSensitive();
        int maxResults = context.maxResults();

        SearchSettings settings = new SearchSettings();
        SearchFormat searchFormat = searchType.getSearchFormat();
        settings.withSearchFormat(searchFormat);
        settings.withBigEndian(program.getMemory().isBigEndian());
        settings.withCaseSensitive(caseSensitive);

        ByteMatcher matcher = searchFormat.parse(searchValue, settings);

        if (!matcher.isValidSearch()) {
            throw new GhidraMcpException(GhidraMcpError.validation()
                    .errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
                    .message("Invalid search value for the given search type: " + matcher.getDescription())
                    .build());
        }

        ProgramByteSource byteSource = new ProgramByteSource(program);
        AddressSetView addressSet = program.getMemory().getLoadedAndInitializedAddressSet();

        // Check if we have any memory to search
        if (addressSet.isEmpty()) {
            throw new GhidraMcpException(GhidraMcpError.searchNoResults()
                    .errorCode(GhidraMcpError.ErrorCode.NO_SEARCH_RESULTS)
                    .message("No initialized memory regions found in the program")
                    .context(new GhidraMcpError.ErrorContext(
                            getMcpName(),
                            "memory region check",
                            Map.of("searchValue", searchValue, "searchType", searchType.getValue()),
                            Map.of("addressSetSize", addressSet.getNumAddresses()),
                            Map.of("programName", program.getName())))
                    .build());
        }

        MemorySearcher searcher = new MemorySearcher(byteSource, matcher, addressSet, maxResults);

        ListAccumulator<MemoryMatch> accumulator = new ListAccumulator<>();
        searcher.findAll(accumulator, monitor);

        List<SearchResult> results = accumulator.stream()
                .map(match -> new SearchResult(match.getAddress().toString(), match.getBytes(), match.getLength(),
                        searchType.getValue()))
                .collect(Collectors.toList());

        // If no results found, provide helpful information
        if (results.isEmpty()) {
            throw new GhidraMcpException(GhidraMcpError.searchNoResults()
                    .errorCode(GhidraMcpError.ErrorCode.NO_SEARCH_RESULTS)
                    .message("No matches found for the search pattern")
                    .context(new GhidraMcpError.ErrorContext(
                            getMcpName(),
                            "search execution",
                            Map.of("searchValue", searchValue, "searchType", searchType.getValue()),
                            Map.of("addressSetSize", addressSet.getNumAddresses(), "maxResults", maxResults),
                            Map.of("programName", program.getName(), "endianness",
                                    program.getMemory().isBigEndian() ? "big" : "little")))
                    .suggestions(List.of(
                            new GhidraMcpError.ErrorSuggestion(
                                    GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
                                    "Try different search patterns",
                                    "Consider trying different hex patterns or search types",
                                    List.of("Try with spaces: '38 8c 36 49'", "Try uppercase: '388C3649'",
                                            "Try different search type"),
                                    null)))
                    .build());
        }

        return results;
    }

    /**
     * Validates hex format and provides helpful suggestions for common format
     * issues.
     */
    private void validateHexFormat(String searchValue, Map<String, Object> args) throws GhidraMcpException {
        String trimmed = searchValue.trim();

        // Check for common format issues
        if (trimmed.startsWith("0x") || trimmed.startsWith("0X")) {
            String withoutPrefix = trimmed.substring(2);
            String suggested = formatHexWithSpaces(withoutPrefix);
            throw new GhidraMcpException(GhidraMcpError.validation()
                    .errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
                    .message("Hex values should not include '0x' prefix. Use space-separated format instead.")
                    .context(new GhidraMcpError.ErrorContext(
                            getMcpName(),
                            "hex format validation",
                            args,
                            Map.of(ARG_SEARCH_VALUE, searchValue),
                            Map.of("detectedPrefix", "0x", "suggestedFormat", suggested)))
                    .suggestions(List.of(
                            new GhidraMcpError.ErrorSuggestion(
                                    GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
                                    "Use space-separated hex format",
                                    "Remove '0x' prefix and add spaces between bytes",
                                    List.of(suggested),
                                    null)))
                    .build());
        }

        // Check if it's a continuous hex string without spaces
        if (trimmed.matches("^[0-9a-fA-F]+$") && trimmed.length() > 2 && !trimmed.contains(" ")) {
            String suggested = formatHexWithSpaces(trimmed);
            throw new GhidraMcpException(GhidraMcpError.validation()
                    .errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
                    .message("Hex values should be space-separated for proper byte interpretation.")
                    .context(new GhidraMcpError.ErrorContext(
                            getMcpName(),
                            "hex format validation",
                            args,
                            Map.of(ARG_SEARCH_VALUE, searchValue),
                            Map.of("detectedFormat", "continuous", "suggestedFormat", suggested)))
                    .suggestions(List.of(
                            new GhidraMcpError.ErrorSuggestion(
                                    GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
                                    "Add spaces between hex bytes",
                                    "Separate each two-digit hex value with a space",
                                    List.of(suggested),
                                    null)))
                    .build());
        }
    }

    /**
     * Formats a continuous hex string into space-separated bytes.
     */
    private String formatHexWithSpaces(String hexString) {
        if (hexString.length() % 2 != 0) {
            hexString = "0" + hexString; // Pad with leading zero if odd length
        }

        StringBuilder result = new StringBuilder();
        for (int i = 0; i < hexString.length(); i += 2) {
            if (result.length() > 0) {
                result.append(" ");
            }
            result.append(hexString.substring(i, i + 2));
        }
        return result.toString();
    }
}
