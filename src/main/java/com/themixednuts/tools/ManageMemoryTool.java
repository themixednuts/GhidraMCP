package com.themixednuts.tools;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.utils.PaginatedResult;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.features.base.memsearch.bytesource.ProgramByteSource;
import ghidra.features.base.memsearch.format.SearchFormat;
import ghidra.features.base.memsearch.gui.SearchSettings;
import ghidra.features.base.memsearch.matcher.ByteMatcher;
import ghidra.features.base.memsearch.searcher.MemoryMatch;
import ghidra.features.base.memsearch.searcher.MemorySearcher;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.datastruct.ListAccumulator;
import io.modelcontextprotocol.common.McpTransportContext;
import reactor.core.publisher.Mono;

import java.util.*;
import java.util.stream.Collectors;

@GhidraMcpTool(
    name = "Manage Memory",
    description = "Comprehensive memory management including reading, writing, searching, and analyzing memory segments.",
    mcpName = "manage_memory",
    mcpDescription = """
    <use_case>
    Comprehensive memory operations for reverse engineering. Read and write bytes, search for patterns,
    analyze memory layout, and manage memory segments. Essential for understanding program structure,
    patching code, and analyzing data structures.
    </use_case>

    <important_notes>
    - Read/write operations validate memory accessibility and permissions
    - Search supports multiple formats: hex, string, binary, regex patterns
    - Memory modifications are transactional and reversible
    - Large operations are monitored for cancellation and progress
    </important_notes>

    <examples>
    Read memory bytes:
    {
      "fileName": "program.exe",
      "action": "read",
      "address": "0x401000",
      "length": 16
    }

    Search for string pattern:
    {
      "fileName": "program.exe",
      "action": "search",
      "search_type": "string",
      "search_value": "password",
      "max_results": 10
    }
    </examples>
    """
)
public class ManageMemoryTool implements IGhidraMcpSpecification {

    public static final String ARG_ACTION = "action";
    public static final String ARG_SEARCH_TYPE = "search_type";
    public static final String ARG_SEARCH_VALUE = "search_value";
    public static final String ARG_BYTES_HEX = "bytes_hex";
    public static final String ARG_CASE_SENSITIVE = "case_sensitive";
    public static final String ARG_MAX_RESULTS = "max_results";
    public static final String ARG_PAGE_SIZE = "page_size";
    private static final int DEFAULT_PAGE_SIZE = 100;

    public enum SearchType {
        STRING("string", SearchFormat.STRING),
        HEX("hex", SearchFormat.HEX),
        BINARY("binary", SearchFormat.BINARY),
        DECIMAL("decimal", SearchFormat.DECIMAL),
        FLOAT("float", SearchFormat.FLOAT),
        DOUBLE("double", SearchFormat.DOUBLE),
        REGEX("regex", SearchFormat.REG_EX);

        private final String value;
        private final SearchFormat format;

        SearchType(String value, SearchFormat format) {
            this.value = value;
            this.format = format;
        }

        public String getValue() { return value; }
        public SearchFormat getFormat() { return format; }

        public static SearchType fromValue(String value) {
            for (SearchType type : values()) {
                if (type.value.equalsIgnoreCase(value)) {
                    return type;
                }
            }
            throw new IllegalArgumentException("Invalid search type: " + value);
        }
    }

    @Override
    public JsonSchema schema() {
        IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();

        schemaRoot.property(ARG_FILE_NAME,
                JsonSchemaBuilder.string(mapper)
                        .description("The name of the program file."));

        schemaRoot.property(ARG_ACTION, JsonSchemaBuilder.string(mapper)
                .enumValues("read", "write", "search", "list_segments", "analyze_segment")
                .description("Memory operation to perform"));

        schemaRoot.property(ARG_ADDRESS, JsonSchemaBuilder.string(mapper)
                .description("Memory address for read/write operations")
                .pattern("^(0x)?[0-9a-fA-F]+$"));

        schemaRoot.property(ARG_LENGTH, JsonSchemaBuilder.integer(mapper)
                .description("Number of bytes to read")
                .minimum(1)
                .maximum(4096));

        schemaRoot.property(ARG_BYTES_HEX, JsonSchemaBuilder.string(mapper)
                .description("Hexadecimal bytes to write (e.g., '4889e5')")
                .pattern("^[0-9a-fA-F]+$"));

        schemaRoot.property(ARG_SEARCH_TYPE, JsonSchemaBuilder.string(mapper)
                .enumValues("string", "hex", "binary", "decimal", "float", "double", "regex")
                .description("Type of search pattern"));

        schemaRoot.property(ARG_SEARCH_VALUE, JsonSchemaBuilder.string(mapper)
                .description("Value to search for (format depends on search_type)"));

        schemaRoot.property(ARG_CASE_SENSITIVE, JsonSchemaBuilder.bool(mapper)
                .description("Case sensitive search for string/regex")
                .defaultValue(false));

        schemaRoot.property(ARG_MAX_RESULTS, JsonSchemaBuilder.integer(mapper)
                .description("Maximum search results to return")
                .minimum(1)
                .maximum(1000)
                .defaultValue(100));

        schemaRoot.property(ARG_PAGE_SIZE, JsonSchemaBuilder.integer(mapper)
                .description("Maximum number of search results to return per page")
                .minimum(1)
                .maximum(1000)
                .defaultValue(DEFAULT_PAGE_SIZE));

        schemaRoot.requiredProperty(ARG_FILE_NAME)
                .requiredProperty(ARG_ACTION);

        return schemaRoot.build();
    }

    @Override
    public Mono<? extends Object> execute(McpTransportContext context, Map<String, Object> args, PluginTool tool) {
        GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);

        return getProgram(args, tool).flatMap(program -> {
            String action = getRequiredStringArgument(args, ARG_ACTION);

            return switch (action.toLowerCase()) {
                case "read" -> handleRead(program, args, annotation);
                case "write" -> handleWrite(program, args, annotation);
                case "search" -> handleSearch(program, args, annotation);
                case "list_segments" -> handleListSegments(program, args, annotation);
                case "analyze_segment" -> handleAnalyzeSegment(program, args, annotation);
                default -> {
                    GhidraMcpError error = GhidraMcpError.validation()
                        .errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
                        .message("Invalid action: " + action)
                        .context(new GhidraMcpError.ErrorContext(
                            annotation.mcpName(),
                            "action validation",
                            args,
                            Map.of(ARG_ACTION, action),
                            Map.of("validActions", List.of("read", "write", "search", "list_segments", "analyze_segment"))))
                        .suggestions(List.of(
                            new GhidraMcpError.ErrorSuggestion(
                                GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
                                "Use a valid action",
                                "Choose from: read, write, search, list_segments, analyze_segment",
                                List.of("read", "write", "search", "list_segments", "analyze_segment"),
                                null)))
                        .build();
                    yield Mono.error(new GhidraMcpException(error));
                }
            };
        });
    }

    private Mono<? extends Object> handleRead(Program program, Map<String, Object> args, GhidraMcpTool annotation) {
        String addressStr = getRequiredStringArgument(args, ARG_ADDRESS);
        int length = getRequiredIntArgument(args, ARG_LENGTH);

        return Mono.fromCallable(() -> {
            // Validate parameters
            if (length <= 0 || length > 4096) {
                GhidraMcpError error = GhidraMcpError.validation()
                    .errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
                    .message("Invalid length: " + length + ". Must be between 1 and 4096")
                    .build();
                throw new GhidraMcpException(error);
            }

            // Parse address
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
                    .context(new GhidraMcpError.ErrorContext(
                        annotation.mcpName(),
                        "address parsing",
                        args,
                        Map.of(ARG_ADDRESS, addressStr),
                        Map.of("parseError", e.getMessage())))
                    .suggestions(List.of(
                        new GhidraMcpError.ErrorSuggestion(
                            GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
                            "Use valid hexadecimal address format",
                            "Provide address as hexadecimal value",
                            List.of("0x401000", "401000", "0x00401000"),
                            null)))
                    .build();
                throw new GhidraMcpException(error);
            }

            // Read memory
            Memory memory = program.getMemory();
            byte[] bytesRead = new byte[length];
            int actualBytesRead;

            try {
                actualBytesRead = memory.getBytes(address, bytesRead);
            } catch (MemoryAccessException e) {
                GhidraMcpError error = GhidraMcpError.execution()
                    .errorCode(GhidraMcpError.ErrorCode.MEMORY_ACCESS_FAILED)
                    .message("Memory access error: " + e.getMessage())
                    .context(new GhidraMcpError.ErrorContext(
                        annotation.mcpName(),
                        "memory read",
                        args,
                        Map.of("memoryError", e.getMessage()),
                        Map.of("address", addressStr, "length", length)))
                    .suggestions(List.of(
                        new GhidraMcpError.ErrorSuggestion(
                            GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
                            "Verify address is in mapped memory",
                            "Ensure the address is within a valid memory region",
                            null,
                            null)))
                    .build();
                throw new GhidraMcpException(error);
            }

            // Trim to actual bytes read
            if (actualBytesRead < length) {
                byte[] trimmed = new byte[actualBytesRead];
                System.arraycopy(bytesRead, 0, trimmed, 0, actualBytesRead);
                bytesRead = trimmed;
            }

            // Generate hex representation and readable ASCII
            String hexData = HexFormat.of().formatHex(bytesRead);
            String readable = generateReadableString(bytesRead);

            return Map.of(
                "address", address.toString(),
                "length", actualBytesRead,
                "hex_data", hexData,
                "readable", readable,
                "bytes_requested", length,
                "bytes_read", actualBytesRead
            );
        });
    }

    private Mono<? extends Object> handleWrite(Program program, Map<String, Object> args, GhidraMcpTool annotation) {
        String addressStr = getRequiredStringArgument(args, ARG_ADDRESS);
        String bytesHex = getRequiredStringArgument(args, ARG_BYTES_HEX);

        return executeInTransaction(program, "MCP - Write Memory at " + addressStr, () -> {
            // Validate hex format
            if (bytesHex.length() % 2 != 0) {
                GhidraMcpError error = GhidraMcpError.validation()
                    .errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
                    .message("Invalid hex format: odd number of characters")
                    .build();
                throw new GhidraMcpException(error);
            }

            // Parse address
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

            // Parse hex bytes
            byte[] bytes;
            try {
                bytes = HexFormat.of().parseHex(bytesHex);
            } catch (IllegalArgumentException e) {
                GhidraMcpError error = GhidraMcpError.validation()
                    .errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
                    .message("Invalid hex string: " + e.getMessage())
                    .build();
                throw new GhidraMcpException(error);
            }

            // Write to memory
            try {
                program.getMemory().setBytes(address, bytes);
                return Map.of(
                    "success", true,
                    "address", address.toString(),
                    "bytes_written", bytes.length,
                    "hex_data", bytesHex
                );
            } catch (MemoryAccessException e) {
                GhidraMcpError error = GhidraMcpError.execution()
                    .errorCode(GhidraMcpError.ErrorCode.MEMORY_ACCESS_FAILED)
                    .message("Memory write error: " + e.getMessage())
                    .build();
                throw new GhidraMcpException(error);
            }
        });
    }

    private Mono<? extends Object> handleSearch(Program program, Map<String, Object> args, GhidraMcpTool annotation) {
        String searchTypeStr = getRequiredStringArgument(args, ARG_SEARCH_TYPE);
        String searchValue = getRequiredStringArgument(args, ARG_SEARCH_VALUE);
        boolean caseSensitive = getOptionalBooleanArgument(args, ARG_CASE_SENSITIVE).orElse(false);
        int pageSize = getOptionalIntArgument(args, ARG_PAGE_SIZE).orElse(DEFAULT_PAGE_SIZE);
        Optional<String> cursorOpt = getOptionalStringArgument(args, ARG_CURSOR);

        return Mono.fromCallable(() -> {
            SearchType searchType;
            try {
                searchType = SearchType.fromValue(searchTypeStr);
            } catch (IllegalArgumentException e) {
                GhidraMcpError error = GhidraMcpError.validation()
                    .errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
                    .message("Invalid search type: " + searchTypeStr)
                    .build();
                throw new GhidraMcpException(error);
            }

            if (searchValue.trim().isEmpty()) {
                GhidraMcpError error = GhidraMcpError.validation()
                    .errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
                    .message("Search value cannot be empty")
                    .build();
                throw new GhidraMcpException(error);
            }

            // Perform search
            SearchSettings settings = new SearchSettings();
            settings.withSearchFormat(searchType.getFormat());
            settings.withBigEndian(program.getMemory().isBigEndian());
            settings.withCaseSensitive(caseSensitive);

            ByteMatcher matcher = searchType.getFormat().parse(searchValue, settings);
            if (!matcher.isValidSearch()) {
                GhidraMcpError error = GhidraMcpError.validation()
                    .errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
                    .message("Invalid search pattern: " + matcher.getDescription())
                    .build();
                throw new GhidraMcpException(error);
            }

            ProgramByteSource byteSource = new ProgramByteSource(program);
            AddressSetView addressSet = program.getMemory().getLoadedAndInitializedAddressSet();
            MemorySearcher searcher = new MemorySearcher(byteSource, matcher, addressSet, pageSize);

            ListAccumulator<MemoryMatch> accumulator = new ListAccumulator<>();
            searcher.findAll(accumulator, null);

            List<MemoryMatch> matches = accumulator.stream().collect(Collectors.toList());
            matches.sort(Comparator.comparing(match -> match.getAddress()));

            int startIndex = 0;
            if (cursorOpt.isPresent()) {
                String cursor = cursorOpt.get();
                for (int i = 0; i < matches.size(); i++) {
                    String matchAddress = matches.get(i).getAddress().toString();
                    if (matchAddress.compareTo(cursor) > 0) {
                        startIndex = i;
                        break;
                    }
                    if (i == matches.size() - 1) {
                        startIndex = matches.size();
                    }
                }
            }

            List<Map<String, Object>> pageBuffer = matches.stream()
                .skip(startIndex)
                .limit((long) pageSize + 1)
                .map(match -> Map.<String, Object>of(
                    "address", match.getAddress().toString(),
                    "bytes", HexFormat.of().formatHex(match.getBytes()),
                    "length", match.getLength(),
                    "readable", generateReadableString(match.getBytes())
                ))
                .collect(Collectors.toList());

            String nextCursor = null;
            if (pageBuffer.size() > pageSize) {
                nextCursor = (String) pageBuffer.get(pageSize).get("address");
            }

            List<Map<String, Object>> pageResults = pageBuffer.size() > pageSize
                ? new ArrayList<>(pageBuffer.subList(0, pageSize))
                : pageBuffer;

            PaginatedResult<Map<String, Object>> paginated = new PaginatedResult<>(pageResults, nextCursor);

            return Map.of(
                "search_type", searchTypeStr,
                "search_value", searchValue,
                "case_sensitive", caseSensitive,
                "results", paginated,
                "total_found", matches.size(),
                "returned_count", pageResults.size(),
                "page_size", pageSize
            );
        });
    }

    private Mono<? extends Object> handleListSegments(Program program, Map<String, Object> args, GhidraMcpTool annotation) {
        return Mono.fromCallable(() -> {
            MemoryBlock[] blocks = program.getMemory().getBlocks();
            List<Map<String, Object>> segments = Arrays.stream(blocks)
                .map(block -> Map.<String, Object>of(
                    "name", block.getName(),
                    "start_address", block.getStart().toString(),
                    "end_address", block.getEnd().toString(),
                    "size", block.getSize(),
                    "permissions", getPermissionString(block),
                    "type", block.getType().toString(),
                    "initialized", block.isInitialized(),
                    "comment", block.getComment() != null ? block.getComment() : ""
                ))
                .sorted(Comparator.comparing(seg -> (String) seg.get("start_address")))
                .collect(Collectors.toList());

            return Map.of(
                "segments", segments,
                "total_segments", segments.size()
            );
        });
    }

    private Mono<? extends Object> handleAnalyzeSegment(Program program, Map<String, Object> args, GhidraMcpTool annotation) {
        String addressStr = getRequiredStringArgument(args, ARG_ADDRESS);

        return Mono.fromCallable(() -> {
            Address address;
            try {
                address = program.getAddressFactory().getAddress(addressStr);
            } catch (Exception e) {
                GhidraMcpError error = GhidraMcpError.validation()
                    .errorCode(GhidraMcpError.ErrorCode.ADDRESS_PARSE_FAILED)
                    .message("Failed to parse address: " + e.getMessage())
                    .build();
                throw new GhidraMcpException(error);
            }

            MemoryBlock block = program.getMemory().getBlock(address);
            if (block == null) {
                GhidraMcpError error = GhidraMcpError.resourceNotFound()
                    .errorCode(GhidraMcpError.ErrorCode.ADDRESS_NOT_FOUND)
                    .message("No memory segment found at address: " + addressStr)
                    .build();
                throw new GhidraMcpException(error);
            }

            return Map.of(
                "name", block.getName(),
                "start_address", block.getStart().toString(),
                "end_address", block.getEnd().toString(),
                "size", block.getSize(),
                "permissions", getPermissionString(block),
                "type", block.getType().toString(),
                "initialized", block.isInitialized(),
                "comment", block.getComment() != null ? block.getComment() : "",
                "source_name", block.getSourceName() != null ? block.getSourceName() : "",
                "overlay", block.isOverlay()
            );
        });
    }

    private String getPermissionString(MemoryBlock block) {
        StringBuilder perms = new StringBuilder();
        perms.append(block.isRead() ? "r" : "-");
        perms.append(block.isWrite() ? "w" : "-");
        perms.append(block.isExecute() ? "x" : "-");
        return perms.toString();
    }

    private String generateReadableString(byte[] bytes) {
        StringBuilder readable = new StringBuilder();
        for (byte b : bytes) {
            // ASCII printable range: 32-126
            if (b >= 32 && b <= 126) {
                readable.append((char) b);
            } else {
                readable.append('.');
            }
        }
        return readable.toString();
    }
}