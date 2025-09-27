package com.themixednuts.tools;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.models.MemoryReadResult;
import com.themixednuts.models.MemorySearchResult;
import com.themixednuts.models.MemorySegmentAnalysisResult;
import com.themixednuts.models.MemorySegmentInfo;
import com.themixednuts.models.MemorySegmentsOverview;
import com.themixednuts.models.MemoryWriteResult;
import com.themixednuts.models.ReferenceInfo;
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
import ghidra.util.task.TaskMonitor;
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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

@GhidraMcpTool(
    name = "Manage Memory",
    description = "Comprehensive memory management including reading, writing, undefining code units, searching, analyzing memory segments, and inspecting cross-references.",
    mcpName = "manage_memory",
    mcpDescription = """
    <use_case>
    Comprehensive memory operations for reverse engineering. Read and write bytes, undefine code units,
    search for patterns, analyze memory layout, manage memory segments, and inspect cross-references at specific addresses.
    Essential for understanding program structure, patching code, clearing incorrect disassembly, and analyzing data structures.
    </use_case>

    <important_notes>
    - Read/write operations validate memory accessibility and permissions
    - Search supports multiple formats: hex, string, binary, regex patterns
    - Memory modifications are transactional and reversible
    - Large operations are monitored for cancellation and progress
    - Cross-reference queries return detailed metadata about incoming and outgoing references
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

    Undefine code unit at address:
    {
      "fileName": "program.exe",
      "action": "undefine",
      "address": "0x401000"
    }

    List incoming cross-references:
    {
      "fileName": "program.exe",
      "action": "get_xrefs_to",
      "address": "0x401000"
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

    private static final String ACTION_READ = "read";
    private static final String ACTION_WRITE = "write";
    private static final String ACTION_UNDEFINE = "undefine";
    private static final String ACTION_SEARCH = "search";
    private static final String ACTION_LIST_SEGMENTS = "list_segments";
    private static final String ACTION_ANALYZE_SEGMENT = "analyze_segment";
    private static final String ACTION_GET_XREFS_TO = "get_xrefs_to";
    private static final String ACTION_GET_XREFS_FROM = "get_xrefs_from";

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
                .enumValues(
                        ACTION_READ,
                        ACTION_WRITE,
                        ACTION_UNDEFINE,
                        ACTION_SEARCH,
                        ACTION_LIST_SEGMENTS,
                        ACTION_ANALYZE_SEGMENT,
                        ACTION_GET_XREFS_TO,
                        ACTION_GET_XREFS_FROM)
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
                case ACTION_READ -> handleRead(program, args, annotation);
                case ACTION_WRITE -> handleWrite(program, args, annotation);
                case ACTION_UNDEFINE -> handleUndefine(program, args, annotation);
                case ACTION_SEARCH -> handleSearch(program, args, annotation);
                case ACTION_LIST_SEGMENTS -> handleListSegments(program, args, annotation);
                case ACTION_ANALYZE_SEGMENT -> handleAnalyzeSegment(program, args, annotation);
                case ACTION_GET_XREFS_TO -> handleGetXrefsTo(program, args, annotation);
                case ACTION_GET_XREFS_FROM -> handleGetXrefsFrom(program, args, annotation);
                default -> {
                    GhidraMcpError error = GhidraMcpError.validation()
                        .errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
                        .message("Invalid action: " + action)
                        .context(new GhidraMcpError.ErrorContext(
                            annotation.mcpName(),
                            "action validation",
                            args,
                            Map.of(ARG_ACTION, action),
                            Map.of("validActions", List.of(
                                    ACTION_READ,
                                    ACTION_WRITE,
                                    ACTION_UNDEFINE,
                                    ACTION_SEARCH,
                                    ACTION_LIST_SEGMENTS,
                                    ACTION_ANALYZE_SEGMENT,
                                    ACTION_GET_XREFS_TO,
                                    ACTION_GET_XREFS_FROM))))
                        .suggestions(List.of(
                            new GhidraMcpError.ErrorSuggestion(
                                GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
                                "Use a valid action",
                                "Choose from: read, write, undefine, search, list_segments, analyze_segment, get_xrefs_to, get_xrefs_from",
                                List.of(
                                        ACTION_READ,
                                        ACTION_WRITE,
                                        ACTION_UNDEFINE,
                                        ACTION_SEARCH,
                                        ACTION_LIST_SEGMENTS,
                                        ACTION_ANALYZE_SEGMENT,
                                        ACTION_GET_XREFS_TO,
                                        ACTION_GET_XREFS_FROM),
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

            return new MemoryReadResult(
                address.toString(),
                actualBytesRead,
                hexData,
                readable,
                length,
                actualBytesRead);
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
                return new MemoryWriteResult(true,
                    address.toString(),
                    bytes.length,
                    bytesHex);
            } catch (MemoryAccessException e) {
                GhidraMcpError error = GhidraMcpError.execution()
                    .errorCode(GhidraMcpError.ErrorCode.MEMORY_ACCESS_FAILED)
                    .message("Memory write error: " + e.getMessage())
                    .build();
                throw new GhidraMcpException(error);
            }
        });
    }

    private Mono<? extends Object> handleUndefine(Program program, Map<String, Object> args, GhidraMcpTool annotation) {
        String addressStr = getRequiredStringArgument(args, ARG_ADDRESS);

        return executeInTransaction(program, "MCP - Undefine at " + addressStr, () -> {
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
                        this.getMcpName(),
                        "address parsing",
                        args,
                        Map.of(ARG_ADDRESS, addressStr),
                        Map.of("parseError", e.getMessage())))
                    .suggestions(List.of(
                        new GhidraMcpError.ErrorSuggestion(
                            GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
                            "Use valid address format",
                            "Provide address in hexadecimal format",
                            List.of("0x401000", "0x00401000", "401000"),
                            null)))
                    .build();
                throw new GhidraMcpException(error);
            }

            // Clear code units at the address
            try {
                program.getListing().clearCodeUnits(address, address, false);
                return "Successfully cleared code unit definition at address " + address.toString();
            } catch (Exception e) {
                GhidraMcpError error = GhidraMcpError.execution()
                    .errorCode(GhidraMcpError.ErrorCode.TRANSACTION_FAILED)
                    .message("Failed to clear code units: " + e.getMessage())
                    .context(new GhidraMcpError.ErrorContext(
                        this.getMcpName(),
                        "undefine operation",
                        args,
                        Map.of(ARG_ADDRESS, addressStr),
                        Map.of("operationError", e.getMessage())))
                    .suggestions(List.of(
                        new GhidraMcpError.ErrorSuggestion(
                            GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
                            "Verify address is valid",
                            "Ensure the address is within a valid memory range",
                            null,
                            null)))
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
            long startTime = System.nanoTime();
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
            searcher.findAll(accumulator, TaskMonitor.DUMMY);

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

            List<MemorySearchResult.MemoryMatch> pageBuffer = matches.stream()
                .skip(startIndex)
                .limit((long) pageSize + 1)
                .map(match -> new MemorySearchResult.MemoryMatch(
                    match.getAddress().toString(),
                    HexFormat.of().formatHex(match.getBytes()),
                    generateReadableString(match.getBytes()),
                    match.getLength()))
                .collect(Collectors.toList());

            String nextCursor = null;
            if (pageBuffer.size() > pageSize) {
                nextCursor = pageBuffer.get(pageSize).getAddress();
            }

            List<MemorySearchResult.MemoryMatch> pageResults = pageBuffer.size() > pageSize
                ? new ArrayList<>(pageBuffer.subList(0, pageSize))
                : pageBuffer;

            PaginatedResult<MemorySearchResult.MemoryMatch> paginated = new PaginatedResult<>(pageResults, nextCursor);

            long searchTimeMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startTime);

            return new MemorySearchResult(
                searchValue,
                searchTypeStr,
                caseSensitive,
                paginated,
                matches.size(),
                pageResults.size(),
                pageSize,
                searchTimeMs);
        });
    }

    private Mono<? extends Object> handleListSegments(Program program, Map<String, Object> args, GhidraMcpTool annotation) {
        return Mono.fromCallable(() -> {
            MemoryBlock[] blocks = program.getMemory().getBlocks();
            List<MemorySegmentInfo> segments = Arrays.stream(blocks)
                .map(block -> new MemorySegmentInfo(
                    block.getName(),
                    block.getStart().toString(),
                    block.getEnd().toString(),
                    block.getSize(),
                    getPermissionString(block),
                    block.getType().toString(),
                    block.isInitialized(),
                    block.getComment() != null ? block.getComment() : ""))
                .sorted(Comparator.comparing(MemorySegmentInfo::getStartAddress))
                .collect(Collectors.toList());

            return new MemorySegmentsOverview(segments);
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

            return new MemorySegmentAnalysisResult(
                block.getName(),
                block.getStart().toString(),
                block.getEnd().toString(),
                block.getSize(),
                getPermissionString(block),
                block.getType().toString(),
                block.isInitialized(),
                block.getComment() != null ? block.getComment() : "",
                block.getSourceName() != null ? block.getSourceName() : "",
                block.isOverlay());
        });
    }

    private Mono<? extends Object> handleGetXrefsTo(Program program, Map<String, Object> args, GhidraMcpTool annotation) {
        String addressStr = getRequiredStringArgument(args, ARG_ADDRESS);

        return parseAddress(program, args, addressStr, ACTION_GET_XREFS_TO, annotation)
                .flatMap(addressResult -> Mono.fromCallable(() -> {
                    ReferenceIterator refIterator = program.getReferenceManager().getReferencesTo(addressResult.getAddress());
                    List<ReferenceInfo> references = new ArrayList<>();

                    try {
                        while (refIterator.hasNext()) {
                            references.add(new ReferenceInfo(program, refIterator.next()));
                        }
                    } catch (Exception e) {
                        throw buildXrefAnalysisException(annotation, args, ACTION_GET_XREFS_TO, addressResult.getAddressString(), references.size(), e);
                    }

                    return references;
                }));
    }

    private Mono<? extends Object> handleGetXrefsFrom(Program program, Map<String, Object> args, GhidraMcpTool annotation) {
        String addressStr = getRequiredStringArgument(args, ARG_ADDRESS);

        return parseAddress(program, args, addressStr, ACTION_GET_XREFS_FROM, annotation)
                .flatMap(addressResult -> Mono.fromCallable(() -> {
                    Reference[] referencesArray = program.getReferenceManager().getReferencesFrom(addressResult.getAddress());
                    List<ReferenceInfo> references = new ArrayList<>(referencesArray != null ? referencesArray.length : 0);

                    try {
                        if (referencesArray != null) {
                            for (Reference reference : referencesArray) {
                                references.add(new ReferenceInfo(program, reference));
                            }
                        }
                    } catch (Exception e) {
                        throw buildXrefAnalysisException(annotation, args, ACTION_GET_XREFS_FROM, addressResult.getAddressString(), references.size(), e);
                    }

                    return references;
                }));
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

    private GhidraMcpException buildXrefAnalysisException(GhidraMcpTool annotation,
                                                          Map<String, Object> args,
                                                          String operation,
                                                          String normalizedAddress,
                                                          int referencesCollected,
                                                          Exception cause) {
        GhidraMcpError error = GhidraMcpError.execution()
                .errorCode(GhidraMcpError.ErrorCode.ANALYSIS_FAILED)
                .message("Error analyzing cross-references: " + cause.getMessage())
                .context(new GhidraMcpError.ErrorContext(
                        annotation.mcpName(),
                        operation,
                        args,
                        Map.of(ARG_ADDRESS, normalizedAddress),
                        Map.of("analysisError", cause.getMessage(), "referencesCollected", referencesCollected)))
                .suggestions(List.of(
                        new GhidraMcpError.ErrorSuggestion(
                                GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
                                "Verify program analysis is complete",
                                "Ensure the program has finished auto-analysis so reference data is available",
                                List.of("Run auto-analysis", "Re-run reference analysis"),
                                null),
                        new GhidraMcpError.ErrorSuggestion(
                                GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
                                "Try a different address",
                                "Provide an address located in analyzed code or data",
                                null,
                                null)))
                .build();
        return new GhidraMcpException(error, cause);
    }
}