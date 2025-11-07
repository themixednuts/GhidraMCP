package com.themixednuts.tools;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.models.MemoryReadResult;
import com.themixednuts.models.MemorySegmentAnalysisResult;
import com.themixednuts.models.MemorySegmentInfo;
import com.themixednuts.models.MemorySegmentsOverview;
import com.themixednuts.models.MemoryWriteResult;
import com.themixednuts.utils.jsonschema.JsonSchema;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import io.modelcontextprotocol.common.McpTransportContext;
import reactor.core.publisher.Mono;

import java.util.Arrays;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

@GhidraMcpTool(name = "Manage Memory", description = "Memory CRUD operations: read, write, undefine code units, list segments, and analyze memory segment details.", mcpName = "manage_memory", mcpDescription = """
                <use_case>
                Memory CRUD operations for reverse engineering. Read and write bytes, undefine code units,
                list and analyze memory segments. Essential for understanding program structure, patching code,
                and clearing incorrect disassembly.
                </use_case>

                <important_notes>
                - Read/write operations validate memory accessibility and permissions
                - Memory modifications are transactional and reversible
                - Use SearchMemoryTool for pattern searching
                - Use FindReferencesTool for cross-reference analysis
                </important_notes>

                <examples>
                Read memory bytes:
                {
                  "fileName": "program.exe",
                  "action": "read",
                  "address": "0x401000",
                  "length": 16
                }

                Write bytes to memory:
                {
                  "fileName": "program.exe",
                  "action": "write",
                  "address": "0x401000",
                  "bytes_hex": "4889e5"
                }

                Undefine code unit at address:
                {
                  "fileName": "program.exe",
                  "action": "undefine",
                  "address": "0x401000"
                }

                List memory segments:
                {
                  "fileName": "program.exe",
                  "action": "list_segments"
                }
                </examples>
                """)
public class ManageMemoryTool implements IGhidraMcpSpecification {

        public static final String ARG_ACTION = "action";
        public static final String ARG_BYTES_HEX = "bytes_hex";

        private static final String ACTION_READ = "read";
        private static final String ACTION_WRITE = "write";
        private static final String ACTION_UNDEFINE = "undefine";
        private static final String ACTION_LIST_SEGMENTS = "list_segments";
        private static final String ACTION_ANALYZE_SEGMENT = "analyze_segment";

        /**
         * Defines the JSON input schema for memory management operations.
         * 
         * @return The JsonSchema defining the expected input arguments
         */
        @Override
        public JsonSchema schema() {
                // Use Draft 7 builder for conditional support
                var schemaRoot = IGhidraMcpSpecification.createDraft7SchemaNode();

                schemaRoot.property(ARG_FILE_NAME,
                                com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.string(mapper)
                                                .description("The name of the program file."));

                schemaRoot.property(ARG_ACTION, com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.string(mapper)
                                .enumValues(
                                                ACTION_READ,
                                                ACTION_WRITE,
                                                ACTION_UNDEFINE,
                                                ACTION_LIST_SEGMENTS,
                                                ACTION_ANALYZE_SEGMENT)
                                .description("Memory operation to perform"));

                schemaRoot.property(ARG_ADDRESS, com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.string(mapper)
                                .description("Memory address for read/write operations")
                                .pattern("^(0x)?[0-9a-fA-F]+$"));

                schemaRoot.property(ARG_LENGTH, com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.integer(mapper)
                                .description("Number of bytes to read")
                                .minimum(1)
                                .maximum(4096));

                schemaRoot.property(ARG_BYTES_HEX, com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.string(mapper)
                                .description("Hexadecimal bytes to write (e.g., '4889e5')")
                                .pattern("^[0-9a-fA-F]+$"));

                schemaRoot.requiredProperty(ARG_FILE_NAME)
                                .requiredProperty(ARG_ACTION);

                // Add conditional requirements based on action (JSON Schema Draft 7)
                schemaRoot.allOf(
                                // action=read requires address and length
                                com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.objectDraft7(mapper)
                                                .ifThen(
                                                                com.themixednuts.utils.jsonschema.draft7.SchemaBuilder
                                                                                .objectDraft7(mapper)
                                                                                .property(ARG_ACTION,
                                                                                                com.themixednuts.utils.jsonschema.draft7.SchemaBuilder
                                                                                                                .string(mapper)
                                                                                                                .constValue(ACTION_READ)),
                                                                com.themixednuts.utils.jsonschema.draft7.SchemaBuilder
                                                                                .objectDraft7(mapper)
                                                                                .requiredProperty(ARG_ADDRESS)
                                                                                .requiredProperty(ARG_LENGTH)),
                                // action=write requires address and bytes_hex
                                com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.objectDraft7(mapper)
                                                .ifThen(
                                                                com.themixednuts.utils.jsonschema.draft7.SchemaBuilder
                                                                                .objectDraft7(mapper)
                                                                                .property(ARG_ACTION,
                                                                                                com.themixednuts.utils.jsonschema.draft7.SchemaBuilder
                                                                                                                .string(mapper)
                                                                                                                .constValue(ACTION_WRITE)),
                                                                com.themixednuts.utils.jsonschema.draft7.SchemaBuilder
                                                                                .objectDraft7(mapper)
                                                                                .requiredProperty(ARG_ADDRESS)
                                                                                .requiredProperty(ARG_BYTES_HEX)),
                                // action=undefine requires address
                                com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.objectDraft7(mapper)
                                                .ifThen(
                                                                com.themixednuts.utils.jsonschema.draft7.SchemaBuilder
                                                                                .objectDraft7(mapper)
                                                                                .property(ARG_ACTION,
                                                                                                com.themixednuts.utils.jsonschema.draft7.SchemaBuilder
                                                                                                                .string(mapper)
                                                                                                                .constValue(ACTION_UNDEFINE)),
                                                                com.themixednuts.utils.jsonschema.draft7.SchemaBuilder
                                                                                .objectDraft7(mapper)
                                                                                .requiredProperty(ARG_ADDRESS)),
                                // action=analyze_segment requires address
                                com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.objectDraft7(mapper)
                                                .ifThen(
                                                                com.themixednuts.utils.jsonschema.draft7.SchemaBuilder
                                                                                .objectDraft7(mapper)
                                                                                .property(ARG_ACTION,
                                                                                                com.themixednuts.utils.jsonschema.draft7.SchemaBuilder
                                                                                                                .string(mapper)
                                                                                                                .constValue(ACTION_ANALYZE_SEGMENT)),
                                                                com.themixednuts.utils.jsonschema.draft7.SchemaBuilder
                                                                                .objectDraft7(mapper)
                                                                                .requiredProperty(ARG_ADDRESS)));

                return schemaRoot.build();
        }

        /**
         * Executes the memory management operation.
         * 
         * @param context The MCP transport context
         * @param args    The tool arguments containing fileName, action, and
         *                action-specific parameters
         * @param tool    The Ghidra PluginTool context
         * @return A Mono emitting the result of the memory operation
         */
        @Override
        public Mono<? extends Object> execute(McpTransportContext context, Map<String, Object> args, PluginTool tool) {
                GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);

                return getProgram(args, tool).flatMap(program -> {
                        String action = getRequiredStringArgument(args, ARG_ACTION);

                        return switch (action.toLowerCase()) {
                                case ACTION_READ -> handleRead(program, args, annotation);
                                case ACTION_WRITE -> handleWrite(program, args, annotation);
                                case ACTION_UNDEFINE -> handleUndefine(program, args, annotation);
                                case ACTION_LIST_SEGMENTS -> handleListSegments(program, args, annotation);
                                case ACTION_ANALYZE_SEGMENT -> handleAnalyzeSegment(program, args, annotation);
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
                                                                                        ACTION_LIST_SEGMENTS,
                                                                                        ACTION_ANALYZE_SEGMENT))))
                                                        .suggestions(List.of(
                                                                        new GhidraMcpError.ErrorSuggestion(
                                                                                        GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
                                                                                        "Use a valid action",
                                                                                        "Choose from: read, write, undefine, list_segments, analyze_segment",
                                                                                        List.of(
                                                                                                        ACTION_READ,
                                                                                                        ACTION_WRITE,
                                                                                                        ACTION_UNDEFINE,
                                                                                                        ACTION_LIST_SEGMENTS,
                                                                                                        ACTION_ANALYZE_SEGMENT),
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
                                                                                List.of("0x401000", "401000",
                                                                                                "0x00401000"),
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
                                bytesRead = Arrays.copyOf(bytesRead, actualBytesRead);
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

        private Mono<? extends Object> handleWrite(Program program, Map<String, Object> args,
                        GhidraMcpTool annotation) {
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

        private Mono<? extends Object> handleUndefine(Program program, Map<String, Object> args,
                        GhidraMcpTool annotation) {
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
                                                                                List.of("0x401000", "0x00401000",
                                                                                                "401000"),
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

        private Mono<? extends Object> handleListSegments(Program program, Map<String, Object> args,
                        GhidraMcpTool annotation) {
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

        private Mono<? extends Object> handleAnalyzeSegment(Program program, Map<String, Object> args,
                        GhidraMcpTool annotation) {
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

        private String getPermissionString(MemoryBlock block) {
                return String.format("%s%s%s",
                                block.isRead() ? "r" : "-",
                                block.isWrite() ? "w" : "-",
                                block.isExecute() ? "x" : "-");
        }

        private String generateReadableString(byte[] bytes) {
                return IntStream.range(0, bytes.length)
                                .mapToObj(i -> {
                                        byte b = bytes[i];
                                        // ASCII printable range: 32-126
                                        return (b >= 32 && b <= 126) ? String.valueOf((char) b) : ".";
                                })
                                .collect(Collectors.joining());
        }

}
