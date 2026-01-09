package com.themixednuts.tools;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.models.ReferenceInfo;
import com.themixednuts.utils.PaginatedResult;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.google.SchemaBuilder;
import com.themixednuts.utils.jsonschema.google.SchemaBuilder.IObjectSchemaBuilder;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import io.modelcontextprotocol.common.McpTransportContext;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@GhidraMcpTool(name = "Find References", description = "Find cross-references to and from addresses in the program with pagination.", mcpName = "find_references", mcpDescription = """
        <use_case>
        Find cross-references (xrefs) to and from specific addresses in the program.
        Use this for analyzing code flow, finding where data is used, or understanding
        program structure and dependencies.
        </use_case>

        <return_value_summary>
        Returns a paginated list of ReferenceInfo objects containing reference details including
        source address, target address, reference type, and context information.
        Use the cursor from the response to fetch the next page of results.
        </return_value_summary>

        <important_notes>
        - Supports both "to" (incoming) and "from" (outgoing) reference searches
        - References include code references, data references, and external references
        - Results are paginated - use cursor parameter for subsequent pages
        - Results include reference type and operation context
        </important_notes>
        """)
public class FindReferencesTool extends BaseMcpTool {

    public static final String ARG_DIRECTION = "direction";
    public static final String ARG_REFERENCE_TYPE = "reference_type";

    /**
     * Enumeration of reference search directions.
     */
    enum Direction {
        TO("to", "Find references TO the specified address"),
        FROM("from", "Find references FROM the specified address");

        private final String value;
        private final String description;

        Direction(String value, String description) {
            this.value = value;
            this.description = description;
        }

        public String getValue() {
            return value;
        }

        public String getDescription() {
            return description;
        }

        public static Direction fromValue(String value) {
            return Arrays.stream(values())
                    .filter(dir -> dir.value.equalsIgnoreCase(value))
                    .findFirst()
                    .orElseThrow(() -> new IllegalArgumentException("Invalid direction: " + value));
        }

        public static String[] getValidValues() {
            return Arrays.stream(values())
                    .map(Direction::getValue)
                    .toArray(String[]::new);
        }
    }

    /**
     * Defines the JSON input schema for finding references.
     * 
     * @return The JsonSchema defining the expected input arguments
     */
    @Override
    public JsonSchema schema() {
        IObjectSchemaBuilder schemaRoot = createBaseSchemaNode();

        schemaRoot.property(ARG_FILE_NAME,
                SchemaBuilder.string(mapper)
                        .description("The name of the program file."));

        schemaRoot.property(ARG_ADDRESS,
                SchemaBuilder.string(mapper)
                        .description("Target address to find references for")
                        .pattern("^(0x)?[0-9a-fA-F]+$"));

        schemaRoot.property(ARG_DIRECTION,
                SchemaBuilder.string(mapper)
                        .description("Direction of references to find")
                        .enumValues(Direction.getValidValues()));

        schemaRoot.property(ARG_REFERENCE_TYPE,
                SchemaBuilder.string(mapper)
                        .description("Filter by reference type (e.g., 'DATA', 'CALL', 'JUMP')"));

        schemaRoot.property(ARG_CURSOR,
                SchemaBuilder.string(mapper)
                        .description("Pagination cursor from previous request"));

        schemaRoot.requiredProperty(ARG_FILE_NAME);
        schemaRoot.requiredProperty(ARG_ADDRESS);
        schemaRoot.requiredProperty(ARG_DIRECTION);

        return schemaRoot.build();
    }

    /**
     * Executes the reference finding operation.
     *
     * @param context The MCP transport context
     * @param args    The tool arguments containing address, direction, and optional
     *                reference type
     * @param tool    The Ghidra PluginTool context
     * @return A Mono emitting a paginated list of ReferenceInfo objects
     */
    @Override
    public Mono<? extends Object> execute(McpTransportContext context, Map<String, Object> args, PluginTool tool) {
        GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);

        return getProgram(args, tool).flatMap(program -> {
            String addressStr;
            String directionStr;
            try {
                addressStr = getRequiredStringArgument(args, ARG_ADDRESS);
                directionStr = getRequiredStringArgument(args, ARG_DIRECTION);
            } catch (GhidraMcpException e) {
                return Mono.error(e);
            }
            String referenceType = getOptionalStringArgument(args, ARG_REFERENCE_TYPE).orElse("");
            Optional<String> cursorOpt = getOptionalStringArgument(args, ARG_CURSOR);

            Direction direction = Direction.fromValue(directionStr);

            return parseAddress(program, addressStr, "find_references")
                    .flatMap(addressResult -> {
                        switch (direction) {
                            case TO -> {
                                return findReferencesTo(program, addressResult.getAddress(), referenceType,
                                        cursorOpt, args, annotation);
                            }
                            case FROM -> {
                                return findReferencesFrom(program, addressResult.getAddress(), referenceType,
                                        cursorOpt, args, annotation);
                            }
                            default -> {
                                return Mono.error(new GhidraMcpException(GhidraMcpError.validation()
                                        .errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
                                        .message("Invalid direction: " + directionStr)
                                        .build()));
                            }
                        }
                    });
        });
    }

    private Mono<PaginatedResult<ReferenceInfo>> findReferencesTo(Program program, Address address,
            String referenceType, Optional<String> cursorOpt, Map<String, Object> args,
            GhidraMcpTool annotation) {
        return Mono.fromCallable(() -> {
            ReferenceManager refManager = program.getReferenceManager();

            // Use native hasReferencesTo() for early exit - avoids iterator creation if no refs
            if (!refManager.hasReferencesTo(address)) {
                return new PaginatedResult<>(List.of(), null);
            }

            // Parse cursor - cursor is the source address of the last reference seen
            Address cursorAddress = null;
            if (cursorOpt.isPresent()) {
                try {
                    cursorAddress = program.getAddressFactory().getAddress(cursorOpt.get());
                } catch (Exception e) {
                    // Invalid cursor, start from beginning
                }
            }

            List<ReferenceInfo> results = new ArrayList<>();
            boolean passedCursor = (cursorAddress == null);
            final Address finalCursorAddress = cursorAddress;

            try {
                ReferenceIterator refIterator = refManager.getReferencesTo(address);
                while (refIterator.hasNext() && results.size() <= DEFAULT_PAGE_LIMIT) {
                    Reference ref = refIterator.next();

                    // Skip past cursor position
                    if (!passedCursor) {
                        if (ref.getFromAddress().compareTo(finalCursorAddress) <= 0) {
                            continue;
                        }
                        passedCursor = true;
                    }

                    // Apply reference type filter
                    if (referenceType.isEmpty() ||
                            ref.getReferenceType().toString().equalsIgnoreCase(referenceType)) {
                        results.add(new ReferenceInfo(program, ref));
                    }
                }
            } catch (Exception e) {
                throw buildXrefAnalysisException(annotation, args, "find_references_to",
                        address.toString(), results.size(), e);
            }

            // Determine if there are more results
            boolean hasMore = results.size() > DEFAULT_PAGE_LIMIT;
            if (hasMore) {
                results = results.subList(0, DEFAULT_PAGE_LIMIT);
            }

            String nextCursor = null;
            if (hasMore && !results.isEmpty()) {
                // Cursor is the source address of the last reference
                nextCursor = results.get(results.size() - 1).getFromAddress();
            }

            return new PaginatedResult<>(results, nextCursor);
        });
    }

    private Mono<PaginatedResult<ReferenceInfo>> findReferencesFrom(Program program, Address address,
            String referenceType, Optional<String> cursorOpt, Map<String, Object> args,
            GhidraMcpTool annotation) {
        return Mono.fromCallable(() -> {
            ReferenceManager refManager = program.getReferenceManager();

            // Use native hasReferencesFrom() for early exit
            if (!refManager.hasReferencesFrom(address)) {
                return new PaginatedResult<>(List.of(), null);
            }

            // Parse cursor - cursor is the target address of the last reference seen
            Address cursorAddress = null;
            if (cursorOpt.isPresent()) {
                try {
                    cursorAddress = program.getAddressFactory().getAddress(cursorOpt.get());
                } catch (Exception e) {
                    // Invalid cursor, start from beginning
                }
            }

            Reference[] referencesArray = refManager.getReferencesFrom(address);
            List<ReferenceInfo> results = new ArrayList<>();
            boolean passedCursor = (cursorAddress == null);
            final Address finalCursorAddress = cursorAddress;

            try {
                if (referencesArray != null) {
                    for (Reference ref : referencesArray) {
                        if (results.size() > DEFAULT_PAGE_LIMIT) break;

                        // Skip past cursor position
                        if (!passedCursor) {
                            if (ref.getToAddress().compareTo(finalCursorAddress) <= 0) {
                                continue;
                            }
                            passedCursor = true;
                        }

                        // Apply reference type filter
                        if (referenceType.isEmpty() ||
                                ref.getReferenceType().toString().equalsIgnoreCase(referenceType)) {
                            results.add(new ReferenceInfo(program, ref));
                        }
                    }
                }
            } catch (Exception e) {
                throw buildXrefAnalysisException(annotation, args, "find_references_from",
                        address.toString(), results.size(), e);
            }

            // Determine if there are more results
            boolean hasMore = results.size() > DEFAULT_PAGE_LIMIT;
            if (hasMore) {
                results = results.subList(0, DEFAULT_PAGE_LIMIT);
            }

            String nextCursor = null;
            if (hasMore && !results.isEmpty()) {
                // Cursor is the target address of the last reference
                nextCursor = results.get(results.size() - 1).getToAddress();
            }

            return new PaginatedResult<>(results, nextCursor);
        });
    }

    private GhidraMcpException buildXrefAnalysisException(GhidraMcpTool annotation,
            Map<String, Object> args,
            String operation,
            String normalizedAddress,
            int referencesCollected,
            Exception cause) {
        return new GhidraMcpException(GhidraMcpError.execution()
                .errorCode(GhidraMcpError.ErrorCode.UNEXPECTED_ERROR)
                .message("Failed during cross-reference analysis: " + cause.getMessage())
                .context(new GhidraMcpError.ErrorContext(
                        annotation.mcpName(),
                        operation,
                        args,
                        Map.of(ARG_ADDRESS, normalizedAddress),
                        Map.of("referencesCollected", referencesCollected)))
                .suggestions(List.of(
                        new GhidraMcpError.ErrorSuggestion(
                                GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
                                "Verify program state and memory accessibility",
                                "Check that the program is properly loaded and the address is valid",
                                null,
                                null)))
                .build());
    }
}
