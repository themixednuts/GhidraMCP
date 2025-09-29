package com.themixednuts.tools;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.models.ReferenceInfo;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import io.modelcontextprotocol.common.McpTransportContext;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Spliterator;
import java.util.Spliterators;
import java.util.stream.StreamSupport;

@GhidraMcpTool(
    name = "Find References",
    description = "Find cross-references to and from addresses in the program.",
    mcpName = "find_references",
    mcpDescription = """
    <use_case>
    Find cross-references (xrefs) to and from specific addresses in the program.
    Use this for analyzing code flow, finding where data is used, or understanding
    program structure and dependencies.
    </use_case>

    <return_value_summary>
    Returns a list of ReferenceInfo objects containing reference details including
    source address, target address, reference type, and context information.
    </return_value_summary>

    <important_notes>
    - Supports both "to" (incoming) and "from" (outgoing) reference searches
    - References include code references, data references, and external references
    - Results include reference type and operation context
    </important_notes>
    """
)
public class FindReferencesTool implements IGhidraMcpSpecification {

    public static final String ARG_DIRECTION = "direction";
    public static final String ARG_REFERENCE_TYPE = "referenceType";

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
        IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();

        schemaRoot.property(ARG_FILE_NAME,
                JsonSchemaBuilder.string(mapper)
                        .description("The name of the program file."));

        schemaRoot.property(ARG_ADDRESS,
                JsonSchemaBuilder.string(mapper)
                        .description("Target address to find references for")
                        .pattern("^(0x)?[0-9a-fA-F]+$"));

        schemaRoot.property(ARG_DIRECTION,
                JsonSchemaBuilder.string(mapper)
                        .description("Direction of references to find")
                        .enumValues(Direction.getValidValues()));

        schemaRoot.property(ARG_REFERENCE_TYPE,
                JsonSchemaBuilder.string(mapper)
                        .description("Filter by reference type (e.g., 'DATA', 'CALL', 'JUMP')"));

        schemaRoot.requiredProperty(ARG_FILE_NAME);
        schemaRoot.requiredProperty(ARG_ADDRESS);
        schemaRoot.requiredProperty(ARG_DIRECTION);

        return schemaRoot.build();
    }

    /**
     * Executes the reference finding operation.
     * 
     * @param context The MCP transport context
     * @param args The tool arguments containing address, direction, and optional reference type
     * @param tool The Ghidra PluginTool context
     * @return A Mono emitting a list of ReferenceInfo objects
     */
    @Override
    public Mono<? extends Object> execute(McpTransportContext context, Map<String, Object> args, PluginTool tool) {
        GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);

        return getProgram(args, tool).flatMap(program -> {
            String addressStr = getRequiredStringArgument(args, ARG_ADDRESS);
            String directionStr = getRequiredStringArgument(args, ARG_DIRECTION);
            String referenceType = getOptionalStringArgument(args, ARG_REFERENCE_TYPE).orElse("");

            Direction direction = Direction.fromValue(directionStr);

            try {
                return parseAddress(program, args, addressStr, "find_references", annotation)
                    .flatMap(addressResult -> {
                    switch (direction) {
                        case TO -> {
                            return findReferencesTo(program, addressResult.getAddress(), referenceType, args, annotation);
                        }
                        case FROM -> {
                            return findReferencesFrom(program, addressResult.getAddress(), referenceType, args, annotation);
                        }
                        default -> {
                            return Mono.error(new GhidraMcpException(GhidraMcpError.validation()
                                .errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
                                .message("Invalid direction: " + directionStr)
                                .build()));
                        }
                    }
                });
            } catch (GhidraMcpException e) {
                return Mono.error(e);
            }
        });
    }

    private Mono<List<ReferenceInfo>> findReferencesTo(Program program, ghidra.program.model.address.Address address,
                                                      String referenceType, Map<String, Object> args,
                                                      GhidraMcpTool annotation) {
        return Mono.fromCallable(() -> {
            ReferenceIterator refIterator = program.getReferenceManager().getReferencesTo(address);
            List<ReferenceInfo> references = new ArrayList<>();

            try {
                StreamSupport.stream(
                    Spliterators.spliteratorUnknownSize(refIterator, Spliterator.ORDERED), false)
                    .filter(ref -> referenceType.isEmpty() ||
                            ref.getReferenceType().toString().equalsIgnoreCase(referenceType))
                    .forEach(ref -> references.add(new ReferenceInfo(program, ref)));
            } catch (Exception e) {
                throw buildXrefAnalysisException(annotation, args, "find_references_to",
                    address.toString(), references.size(), e);
            }

            return references;
        });
    }

    private Mono<List<ReferenceInfo>> findReferencesFrom(Program program, ghidra.program.model.address.Address address,
                                                        String referenceType, Map<String, Object> args,
                                                        GhidraMcpTool annotation) {
        return Mono.fromCallable(() -> {
            Reference[] referencesArray = program.getReferenceManager().getReferencesFrom(address);
            List<ReferenceInfo> references = new ArrayList<>(referencesArray != null ? referencesArray.length : 0);

            try {
                if (referencesArray != null) {
                    Arrays.stream(referencesArray)
                        .filter(ref -> referenceType.isEmpty() ||
                                ref.getReferenceType().toString().equalsIgnoreCase(referenceType))
                        .forEach(reference -> references.add(new ReferenceInfo(program, reference)));
                }
            } catch (Exception e) {
                throw buildXrefAnalysisException(annotation, args, "find_references_from",
                    address.toString(), references.size(), e);
            }

            return references;
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