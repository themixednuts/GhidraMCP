package com.themixednuts.tools;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.AnalysisOptionInfo;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.framework.options.OptionType;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.common.McpTransportContext;
import reactor.core.publisher.Mono;

import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

@GhidraMcpTool(
    name = "List Analysis Options",
    description = "List program analysis options with filtering and pagination support.",
    mcpName = "list_analysis_options",
    mcpDescription = """
    <use_case>
    Retrieve a paginated list of analysis options for a program with optional filtering.
    Use this when you need to examine or configure analysis settings for reverse engineering.
    </use_case>

    <return_value_summary>
    Returns a list of AnalysisOptionInfo objects sorted by option name, containing
    option name, description, type, current value, and whether it uses the default value.
    </return_value_summary>

    <important_notes>
    - Requires an active program
    - Options are sorted alphabetically by name
    - Shows current values and default status for each option
    </important_notes>
    """
)
public class ListAnalysisOptionsTool implements IGhidraMcpSpecification {

    public static final String ARG_FILTER = "filter";
    public static final String ARG_OPTION_TYPE = "optionType";
    public static final String ARG_DEFAULTS_ONLY = "defaultsOnly";

    @Override
    public JsonSchema schema() {
        IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();

        schemaRoot.property(ARG_FILE_NAME,
                JsonSchemaBuilder.string(mapper)
                        .description("The name of the program file."));

        schemaRoot.property(ARG_FILTER,
                JsonSchemaBuilder.string(mapper)
                        .description("Filter options by name (case-insensitive substring match)"));

        schemaRoot.property(ARG_OPTION_TYPE,
                JsonSchemaBuilder.string(mapper)
                        .description("Filter by option type (e.g., BOOLEAN, STRING, INT)"));

        schemaRoot.property(ARG_DEFAULTS_ONLY,
                JsonSchemaBuilder.bool(mapper)
                        .description("Show only options using default values"));

        schemaRoot.requiredProperty(ARG_FILE_NAME);

        return schemaRoot.build();
    }

    @Override
    public Mono<? extends Object> execute(McpTransportContext context, Map<String, Object> args, PluginTool tool) {
        return getProgram(args, tool).flatMap(program -> {
            String filter = getOptionalStringArgument(args, ARG_FILTER).orElse("");
            String optionType = getOptionalStringArgument(args, ARG_OPTION_TYPE).orElse("");
            boolean defaultsOnly = getOptionalBooleanArgument(args, ARG_DEFAULTS_ONLY).orElse(false);

            return listAnalysisOptions(program, filter, optionType, defaultsOnly);
        });
    }

    private Mono<List<AnalysisOptionInfo>> listAnalysisOptions(Program program, String filter,
                                                               String optionType, boolean defaultsOnly) {
        return Mono.fromCallable(() -> {
            Options analysisOptions = Optional.ofNullable(program.getOptions(Program.ANALYSIS_PROPERTIES))
                .orElseThrow(() -> new GhidraMcpException(GhidraMcpError.execution()
                        .errorCode(GhidraMcpError.ErrorCode.UNEXPECTED_ERROR)
                        .message("Analysis options are not available for program: " + program.getName())
                        .context(new GhidraMcpError.ErrorContext(
                                this.getMcpName(),
                                "list_analysis_options",
                                Map.of(ARG_FILE_NAME, program.getName()),
                                Map.of(),
                                Map.of("analysisOptionsAvailable", false)))
                        .build()));

            return analysisOptions.getOptionNames().stream()
                .map(optionName -> createAnalysisOptionInfo(analysisOptions, optionName))
                .filter(option -> filter.isEmpty() ||
                        option.getName().toLowerCase().contains(filter.toLowerCase()))
                .filter(option -> optionType.isEmpty() ||
                        option.getType().equalsIgnoreCase(optionType))
                .filter(option -> !defaultsOnly || option.isUsingDefaultValue())
                .sorted(Comparator.comparing(AnalysisOptionInfo::getName, String.CASE_INSENSITIVE_ORDER))
                .collect(Collectors.toList());
        });
    }

    private AnalysisOptionInfo createAnalysisOptionInfo(Options analysisOptions, String optionName) {
        OptionType optionType = analysisOptions.getType(optionName);
        String value = Optional.ofNullable(analysisOptions.getObject(optionName, null))
                .map(Object::toString)
                .orElse("null");
        boolean usingDefault = analysisOptions.isDefaultValue(optionName);
        String description = analysisOptions.getDescription(optionName);

        return new AnalysisOptionInfo(
                optionName,
                description,
                Optional.ofNullable(optionType).map(Object::toString).orElse("unknown"),
                value,
                usingDefault);
    }
}