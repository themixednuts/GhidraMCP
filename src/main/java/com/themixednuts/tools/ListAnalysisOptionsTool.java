package com.themixednuts.tools;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.AnalysisOptionInfo;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.utils.OpaqueCursorCodec;
import com.themixednuts.utils.PaginatedResult;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.google.SchemaBuilder;
import com.themixednuts.utils.jsonschema.google.SchemaBuilder.IObjectSchemaBuilder;
import ghidra.framework.options.OptionType;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.common.McpTransportContext;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import reactor.core.publisher.Mono;

@GhidraMcpTool(
    name = "List Analysis Options",
    description = "List program analysis options with filtering and pagination support.",
    mcpName = "list_analysis_options",
    readOnlyHint = true,
    idempotentHint = true,
    mcpDescription =
        """
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
        - Pagination uses opaque v1 cursors
        </important_notes>
        """)
public class ListAnalysisOptionsTool extends BaseMcpTool {

  public static final String ARG_OPTION_TYPE = "option_type";
  public static final String ARG_DEFAULTS_ONLY = "defaults_only";

  /**
   * Defines the JSON input schema for listing analysis options.
   *
   * @return The JsonSchema defining the expected input arguments
   */
  @Override
  public JsonSchema schema() {
    IObjectSchemaBuilder schemaRoot = createBaseSchemaNode();

    schemaRoot.property(
        ARG_FILE_NAME, SchemaBuilder.string(mapper).description("The name of the program file."));

    schemaRoot.property(
        ARG_FILTER,
        SchemaBuilder.string(mapper)
            .description("Filter options by name (case-insensitive substring match)"));

    schemaRoot.property(
        ARG_OPTION_TYPE,
        SchemaBuilder.string(mapper)
            .description("Filter by option type (e.g., BOOLEAN, STRING, INT)"));

    schemaRoot.property(
        ARG_DEFAULTS_ONLY,
        SchemaBuilder.bool(mapper).description("Show only options using default values"));

    schemaRoot.property(
        ARG_CURSOR,
        SchemaBuilder.string(mapper)
            .description(
                "Pagination cursor from previous request (format:"
                    + " v1:<base64url_option_name>)"));

    schemaRoot.property(
        ARG_PAGE_SIZE,
        SchemaBuilder.integer(mapper)
            .description(
                "Number of options to return per page (default: "
                    + DEFAULT_PAGE_LIMIT
                    + ", max: "
                    + MAX_PAGE_LIMIT
                    + ")")
            .minimum(1)
            .maximum(MAX_PAGE_LIMIT));

    schemaRoot.requiredProperty(ARG_FILE_NAME);

    return schemaRoot.build();
  }

  /**
   * Executes the analysis options listing operation.
   *
   * @param context The MCP transport context
   * @param args The tool arguments containing file_name and optional filters
   * @param tool The Ghidra PluginTool context
   * @return A Mono emitting a paginated list of AnalysisOptionInfo objects
   */
  @Override
  public Mono<? extends Object> execute(
      McpTransportContext context, Map<String, Object> args, PluginTool tool) {
    return getProgram(args, tool)
        .flatMap(
            program -> {
              String filter = getOptionalStringArgument(args, ARG_FILTER).orElse("");
              String optionType = getOptionalStringArgument(args, ARG_OPTION_TYPE).orElse("");
              boolean defaultsOnly =
                  getOptionalBooleanArgument(args, ARG_DEFAULTS_ONLY).orElse(false);
              Optional<String> cursorOpt = getOptionalStringArgument(args, ARG_CURSOR);
              int pageSize =
                  getOptionalIntArgument(args, ARG_PAGE_SIZE)
                      .filter(size -> size > 0)
                      .map(size -> Math.min(size, MAX_PAGE_LIMIT))
                      .orElse(DEFAULT_PAGE_LIMIT);

              return listAnalysisOptions(
                  program, filter, optionType, defaultsOnly, cursorOpt, pageSize);
            });
  }

  private Mono<PaginatedResult<AnalysisOptionInfo>> listAnalysisOptions(
      Program program,
      String filter,
      String optionType,
      boolean defaultsOnly,
      Optional<String> cursorOpt,
      int pageSize) {
    return Mono.fromCallable(
        () -> {
          Options analysisOptions =
              Optional.ofNullable(program.getOptions(Program.ANALYSIS_PROPERTIES))
                  .orElseThrow(
                      () ->
                          new GhidraMcpException(
                              GhidraMcpError.execution()
                                  .errorCode(GhidraMcpError.ErrorCode.UNEXPECTED_ERROR)
                                  .message(
                                      "Analysis options are not available for program: "
                                          + program.getName())
                                  .context(
                                      new GhidraMcpError.ErrorContext(
                                          this.getMcpName(),
                                          "list_analysis_options",
                                          Map.of(ARG_FILE_NAME, program.getName()),
                                          Map.of(),
                                          Map.of("analysis_options_available", false)))
                                  .build()));

          // Get cursor for pagination
          final String cursorName =
              cursorOpt
                  .map(
                      value ->
                          OpaqueCursorCodec.decodeV1(
                                  value, 1, ARG_CURSOR, "v1:<base64url_option_name>")
                              .get(0))
                  .orElse(null);
          boolean passedCursor = (cursorName == null);
          boolean cursorMatched = (cursorName == null);

          // Get all matching options sorted by name
          List<AnalysisOptionInfo> allOptions = new ArrayList<>();
          List<String> sortedNames =
              analysisOptions.getOptionNames().stream()
                  .sorted(String.CASE_INSENSITIVE_ORDER)
                  .toList();

          for (String optName : sortedNames) {
            // Skip past cursor
            if (!passedCursor) {
              if (optName.compareToIgnoreCase(cursorName) <= 0) {
                if (optName.equalsIgnoreCase(cursorName)) {
                  cursorMatched = true;
                }
                continue;
              }
              passedCursor = true;
            }

            AnalysisOptionInfo option = createAnalysisOptionInfo(analysisOptions, optName);

            // Apply filters
            if (!filter.isEmpty()
                && !option.getName().toLowerCase().contains(filter.toLowerCase())) {
              continue;
            }
            if (!optionType.isEmpty() && !option.getType().equalsIgnoreCase(optionType)) {
              continue;
            }
            if (defaultsOnly && !option.isUsingDefaultValue()) {
              continue;
            }

            allOptions.add(option);

            // Stop if we have enough for pagination check
            if (allOptions.size() > pageSize) {
              break;
            }
          }

          if (!cursorMatched) {
            throw new GhidraMcpException(
                GhidraMcpError.invalid(
                    ARG_CURSOR,
                    cursorName,
                    "cursor is invalid or no longer present in this analysis option listing"));
          }

          // Determine if there are more results
          boolean hasMore = allOptions.size() > pageSize;
          List<AnalysisOptionInfo> results = hasMore ? allOptions.subList(0, pageSize) : allOptions;

          String nextCursor = null;
          if (hasMore && !results.isEmpty()) {
            nextCursor = OpaqueCursorCodec.encodeV1(results.get(results.size() - 1).getName());
          }

          return new PaginatedResult<>(results, nextCursor);
        });
  }

  private AnalysisOptionInfo createAnalysisOptionInfo(Options analysisOptions, String optionName) {
    OptionType optionType = analysisOptions.getType(optionName);
    String value =
        Optional.ofNullable(analysisOptions.getObject(optionName, null))
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
