package com.themixednuts.tools;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.AnalysisOptionInfo;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.models.OperationResult;
import com.themixednuts.utils.OpaqueCursorCodec;
import com.themixednuts.utils.PaginatedResult;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.draft7.SchemaBuilder;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.services.GoToService;
import ghidra.framework.options.OptionType;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.common.McpTransportContext;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import reactor.core.publisher.Mono;

@GhidraMcpTool(
    name = "Project",
    description =
        "Project-level operations: list analysis options, run analysis, save, navigation,"
            + " undo/redo, and transaction history.",
    mcpName = "project",
    mcpDescription =
        """
        <use_case>
        Perform project-level actions such as inspecting analysis options, running analysis,
        navigating to addresses, and managing undo/redo operations.
        </use_case>

        <important_notes>
        - All actions require an open program; provide file_name for those requests.
        - For program metadata, use the ghidra://program/{name}/info resource.
        - For listing available programs, use the ghidra://programs resource.
        - For imports/exports use ghidra://program/{name}/imports and ghidra://program/{name}/exports resources.
        - For defined strings use ghidra://program/{name}/strings resource.
        - Navigation relies on GoToService being available in the active tool.
        - Analysis option listing reflects current values and flags options still using defaults.
        - Undo/redo operations are performed on the Swing EDT thread.
        </important_notes>

        <return_value_summary>
        - list_analysis_options: returns a paginated list of AnalysisOptionInfo objects.
        - run_analysis: returns OperationResult describing the triggered analysis.
        - save: saves the program to the project, preserving all changes.
        - go_to_address: returns OperationResult describing navigation outcome.
        - undo/redo: returns a map with action, success, and current undo/redo state.
        - history: returns a map with available undo/redo operation lists.
        </return_value_summary>

        <agent_response_guidance>
        Summarize the performed action, highlight key fields (e.g., address,
        notable analysis options), and mention any suggested follow-up steps when appropriate.
        </agent_response_guidance>
        """)
public class ProjectTool extends BaseMcpTool {

  private static final String ACTION_LIST_ANALYSIS_OPTIONS = "list_analysis_options";
  private static final String ACTION_GO_TO_ADDRESS = "go_to_address";
  private static final String ACTION_RUN_ANALYSIS = "run_analysis";
  private static final String ACTION_SAVE = "save";
  private static final String ACTION_UNDO = "undo";
  private static final String ACTION_REDO = "redo";
  private static final String ACTION_HISTORY = "history";

  // list_analysis_options specific args
  private static final String ARG_OPTION_TYPE = "option_type";
  private static final String ARG_DEFAULTS_ONLY = "defaults_only";

  @Override
  public JsonSchema schema() {
    var schemaRoot = createDraft7SchemaNode();

    schemaRoot.property(
        ARG_FILE_NAME, SchemaBuilder.string(mapper).description("The name of the program file."));

    schemaRoot.property(
        ARG_ACTION,
        SchemaBuilder.string(mapper)
            .enumValues(
                ACTION_LIST_ANALYSIS_OPTIONS,
                ACTION_GO_TO_ADDRESS,
                ACTION_RUN_ANALYSIS,
                ACTION_SAVE,
                ACTION_UNDO,
                ACTION_REDO,
                ACTION_HISTORY)
            .description("Project-level operation to perform"));

    schemaRoot.property(
        ARG_ADDRESS,
        SchemaBuilder.string(mapper)
            .description("Target address for navigation")
            .pattern("^(0x)?[0-9a-fA-F]+$"));

    // list_analysis_options specific properties
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

    // Common pagination properties
    schemaRoot.property(
        ARG_CURSOR,
        SchemaBuilder.string(mapper).description("Cursor from previous response for pagination"));

    schemaRoot.property(
        ARG_PAGE_SIZE,
        SchemaBuilder.integer(mapper)
            .description(
                "Number of results per page (default: "
                    + DEFAULT_PAGE_LIMIT
                    + ", max: "
                    + MAX_PAGE_LIMIT
                    + ")")
            .minimum(1)
            .maximum(MAX_PAGE_LIMIT));

    schemaRoot.requiredProperty(ARG_ACTION);

    // Conditional requirements based on action
    schemaRoot.allOf(
        // action=list_analysis_options requires file_name
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_ACTION,
                        SchemaBuilder.string(mapper).constValue(ACTION_LIST_ANALYSIS_OPTIONS)),
                SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_FILE_NAME)),
        // action=go_to_address requires file_name and address
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_ACTION, SchemaBuilder.string(mapper).constValue(ACTION_GO_TO_ADDRESS)),
                SchemaBuilder.objectDraft7(mapper)
                    .requiredProperty(ARG_FILE_NAME)
                    .requiredProperty(ARG_ADDRESS)),
        // action=run_analysis requires file_name
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_ACTION, SchemaBuilder.string(mapper).constValue(ACTION_RUN_ANALYSIS)),
                SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_FILE_NAME)),
        // action=undo requires file_name
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(ARG_ACTION, SchemaBuilder.string(mapper).constValue(ACTION_UNDO)),
                SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_FILE_NAME)),
        // action=redo requires file_name
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(ARG_ACTION, SchemaBuilder.string(mapper).constValue(ACTION_REDO)),
                SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_FILE_NAME)),
        // action=history requires file_name
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(ARG_ACTION, SchemaBuilder.string(mapper).constValue(ACTION_HISTORY)),
                SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_FILE_NAME)));

    return schemaRoot.build();
  }

  @Override
  public Mono<? extends Object> execute(
      McpTransportContext context, Map<String, Object> args, PluginTool tool) {
    String action;
    try {
      action = getRequiredStringArgument(args, ARG_ACTION);
    } catch (GhidraMcpException e) {
      return Mono.error(e);
    }
    String normalizedAction = action.toLowerCase();

    // All actions require a program
    return getProgram(args, tool)
        .flatMap(
            program -> {
              return switch (normalizedAction) {
                case ACTION_LIST_ANALYSIS_OPTIONS -> handleListAnalysisOptions(program, args);
                case ACTION_GO_TO_ADDRESS -> handleGoToAddress(program, args, tool);
                case ACTION_RUN_ANALYSIS -> handleRunAnalysis(program);
                case ACTION_SAVE -> handleSave(program);
                case ACTION_UNDO -> handleUndo(program, args);
                case ACTION_REDO -> handleRedo(program, args);
                case ACTION_HISTORY -> handleHistory(program);
                default -> {
                  GhidraMcpError error =
                      GhidraMcpError.invalid(
                          ARG_ACTION,
                          action,
                          "must be one of: "
                              + ACTION_LIST_ANALYSIS_OPTIONS
                              + ", "
                              + ACTION_GO_TO_ADDRESS
                              + ", "
                              + ACTION_RUN_ANALYSIS
                              + ", "
                              + ACTION_SAVE
                              + ", "
                              + ACTION_UNDO
                              + ", "
                              + ACTION_REDO
                              + ", "
                              + ACTION_HISTORY);
                  yield Mono.error(new GhidraMcpException(error));
                }
              };
            });
  }

  // =================== list_analysis_options ===================

  private Mono<? extends Object> handleListAnalysisOptions(
      Program program, Map<String, Object> args) {
    String filter = getOptionalStringArgument(args, ARG_FILTER).orElse("");
    String optionType = getOptionalStringArgument(args, ARG_OPTION_TYPE).orElse("");
    boolean defaultsOnly = getOptionalBooleanArgument(args, ARG_DEFAULTS_ONLY).orElse(false);
    Optional<String> cursorOpt = getOptionalStringArgument(args, ARG_CURSOR);
    int pageSize = getPageSizeArgument(args, DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT);

    return listAnalysisOptions(program, filter, optionType, defaultsOnly, cursorOpt, pageSize);
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
                                          ACTION_LIST_ANALYSIS_OPTIONS,
                                          Map.of(ARG_FILE_NAME, program.getName()),
                                          Map.of(),
                                          Map.of("analysis_options_available", false)))
                                  .build()));

          final String cursorName =
              cursorOpt
                  .map(
                      value ->
                          decodeOpaqueCursorSingleV1(
                              value, ARG_CURSOR, "v1:<base64url_option_name>"))
                  .orElse(null);
          boolean passedCursor = (cursorName == null);
          boolean cursorMatched = (cursorName == null);

          List<AnalysisOptionInfo> allOptions = new ArrayList<>();
          List<String> sortedNames =
              analysisOptions.getOptionNames().stream()
                  .sorted(String.CASE_INSENSITIVE_ORDER)
                  .toList();

          for (String optName : sortedNames) {
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
    OptionType optType = analysisOptions.getType(optionName);
    String value =
        Optional.ofNullable(analysisOptions.getObject(optionName, null))
            .map(Object::toString)
            .orElse("null");
    boolean usingDefault = analysisOptions.isDefaultValue(optionName);
    String description = analysisOptions.getDescription(optionName);

    return new AnalysisOptionInfo(
        optionName,
        description,
        Optional.ofNullable(optType).map(Object::toString).orElse("unknown"),
        value,
        usingDefault);
  }

  // =================== go_to_address ===================

  private Mono<? extends Object> handleGoToAddress(
      Program program, Map<String, Object> args, PluginTool tool) {
    String addressStr;
    try {
      addressStr = getRequiredStringArgument(args, ARG_ADDRESS);
    } catch (GhidraMcpException e) {
      return Mono.error(e);
    }
    return parseAddress(program, addressStr, ACTION_GO_TO_ADDRESS)
        .flatMap(
            addressResult ->
                Mono.fromCallable(
                    () -> {
                      Address address = addressResult.getAddress();
                      GoToService goToService =
                          tool != null ? tool.getService(GoToService.class) : null;
                      if (goToService == null) {
                        GhidraMcpError error =
                            GhidraMcpError.of(
                                "GoToService is not available in the current tool context.");
                        throw new GhidraMcpException(error);
                      }

                      boolean success = goToService.goTo(address, program);
                      if (!success) {
                        String normalizedAddress = addressResult.getAddressString();
                        GhidraMcpError error =
                            GhidraMcpError.failed(
                                "navigate to address " + normalizedAddress,
                                "ensure Listing or Decompiler views are open");
                        throw new GhidraMcpException(error);
                      }

                      return OperationResult.success(
                          ACTION_GO_TO_ADDRESS,
                          address.toString(),
                          "Navigation completed successfully.");
                    }));
  }

  // =================== run_analysis ===================

  private Mono<? extends Object> handleRunAnalysis(Program program) {
    return Mono.fromCallable(
        () -> {
          AutoAnalysisManager analysisManager = AutoAnalysisManager.getAnalysisManager(program);
          if (analysisManager == null) {
            throw new GhidraMcpException(
                GhidraMcpError.failed(
                    "run analysis", "AutoAnalysisManager is not available for this program."));
          }

          analysisManager.reAnalyzeAll(program.getMemory());
          analysisManager.startAnalysis(TaskMonitor.DUMMY);

          return OperationResult.success(
              ACTION_RUN_ANALYSIS,
              program.getName(),
              "Auto-analysis triggered successfully on '" + program.getName() + "'.");
        });
  }

  // =================== save ===================

  private Mono<? extends Object> handleSave(Program program) {
    return Mono.fromCallable(
        () -> {
          ghidra.framework.model.DomainFile domainFile = program.getDomainFile();
          if (domainFile == null) {
            throw new GhidraMcpException(
                GhidraMcpError.failed("save", "Program has no associated domain file."));
          }

          if (!domainFile.canSave()) {
            throw new GhidraMcpException(
                GhidraMcpError.failed(
                    "save", "Program cannot be saved (read-only or no write permission)."));
          }

          domainFile.save(TaskMonitor.DUMMY);

          return OperationResult.success(
              ACTION_SAVE,
              program.getName(),
              "Program '" + program.getName() + "' saved successfully.");
        });
  }

  // =================== undo ===================

  private Mono<? extends Object> handleUndo(Program program, Map<String, Object> args) {
    return executeOnEdt(
        "undo operation",
        () -> {
          if (!program.canUndo()) {
            GhidraMcpError error =
                GhidraMcpError.execution()
                    .errorCode(GhidraMcpError.ErrorCode.INVALID_PROGRAM_STATE)
                    .message("No operations available to undo")
                    .context(
                        new GhidraMcpError.ErrorContext(
                            this.getMcpName(),
                            "undo operation",
                            args,
                            Map.of("can_undo", false),
                            Map.of("undo_available", false)))
                    .suggestions(
                        List.of(
                            new GhidraMcpError.ErrorSuggestion(
                                GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
                                "Check undo/redo status",
                                "Use action 'history' to see available undo/redo operations",
                                null,
                                null)))
                    .build();
            throw new GhidraMcpException(error);
          }

          String undoName = program.getUndoName();
          program.undo();
          Msg.info(this, "Undone operation: " + undoName);

          return createUndoRedoResult("undo", undoName, program);
        });
  }

  // =================== redo ===================

  private Mono<? extends Object> handleRedo(Program program, Map<String, Object> args) {
    return executeOnEdt(
        "redo operation",
        () -> {
          if (!program.canRedo()) {
            GhidraMcpError error =
                GhidraMcpError.execution()
                    .errorCode(GhidraMcpError.ErrorCode.INVALID_PROGRAM_STATE)
                    .message("No operations available to redo")
                    .context(
                        new GhidraMcpError.ErrorContext(
                            this.getMcpName(),
                            "redo operation",
                            args,
                            Map.of("can_redo", false),
                            Map.of("redo_available", false)))
                    .suggestions(
                        List.of(
                            new GhidraMcpError.ErrorSuggestion(
                                GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
                                "Check undo/redo status",
                                "Use action 'history' to see available undo/redo operations",
                                null,
                                null)))
                    .build();
            throw new GhidraMcpException(error);
          }

          String redoName = program.getRedoName();
          program.redo();
          Msg.info(this, "Redone operation: " + redoName);

          return createUndoRedoResult("redo", redoName, program);
        });
  }

  // =================== history ===================

  private Mono<? extends Object> handleHistory(Program program) {
    return Mono.fromCallable(
        () -> {
          Map<String, Object> result = new HashMap<>();
          result.put("action", "history");
          result.put("can_undo", program.canUndo());
          result.put("can_redo", program.canRedo());

          if (program.canUndo()) {
            result.put("next_undo", program.getUndoName());
          }
          if (program.canRedo()) {
            result.put("next_redo", program.getRedoName());
          }

          List<String> undoList = program.getAllUndoNames();
          List<String> redoList = program.getAllRedoNames();

          result.put("undo_list", undoList);
          result.put("redo_list", redoList);
          result.put("undo_count", undoList.size());
          result.put("redo_count", redoList.size());

          return result;
        });
  }

  // =================== helpers ===================

  private Map<String, Object> createUndoRedoResult(
      String action, String operationName, Program program) {
    Map<String, Object> result = new HashMap<>();
    result.put("action", action);
    result.put("success", true);

    if ("undo".equals(action)) {
      result.put("undone_operation", operationName);
    } else if ("redo".equals(action)) {
      result.put("redone_operation", operationName);
    }

    result.put("can_undo", program.canUndo());
    result.put("can_redo", program.canRedo());
    if (program.canUndo()) {
      result.put("next_undo", program.getUndoName());
    }
    if (program.canRedo()) {
      result.put("next_redo", program.getRedoName());
    }

    return result;
  }
}
