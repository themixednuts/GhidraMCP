package com.themixednuts.tools;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.AnalysisOptionInfo;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.models.OperationResult;
import com.themixednuts.ui.GhidraUiCoordinator;
import com.themixednuts.ui.NavigateToAddressEffect;
import com.themixednuts.utils.OpaqueCursorCodec;
import com.themixednuts.utils.PaginatedResult;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.draft7.SchemaBuilder;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.FileByteProvider;
import ghidra.app.util.bin.format.pe.NTHeader;
import ghidra.app.util.bin.format.pe.OptionalHeader;
import ghidra.app.util.bin.format.pe.PortableExecutable;
import ghidra.framework.options.OptionType;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import io.modelcontextprotocol.common.McpTransportContext;
import java.io.File;
import java.nio.file.AccessMode;
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
            + " image rebasing, undo/redo, and transaction history.",
    mcpName = "project",
    mcpDescription =
        """
        <use_case>
        Perform project-level actions such as inspecting analysis options, running analysis,
        navigating to addresses, rebasing program image bases, and managing undo/redo operations.
        </use_case>

        <important_notes>
        - All actions require an open program; provide file_name for those requests.
        - For program metadata, use the ghidra://program/{name}/info resource.
        - For listing available programs, use the ghidra://programs resource.
        - For imports/exports use ghidra://program/{name}/imports and ghidra://program/{name}/exports resources.
        - For defined strings use ghidra://program/{name}/strings resource.
        - Navigation relies on GoToService being available in the active tool.
        - rebase permanently changes the program image base and marks the program changed.
        - rebase can use an explicit image_base or use_stated_image_base=true for PE optional-header ImageBase.
        - Analysis option listing reflects current values and flags options still using defaults.
        - list_analysis_options is bounded by page_size. Pass returned next_cursor as cursor to
          continue with the same filters.
        - Undo/redo operations are performed on the Swing EDT thread.
        </important_notes>

        <return_value_summary>
        - list_analysis_options: returns a paginated list of AnalysisOptionInfo objects.
        - run_analysis: returns OperationResult describing the triggered analysis.
        - save: saves the program to the project, preserving all changes.
        - go_to_address: returns OperationResult describing navigation outcome.
        - rebase: returns OperationResult with previous/new image-base metadata.
        - undo/redo: returns a map with action, success, and current undo/redo state.
        - history: returns a map with available undo/redo operation lists.
        </return_value_summary>

        <agent_response_guidance>
        Summarize the performed action, highlight key fields (e.g., address,
        notable analysis options), and mention any suggested follow-up steps when appropriate.
        </agent_response_guidance>
        """)
public class ProjectTool extends BaseMcpTool {

  private static final String ABSOLUTE_ADDRESS_PATTERN =
      "^([A-Za-z_][A-Za-z0-9_]*:)?(0[xX])?[0-9a-fA-F]+$";

  private static final String ACTION_LIST_ANALYSIS_OPTIONS = "list_analysis_options";
  private static final String ACTION_GO_TO_ADDRESS = "go_to_address";
  private static final String ACTION_RUN_ANALYSIS = "run_analysis";
  private static final String ACTION_SAVE = "save";
  private static final String ACTION_REBASE = "rebase";
  private static final String ACTION_UNDO = "undo";
  private static final String ACTION_REDO = "redo";
  private static final String ACTION_HISTORY = "history";

  // list_analysis_options specific args
  private static final String ARG_OPTION_TYPE = "option_type";
  private static final String ARG_DEFAULTS_ONLY = "defaults_only";
  private static final String ARG_VERBOSE = "verbose";
  private static final String ARG_IMAGE_BASE = "image_base";
  private static final String ARG_USE_STATED_IMAGE_BASE = "use_stated_image_base";

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
                ACTION_REBASE,
                ACTION_UNDO,
                ACTION_REDO,
                ACTION_HISTORY)
            .description("Project-level operation to perform"));

    schemaRoot.property(
        ARG_ADDRESS,
        SchemaBuilder.string(mapper)
            .description("Target address for navigation")
            .pattern(ADDRESS_PATTERN));

    schemaRoot.property(
        ARG_IMAGE_BASE,
        SchemaBuilder.string(mapper)
            .description(
                "Absolute image base address to set for action=rebase, e.g. 0x140000000."
                    + " Must be in the program default address space.")
            .pattern(ABSOLUTE_ADDRESS_PATTERN));

    schemaRoot.property(
        ARG_USE_STATED_IMAGE_BASE,
        SchemaBuilder.bool(mapper)
            .description(
                "For action=rebase, read the preferred ImageBase stated in the original PE"
                    + " optional header instead of using image_base."));

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

    schemaRoot.property(
        ARG_VERBOSE,
        SchemaBuilder.bool(mapper)
            .description("Include long analysis option descriptions. Default false."));

    // Common pagination properties
    schemaRoot.property(
        ARG_CURSOR,
        SchemaBuilder.string(mapper)
            .description(
                "Opaque cursor copied from the previous list_analysis_options next_cursor. Keep"
                    + " filter, option_type, defaults_only, and verbose unchanged."));

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
        // action=rebase requires file_name; image_base vs use_stated_image_base is validated in
        // code
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(ARG_ACTION, SchemaBuilder.string(mapper).constValue(ACTION_REBASE)),
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
                case ACTION_REBASE -> handleRebase(program, args);
                case ACTION_UNDO -> handleUndo(program, args);
                case ACTION_REDO -> handleRedo(program, args);
                case ACTION_HISTORY -> handleHistory(program);
                default -> {
                  // Program metadata and program lists live on the ghidra:// resources, not on
                  // this tool. Redirect common metadata-style guesses to the right surface.
                  java.util.Map<String, String> aliases =
                      java.util.Map.ofEntries(
                          java.util.Map.entry(
                              "info",
                              "use the ghidra://program/{name} resource for program metadata"),
                          java.util.Map.entry(
                              "list_programs", "use the ghidra://programs resource"),
                          java.util.Map.entry("list", "use the ghidra://programs resource"),
                          java.util.Map.entry("analyze", ACTION_RUN_ANALYSIS),
                          java.util.Map.entry("analysis", ACTION_LIST_ANALYSIS_OPTIONS),
                          java.util.Map.entry("options", ACTION_LIST_ANALYSIS_OPTIONS),
                          java.util.Map.entry("goto", ACTION_GO_TO_ADDRESS),
                          java.util.Map.entry("navigate", ACTION_GO_TO_ADDRESS),
                          java.util.Map.entry("set_image_base", ACTION_REBASE),
                          java.util.Map.entry("image_base", ACTION_REBASE),
                          java.util.Map.entry("rebase_image", ACTION_REBASE));
                  GhidraMcpError error =
                      com.themixednuts.utils.GhidraMcpErrorUtils.invalidAction(
                          action,
                          java.util.List.of(
                              ACTION_LIST_ANALYSIS_OPTIONS,
                              ACTION_GO_TO_ADDRESS,
                              ACTION_RUN_ANALYSIS,
                              ACTION_SAVE,
                              ACTION_REBASE,
                              ACTION_UNDO,
                              ACTION_REDO,
                              ACTION_HISTORY),
                          aliases);
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
    boolean verbose = getOptionalBooleanArgument(args, ARG_VERBOSE).orElse(false);
    Optional<String> cursorOpt = getOptionalStringArgument(args, ARG_CURSOR);
    int pageSize = getPageSizeArgument(args, DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT);

    return listAnalysisOptions(
        program, filter, optionType, defaultsOnly, verbose, cursorOpt, pageSize);
  }

  private Mono<PaginatedResult<AnalysisOptionInfo>> listAnalysisOptions(
      Program program,
      String filter,
      String optionType,
      boolean defaultsOnly,
      boolean verbose,
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

            AnalysisOptionInfo option = createAnalysisOptionInfo(analysisOptions, optName, verbose);

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

  private AnalysisOptionInfo createAnalysisOptionInfo(
      Options analysisOptions, String optionName, boolean verbose) {
    OptionType optType = analysisOptions.getType(optionName);
    String value =
        Optional.ofNullable(analysisOptions.getObject(optionName, null))
            .map(Object::toString)
            .orElse(null);
    boolean usingDefault = analysisOptions.isDefaultValue(optionName);
    String description = analysisOptions.getDescription(optionName);

    return new AnalysisOptionInfo(
        optionName,
        description,
        Optional.ofNullable(optType).map(Object::toString).orElse(null),
        value,
        usingDefault,
        verbose);
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
                      GhidraUiCoordinator.applyRequired(
                          tool, NavigateToAddressEffect.listing(program, address));

                      return OperationResult.success(
                          ACTION_GO_TO_ADDRESS,
                          address.toString(),
                          "Navigation completed successfully.");
                    }));
  }

  // =================== run_analysis ===================

  private Mono<? extends Object> handleRunAnalysis(Program program) {
    return withTaskMonitor(
        "project.run_analysis",
        monitor -> {
          AutoAnalysisManager analysisManager = AutoAnalysisManager.getAnalysisManager(program);
          if (analysisManager == null) {
            throw new GhidraMcpException(
                GhidraMcpError.failed(
                    "run analysis", "AutoAnalysisManager is not available for this program."));
          }

          analysisManager.reAnalyzeAll(program.getMemory());
          analysisManager.startAnalysis(monitor);

          return OperationResult.success(
              ACTION_RUN_ANALYSIS,
              program.getName(),
              "Auto-analysis triggered successfully on '" + program.getName() + "'.");
        });
  }

  // =================== save ===================

  private Mono<? extends Object> handleSave(Program program) {
    return withTaskMonitor(
        "project.save",
        monitor -> {
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

          domainFile.save(monitor);

          return OperationResult.success(
              ACTION_SAVE,
              program.getName(),
              "Program '" + program.getName() + "' saved successfully.");
        });
  }

  // =================== rebase ===================

  private Mono<? extends Object> handleRebase(Program program, Map<String, Object> args) {
    Optional<String> explicitImageBase = getOptionalStringArgument(args, ARG_IMAGE_BASE);
    boolean useStatedImageBase =
        getOptionalBooleanArgument(args, ARG_USE_STATED_IMAGE_BASE).orElse(false);

    if (explicitImageBase.isPresent() && useStatedImageBase) {
      return Mono.error(
          new GhidraMcpException(
              GhidraMcpError.invalid(
                  ARG_USE_STATED_IMAGE_BASE, true, "cannot be combined with " + ARG_IMAGE_BASE)));
    }
    if (explicitImageBase.isEmpty() && !useStatedImageBase) {
      return Mono.error(
          new GhidraMcpException(
              GhidraMcpError.invalid(
                  ARG_IMAGE_BASE,
                  null,
                  "provide an explicit image_base or set use_stated_image_base=true")));
    }

    return Mono.fromCallable(
            () -> {
              ResolvedImageBase resolved =
                  useStatedImageBase
                      ? resolveStatedImageBase(program)
                      : resolveExplicitImageBase(program, explicitImageBase.get());
              Address previousBase = program.getImageBase();
              boolean changed = previousBase == null || !previousBase.equals(resolved.address());
              return new RebasePlan(resolved, previousBase, changed);
            })
        .flatMap(
            plan -> {
              if (!plan.changed()) {
                return Mono.just(
                    createRebaseResult(
                        program, plan.resolved(), plan.previousBase(), plan.previousBase(), false));
              }

              return executeInTransaction(
                  program,
                  "project.rebase",
                  () -> {
                    program.setImageBase(plan.resolved().address(), true);
                    Address newBase = program.getImageBase();
                    return createRebaseResult(
                        program, plan.resolved(), plan.previousBase(), newBase, true);
                  });
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

          return result;
        });
  }

  // =================== helpers ===================

  private ResolvedImageBase resolveExplicitImageBase(Program program, String imageBaseString)
      throws GhidraMcpException {
    String input = imageBaseString == null ? "" : imageBaseString.trim();
    if (input.isEmpty()) {
      throw new GhidraMcpException(GhidraMcpError.parse(ARG_IMAGE_BASE, imageBaseString));
    }
    if (input.contains("+")) {
      throw new GhidraMcpException(
          GhidraMcpError.invalid(
              ARG_IMAGE_BASE,
              imageBaseString,
              "must be an absolute address, not an image-base-relative offset"));
    }

    return new ResolvedImageBase(
        parseDefaultSpaceAddress(program, input, ARG_IMAGE_BASE), "explicit", null, null);
  }

  private ResolvedImageBase resolveStatedImageBase(Program program) throws GhidraMcpException {
    String executablePath = Optional.ofNullable(program.getExecutablePath()).orElse("").trim();
    if (executablePath.isEmpty()) {
      throw new GhidraMcpException(
          GhidraMcpError.failed(
              "read stated image base",
              "Program executable_path is empty; provide image_base explicitly."));
    }

    File executableFile = new File(executablePath);
    if (!executableFile.isFile()) {
      throw new GhidraMcpException(
          GhidraMcpError.failed(
              "read stated image base",
              "Program executable_path does not refer to a readable file: "
                  + executableFile.getAbsolutePath()
                  + ". Provide image_base explicitly."));
    }

    try (ByteProvider provider = new FileByteProvider(executableFile, null, AccessMode.READ)) {
      PortableExecutable pe =
          new PortableExecutable(provider, PortableExecutable.SectionLayout.FILE, false, false);
      NTHeader ntHeader = pe.getNTHeader();
      if (ntHeader == null) {
        throw new GhidraMcpException(
            GhidraMcpError.failed(
                "read stated image base", "PE NT header was not present in executable_path."));
      }
      OptionalHeader optionalHeader = ntHeader.getOptionalHeader();
      if (optionalHeader == null) {
        throw new GhidraMcpException(
            GhidraMcpError.failed(
                "read stated image base",
                "PE optional header was not present in executable_path."));
      }

      String statedImageBase = toUnsignedHexAddress(optionalHeader.getImageBase());
      Address imageBase =
          parseDefaultSpaceAddress(program, statedImageBase, ARG_USE_STATED_IMAGE_BASE);
      return new ResolvedImageBase(
          imageBase, "pe_optional_header", executableFile.getAbsolutePath(), statedImageBase);
    } catch (GhidraMcpException e) {
      throw e;
    } catch (Exception e) {
      throw new GhidraMcpException(
          GhidraMcpError.failed(
              "read stated image base",
              "Unable to read a PE optional-header ImageBase from executable_path '"
                  + executableFile.getAbsolutePath()
                  + "': "
                  + Optional.ofNullable(e.getMessage()).orElse(e.getClass().getSimpleName())
                  + ". Provide image_base explicitly for non-PE or missing original files."),
          e);
    }
  }

  private Address parseDefaultSpaceAddress(
      Program program, String addressString, String argumentName) throws GhidraMcpException {
    Address address = program.getAddressFactory().getAddress(addressString);
    if (address == null) {
      throw new GhidraMcpException(GhidraMcpError.parse(argumentName, addressString));
    }

    AddressSpace defaultSpace = program.getAddressFactory().getDefaultAddressSpace();
    if (defaultSpace != null && !defaultSpace.equals(address.getAddressSpace())) {
      throw new GhidraMcpException(
          GhidraMcpError.invalid(
              argumentName,
              addressString,
              "must resolve in the program default address space '"
                  + defaultSpace.getName()
                  + "'"));
    }
    return address;
  }

  private OperationResult createRebaseResult(
      Program program,
      ResolvedImageBase resolved,
      Address previousBase,
      Address newBase,
      boolean changed) {
    String message =
        changed
            ? "Image base rebased successfully."
            : "Image base already matched the requested base.";

    Map<String, Object> metadata = new HashMap<>();
    metadata.put("program", program.getName());
    metadata.put("previous_image_base", formatAddress(previousBase));
    metadata.put("new_image_base", formatAddress(newBase));
    metadata.put("changed", changed);
    metadata.put("source", resolved.source());
    metadata.put("commit", true);
    putIfPresent(metadata, "source_detail", resolved.sourceDetail());
    putIfPresent(metadata, "stated_image_base", resolved.statedImageBase());

    return OperationResult.success(ACTION_REBASE, formatAddress(newBase), message)
        .setMetadata(metadata);
  }

  private void putIfPresent(Map<String, Object> map, String key, Object value) {
    if (value != null) {
      map.put(key, value);
    }
  }

  private String formatAddress(Address address) {
    return address != null ? address.toString() : null;
  }

  private String toUnsignedHexAddress(long value) {
    return "0x" + Long.toUnsignedString(value, 16);
  }

  private Map<String, Object> createUndoRedoResult(
      String action, String operationName, Program program) {
    Map<String, Object> result = new HashMap<>();
    result.put("action", action);
    // 'success: true' inside the data payload would duplicate the envelope's success signal.
    // Failure throws GhidraMcpException, so reaching this builder already implies success.

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

  private record ResolvedImageBase(
      Address address, String source, String sourceDetail, String statedImageBase) {}

  private record RebasePlan(ResolvedImageBase resolved, Address previousBase, boolean changed) {}
}
