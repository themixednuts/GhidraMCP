package com.themixednuts.tools.versiontracking;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.models.versiontracking.VTCorrelatorInfo;
import com.themixednuts.models.versiontracking.VTMarkupItemInfo;
import com.themixednuts.models.versiontracking.VTMatchInfo;
import com.themixednuts.utils.OpaqueCursorCodec;
import com.themixednuts.utils.PaginatedResult;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.draft7.SchemaBuilder;
import ghidra.feature.vt.api.main.VTAssociation;
import ghidra.feature.vt.api.main.VTAssociationStatus;
import ghidra.feature.vt.api.main.VTAssociationType;
import ghidra.feature.vt.api.main.VTMarkupItem;
import ghidra.feature.vt.api.main.VTMarkupItemApplyActionType;
import ghidra.feature.vt.api.main.VTMatch;
import ghidra.feature.vt.api.main.VTMatchSet;
import ghidra.feature.vt.api.main.VTSession;
import ghidra.feature.vt.api.util.VersionTrackingApplyException;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.common.McpTransportContext;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import reactor.core.publisher.Mono;

@GhidraMcpTool(
    name = "VT Operations",
    description = "Manage Version Tracking matches, markup, and correlators within a VT session.",
    mcpName = "vt_operations",
    mcpDescription =
        """
        <use_case>
        Perform all Version Tracking operations within a session: run correlators to find matches,
        list/accept/reject matches, and apply/unapply markup items to migrate analysis between
        source and destination programs.
        </use_case>

        <important_notes>
        - Session must be created first with vt_sessions
        - Actions for matches: accept, reject, clear, accept_bulk, reject_bulk, list_matches
        - Actions for correlators: list_correlators, run_correlator
        - Actions for markup: list_markup, apply_markup, apply_all_markup, unapply_markup
        - Accepting a match may block other matches that conflict with it
        - Markup can only be applied to ACCEPTED matches
        - Changes are persisted to the VT session file automatically
        - run_correlator on large binaries may take minutes — if the client times out, the
          correlator still completes server-side. Check vt_sessions (action: info) for results.
        - Use exclude_default_names: true in list_matches to find matches with user-defined source
          names worth propagating to the destination binary
        - Standard workflow: run correlators -> check session info -> accept matches -> apply markup
        </important_notes>

        <return_value_summary>
        - accept/reject/clear: Returns affected count and blocked count
        - accept_bulk/reject_bulk: Returns count of matches processed
        - list_matches: Returns paginated VTMatchInfo list
        - list_correlators: Returns available correlator types
        - run_correlator: Returns match count from correlator run
        - list_markup/apply_markup/apply_all_markup/unapply_markup: Returns markup operation results
        </return_value_summary>
        """)
public class VTOperationsTool extends BaseVTTool {

  public static final String ARG_SOURCE_ADDRESS = "source_address";
  public static final String ARG_DESTINATION_ADDRESS = "destination_address";
  public static final String ARG_MIN_SIMILARITY = "min_similarity";
  public static final String ARG_MIN_CONFIDENCE = "min_confidence";
  public static final String ARG_MAX_SIMILARITY = "max_similarity";
  public static final String ARG_MAX_CONFIDENCE = "max_confidence";
  public static final String ARG_STATUS = "status";
  public static final String ARG_MATCH_TYPE = "match_type";
  public static final String ARG_CORRELATOR = "correlator";
  public static final String ARG_CORRELATOR_TYPE = "correlator_type";
  public static final String ARG_SOURCE_MIN_ADDRESS = "source_min_address";
  public static final String ARG_SOURCE_MAX_ADDRESS = "source_max_address";
  public static final String ARG_DEST_MIN_ADDRESS = "destination_min_address";
  public static final String ARG_DEST_MAX_ADDRESS = "destination_max_address";
  public static final String ARG_EXCLUDE_ACCEPTED = "exclude_accepted";
  public static final String ARG_MARKUP_TYPES = "markup_types";
  public static final String ARG_APPLY_ACTION = "apply_action";
  public static final String ARG_EXCLUDE_DEFAULT_NAMES = "exclude_default_names";

  private static final Set<String> DEFAULT_NAME_PREFIXES =
      Set.of("FUN_", "thunk_FUN_", "DAT_", "LAB_", "s_", "PTR_", "switchD_", "caseD_", "EXTERNAL_");

  // Match management actions
  private static final String ACTION_ACCEPT = "accept";
  private static final String ACTION_REJECT = "reject";
  private static final String ACTION_CLEAR = "clear";
  private static final String ACTION_ACCEPT_BULK = "accept_bulk";
  private static final String ACTION_REJECT_BULK = "reject_bulk";

  // Match reading actions
  private static final String ACTION_LIST_MATCHES = "list_matches";

  // Correlator actions
  private static final String ACTION_LIST_CORRELATORS = "list_correlators";
  private static final String ACTION_RUN_CORRELATOR = "run_correlator";

  // Markup actions
  private static final String ACTION_LIST_MARKUP = "list_markup";
  private static final String ACTION_APPLY_MARKUP = "apply_markup";
  private static final String ACTION_APPLY_ALL_MARKUP = "apply_all_markup";
  private static final String ACTION_UNAPPLY_MARKUP = "unapply_markup";

  // Built-in correlator factory class names
  private static final Map<String, String> CORRELATOR_CLASS_MAP = new HashMap<>();

  static {
    CORRELATOR_CLASS_MAP.put(
        "exact_bytes",
        "ghidra.feature.vt.api.correlator.program.ExactMatchBytesProgramCorrelatorFactory");
    CORRELATOR_CLASS_MAP.put(
        "exact_instructions",
        "ghidra.feature.vt.api.correlator.program.ExactMatchInstructionsProgramCorrelatorFactory");
    CORRELATOR_CLASS_MAP.put(
        "exact_data",
        "ghidra.feature.vt.api.correlator.program.ExactDataMatchProgramCorrelatorFactory");
    CORRELATOR_CLASS_MAP.put(
        "symbol_name",
        "ghidra.feature.vt.api.correlator.program.SymbolNameProgramCorrelatorFactory");
  }

  // Mapping of user-friendly names to VT markup type class name substrings
  private static final Map<String, String> MARKUP_TYPE_MAP = new HashMap<>();

  static {
    MARKUP_TYPE_MAP.put("function_name", "FunctionName");
    MARKUP_TYPE_MAP.put("function_signature", "FunctionSignature");
    MARKUP_TYPE_MAP.put("labels", "Label");
    MARKUP_TYPE_MAP.put("comment_eol", "EolComment");
    MARKUP_TYPE_MAP.put("comment_plate", "PlateComment");
    MARKUP_TYPE_MAP.put("comment_pre", "PreComment");
    MARKUP_TYPE_MAP.put("comment_post", "PostComment");
    MARKUP_TYPE_MAP.put("comment_repeatable", "RepeatableComment");
  }

  @Override
  public JsonSchema schema() {
    var schemaRoot = createDraft7SchemaNode();

    schemaRoot.property(
        ARG_ACTION,
        SchemaBuilder.string(mapper)
            .enumValues(
                ACTION_ACCEPT,
                ACTION_REJECT,
                ACTION_CLEAR,
                ACTION_ACCEPT_BULK,
                ACTION_REJECT_BULK,
                ACTION_LIST_MATCHES,
                ACTION_LIST_CORRELATORS,
                ACTION_RUN_CORRELATOR,
                ACTION_LIST_MARKUP,
                ACTION_APPLY_MARKUP,
                ACTION_APPLY_ALL_MARKUP,
                ACTION_UNAPPLY_MARKUP)
            .description("The VT operation to perform"));

    schemaRoot.property(
        ARG_SESSION_NAME, SchemaBuilder.string(mapper).description("Name of the VT session"));

    schemaRoot.property(
        ARG_SOURCE_ADDRESS,
        SchemaBuilder.string(mapper).description("Source address of the match"));

    schemaRoot.property(
        ARG_DESTINATION_ADDRESS,
        SchemaBuilder.string(mapper).description("Destination address of the match"));

    schemaRoot.property(
        ARG_MIN_SIMILARITY,
        SchemaBuilder.number(mapper)
            .description("Minimum similarity score (0.0 to 1.0)")
            .minimum(0.0)
            .maximum(1.0));

    schemaRoot.property(
        ARG_MIN_CONFIDENCE,
        SchemaBuilder.number(mapper).description("Minimum confidence score (>= 0.0)").minimum(0.0));

    schemaRoot.property(
        ARG_MAX_SIMILARITY,
        SchemaBuilder.number(mapper)
            .description("Maximum similarity score for bulk reject (0.0 to 1.0)")
            .minimum(0.0)
            .maximum(1.0));

    schemaRoot.property(
        ARG_MAX_CONFIDENCE,
        SchemaBuilder.number(mapper)
            .description("Maximum confidence score for bulk reject (>= 0.0)")
            .minimum(0.0));

    schemaRoot.property(
        ARG_STATUS,
        SchemaBuilder.string(mapper)
            .enumValues("AVAILABLE", "ACCEPTED", "REJECTED", "BLOCKED")
            .description("Filter by match status (for list_matches)"));

    schemaRoot.property(
        ARG_MATCH_TYPE,
        SchemaBuilder.string(mapper)
            .enumValues("FUNCTION", "DATA")
            .description("Filter by match type (for list_matches)"));

    schemaRoot.property(
        ARG_CORRELATOR,
        SchemaBuilder.string(mapper).description("Filter by correlator name (for list_matches)"));

    schemaRoot.property(
        ARG_CORRELATOR_TYPE,
        SchemaBuilder.string(mapper)
            .enumValues("exact_bytes", "exact_instructions", "exact_data", "symbol_name")
            .description("Type of correlator to run (for run_correlator)"));

    schemaRoot.property(
        ARG_SOURCE_MIN_ADDRESS,
        SchemaBuilder.string(mapper).description("Minimum address in source program to correlate"));

    schemaRoot.property(
        ARG_SOURCE_MAX_ADDRESS,
        SchemaBuilder.string(mapper).description("Maximum address in source program to correlate"));

    schemaRoot.property(
        ARG_DEST_MIN_ADDRESS,
        SchemaBuilder.string(mapper)
            .description("Minimum address in destination program to correlate"));

    schemaRoot.property(
        ARG_DEST_MAX_ADDRESS,
        SchemaBuilder.string(mapper)
            .description("Maximum address in destination program to correlate"));

    schemaRoot.property(
        ARG_EXCLUDE_ACCEPTED,
        SchemaBuilder.bool(mapper)
            .description("Exclude addresses that already have accepted matches (default: true)"));

    String[] markupTypes = MARKUP_TYPE_MAP.keySet().toArray(new String[0]);
    schemaRoot.property(
        ARG_MARKUP_TYPES,
        SchemaBuilder.array(mapper)
            .items(SchemaBuilder.string(mapper).enumValues(markupTypes))
            .description("List of markup types to apply/unapply (omit to apply all available)"));

    schemaRoot.property(
        ARG_APPLY_ACTION,
        SchemaBuilder.string(mapper)
            .enumValues("REPLACE", "ADD")
            .description(
                "How to apply markup: REPLACE (overwrite) or ADD (merge). Default: REPLACE"));

    schemaRoot.property(
        ARG_EXCLUDE_DEFAULT_NAMES,
        SchemaBuilder.bool(mapper)
            .description(
                "When true, skip matches whose source function name starts with a default"
                    + " prefix (FUN_, thunk_FUN_, DAT_, LAB_, s_, PTR_, switchD_, caseD_,"
                    + " EXTERNAL_). Only applies to list_matches."));

    schemaRoot.property(
        ARG_CURSOR,
        SchemaBuilder.string(mapper)
            .description("Pagination cursor from previous request (for list_matches)"));

    schemaRoot.property(
        ARG_PAGE_SIZE,
        SchemaBuilder.integer(mapper)
            .description(
                "Number of matches to return per page (default: "
                    + DEFAULT_PAGE_LIMIT
                    + ", max: "
                    + MAX_PAGE_LIMIT
                    + ")")
            .minimum(1)
            .maximum(MAX_PAGE_LIMIT));

    schemaRoot.requiredProperty(ARG_ACTION);

    // Conditional requirements
    schemaRoot.allOf(
        // accept/reject/clear require session_name, source_address, destination_address
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(ARG_ACTION, SchemaBuilder.string(mapper).constValue(ACTION_ACCEPT)),
                SchemaBuilder.objectDraft7(mapper)
                    .requiredProperty(ARG_SESSION_NAME)
                    .requiredProperty(ARG_SOURCE_ADDRESS)
                    .requiredProperty(ARG_DESTINATION_ADDRESS)),
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(ARG_ACTION, SchemaBuilder.string(mapper).constValue(ACTION_REJECT)),
                SchemaBuilder.objectDraft7(mapper)
                    .requiredProperty(ARG_SESSION_NAME)
                    .requiredProperty(ARG_SOURCE_ADDRESS)
                    .requiredProperty(ARG_DESTINATION_ADDRESS)),
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(ARG_ACTION, SchemaBuilder.string(mapper).constValue(ACTION_CLEAR)),
                SchemaBuilder.objectDraft7(mapper)
                    .requiredProperty(ARG_SESSION_NAME)
                    .requiredProperty(ARG_SOURCE_ADDRESS)
                    .requiredProperty(ARG_DESTINATION_ADDRESS)),
        // accept_bulk/reject_bulk require session_name
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_ACTION, SchemaBuilder.string(mapper).constValue(ACTION_ACCEPT_BULK)),
                SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_SESSION_NAME)),
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_ACTION, SchemaBuilder.string(mapper).constValue(ACTION_REJECT_BULK)),
                SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_SESSION_NAME)),
        // list_matches requires session_name
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_ACTION, SchemaBuilder.string(mapper).constValue(ACTION_LIST_MATCHES)),
                SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_SESSION_NAME)),
        // run_correlator requires session_name and correlator_type
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_ACTION, SchemaBuilder.string(mapper).constValue(ACTION_RUN_CORRELATOR)),
                SchemaBuilder.objectDraft7(mapper)
                    .requiredProperty(ARG_SESSION_NAME)
                    .requiredProperty(ARG_CORRELATOR_TYPE)),
        // list_markup requires session_name, source_address, destination_address
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_ACTION, SchemaBuilder.string(mapper).constValue(ACTION_LIST_MARKUP)),
                SchemaBuilder.objectDraft7(mapper)
                    .requiredProperty(ARG_SESSION_NAME)
                    .requiredProperty(ARG_SOURCE_ADDRESS)
                    .requiredProperty(ARG_DESTINATION_ADDRESS)),
        // apply_markup requires session_name, source_address, destination_address
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_ACTION, SchemaBuilder.string(mapper).constValue(ACTION_APPLY_MARKUP)),
                SchemaBuilder.objectDraft7(mapper)
                    .requiredProperty(ARG_SESSION_NAME)
                    .requiredProperty(ARG_SOURCE_ADDRESS)
                    .requiredProperty(ARG_DESTINATION_ADDRESS)),
        // apply_all_markup requires session_name
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_ACTION,
                        SchemaBuilder.string(mapper).constValue(ACTION_APPLY_ALL_MARKUP)),
                SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_SESSION_NAME)),
        // unapply_markup requires session_name, source_address, destination_address
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_ACTION, SchemaBuilder.string(mapper).constValue(ACTION_UNAPPLY_MARKUP)),
                SchemaBuilder.objectDraft7(mapper)
                    .requiredProperty(ARG_SESSION_NAME)
                    .requiredProperty(ARG_SOURCE_ADDRESS)
                    .requiredProperty(ARG_DESTINATION_ADDRESS)));

    return schemaRoot.build();
  }

  @Override
  public Mono<? extends Object> execute(
      McpTransportContext context, Map<String, Object> args, PluginTool tool) {
    return Mono.fromCallable(
        () -> {
          String action = getRequiredStringArgument(args, ARG_ACTION);
          String normalizedAction = action.toLowerCase();

          return switch (normalizedAction) {
            // Match management
            case ACTION_ACCEPT -> handleMatchAction(args, VTAssociationStatus.ACCEPTED);
            case ACTION_REJECT -> handleMatchAction(args, VTAssociationStatus.REJECTED);
            case ACTION_CLEAR -> handleMatchAction(args, VTAssociationStatus.AVAILABLE);
            case ACTION_ACCEPT_BULK -> handleBulkAccept(args);
            case ACTION_REJECT_BULK -> handleBulkReject(args);
            // Match reading
            case ACTION_LIST_MATCHES -> handleListMatches(args);
            // Correlators
            case ACTION_LIST_CORRELATORS -> handleListCorrelators();
            case ACTION_RUN_CORRELATOR -> handleRunCorrelator(args);
            // Markup
            case ACTION_LIST_MARKUP -> handleListMarkup(args);
            case ACTION_APPLY_MARKUP -> handleApplyMarkup(args);
            case ACTION_APPLY_ALL_MARKUP -> handleApplyAllMarkup(args);
            case ACTION_UNAPPLY_MARKUP -> handleUnapplyMarkup(args);
            default ->
                throw new GhidraMcpException(
                    GhidraMcpError.invalid(
                        ARG_ACTION,
                        action,
                        "must be one of: "
                            + ACTION_ACCEPT
                            + ", "
                            + ACTION_REJECT
                            + ", "
                            + ACTION_CLEAR
                            + ", "
                            + ACTION_ACCEPT_BULK
                            + ", "
                            + ACTION_REJECT_BULK
                            + ", "
                            + ACTION_LIST_MATCHES
                            + ", "
                            + ACTION_LIST_CORRELATORS
                            + ", "
                            + ACTION_RUN_CORRELATOR
                            + ", "
                            + ACTION_LIST_MARKUP
                            + ", "
                            + ACTION_APPLY_MARKUP
                            + ", "
                            + ACTION_APPLY_ALL_MARKUP
                            + ", "
                            + ACTION_UNAPPLY_MARKUP));
          };
        });
  }

  // =================== Match Management ===================

  private Object handleMatchAction(Map<String, Object> args, VTAssociationStatus newStatus)
      throws GhidraMcpException {
    String sessionName = getRequiredStringArgument(args, ARG_SESSION_NAME);
    return withSession(sessionName, session -> handleSingleMatch(session, args, newStatus));
  }

  private Map<String, Object> handleSingleMatch(
      VTSession session, Map<String, Object> args, VTAssociationStatus newStatus)
      throws GhidraMcpException {
    String sourceAddrStr = getRequiredStringArgument(args, ARG_SOURCE_ADDRESS);
    String destAddrStr = getRequiredStringArgument(args, ARG_DESTINATION_ADDRESS);

    VTMatchResolver.ResolvedMatch resolvedMatch =
        VTMatchResolver.findMatch(
            session, sourceAddrStr, destAddrStr, ARG_SOURCE_ADDRESS, ARG_DESTINATION_ADDRESS);
    VTMatch targetMatch = resolvedMatch.match();

    int blockedCount = 0;
    int blockedBefore =
        VTMatchResolver.countMatchesWithStatus(session, VTAssociationStatus.BLOCKED);

    blockedCount =
        inSessionTransaction(
            session,
            "Set Match Status",
            "Failed to update match status: ",
            () -> {
              VTAssociation association = targetMatch.getAssociation();

              if (newStatus == VTAssociationStatus.ACCEPTED) {
                association.setAccepted();
                int blockedAfter =
                    VTMatchResolver.countMatchesWithStatus(session, VTAssociationStatus.BLOCKED);
                return Math.max(0, blockedAfter - blockedBefore);
              }

              if (newStatus == VTAssociationStatus.REJECTED) {
                association.setRejected();
              } else {
                association.clearStatus();
              }
              return 0;
            });

    String actionName = actionNameForStatus(newStatus);

    Map<String, Object> result = new HashMap<>();
    result.put("action", actionName);
    result.put("source_address", sourceAddrStr);
    result.put("destination_address", destAddrStr);
    result.put("affected_count", 1);
    if (newStatus == VTAssociationStatus.ACCEPTED && blockedCount > 0) {
      result.put("blocked_count", blockedCount);
    }

    return result;
  }

  static String actionNameForStatus(VTAssociationStatus status) {
    return switch (status) {
      case ACCEPTED -> ACTION_ACCEPT;
      case REJECTED -> ACTION_REJECT;
      case AVAILABLE -> ACTION_CLEAR;
      default -> status.name().toLowerCase();
    };
  }

  private Object handleBulkAccept(Map<String, Object> args) throws GhidraMcpException {
    String sessionName = getRequiredStringArgument(args, ARG_SESSION_NAME);
    return withSession(
        sessionName,
        session -> {
          Optional<Double> minSimilarity =
              getOptionalBoundedDoubleArgument(args, ARG_MIN_SIMILARITY, 0.0, 1.0);
          Optional<Double> minConfidence =
              getOptionalBoundedDoubleArgument(args, ARG_MIN_CONFIDENCE, 0.0, null);

          if (minSimilarity.isEmpty() && minConfidence.isEmpty()) {
            throw new GhidraMcpException(
                GhidraMcpError.validation()
                    .errorCode(GhidraMcpError.ErrorCode.MISSING_REQUIRED_ARGUMENT)
                    .message(
                        "At least one of min_similarity or min_confidence is required for"
                            + " bulk accept")
                    .build());
          }

          List<VTMatch> matchesToAccept = new ArrayList<>();

          for (VTMatchSet matchSet : session.getMatchSets()) {
            for (VTMatch match : matchSet.getMatches()) {
              VTAssociationStatus status = match.getAssociation().getStatus();
              if (status != VTAssociationStatus.AVAILABLE) {
                continue;
              }

              double similarity = match.getSimilarityScore().getScore();
              double confidence = match.getConfidenceScore().getScore();

              boolean meetsCriteria = true;
              if (minSimilarity.isPresent() && similarity < minSimilarity.get()) {
                meetsCriteria = false;
              }
              if (minConfidence.isPresent() && confidence < minConfidence.get()) {
                meetsCriteria = false;
              }

              if (meetsCriteria) {
                matchesToAccept.add(match);
              }
            }
          }

          int blockedBefore =
              VTMatchResolver.countMatchesWithStatus(session, VTAssociationStatus.BLOCKED);

          int[] transactionResult =
              inSessionTransaction(
                  session,
                  "Bulk Accept Matches",
                  "Bulk accept failed: ",
                  () -> {
                    int accepted = 0;
                    for (VTMatch match : matchesToAccept) {
                      try {
                        match.getAssociation().setAccepted();
                        accepted++;
                      } catch (Exception e) {
                        // Skip matches that can't be accepted
                      }
                    }

                    int blockedAfter =
                        VTMatchResolver.countMatchesWithStatus(
                            session, VTAssociationStatus.BLOCKED);
                    return new int[] {accepted, Math.max(0, blockedAfter - blockedBefore)};
                  });

          Map<String, Object> result = new HashMap<>();
          result.put("action", "accept_bulk");
          result.put("accepted_count", transactionResult[0]);
          result.put("blocked_count", transactionResult[1]);
          if (minSimilarity.isPresent()) {
            result.put("min_similarity", minSimilarity.get());
          }
          if (minConfidence.isPresent()) {
            result.put("min_confidence", minConfidence.get());
          }

          return result;
        });
  }

  private Object handleBulkReject(Map<String, Object> args) throws GhidraMcpException {
    String sessionName = getRequiredStringArgument(args, ARG_SESSION_NAME);
    return withSession(
        sessionName,
        session -> {
          Optional<Double> maxSimilarity =
              getOptionalBoundedDoubleArgument(args, ARG_MAX_SIMILARITY, 0.0, 1.0);
          Optional<Double> maxConfidence =
              getOptionalBoundedDoubleArgument(args, ARG_MAX_CONFIDENCE, 0.0, null);

          if (maxSimilarity.isEmpty() && maxConfidence.isEmpty()) {
            throw new GhidraMcpException(
                GhidraMcpError.validation()
                    .errorCode(GhidraMcpError.ErrorCode.MISSING_REQUIRED_ARGUMENT)
                    .message(
                        "At least one of max_similarity or max_confidence is required for"
                            + " bulk reject")
                    .build());
          }

          List<VTMatch> matchesToReject = new ArrayList<>();

          for (VTMatchSet matchSet : session.getMatchSets()) {
            for (VTMatch match : matchSet.getMatches()) {
              VTAssociationStatus status = match.getAssociation().getStatus();
              if (status != VTAssociationStatus.AVAILABLE) {
                continue;
              }

              double similarity = match.getSimilarityScore().getScore();
              double confidence = match.getConfidenceScore().getScore();

              boolean meetsCriteria = true;
              if (maxSimilarity.isPresent() && similarity > maxSimilarity.get()) {
                meetsCriteria = false;
              }
              if (maxConfidence.isPresent() && confidence > maxConfidence.get()) {
                meetsCriteria = false;
              }

              if (meetsCriteria) {
                matchesToReject.add(match);
              }
            }
          }

          int rejectedCount =
              inSessionTransaction(
                  session,
                  "Bulk Reject Matches",
                  "Bulk reject failed: ",
                  () -> {
                    int rejected = 0;
                    for (VTMatch match : matchesToReject) {
                      match.getAssociation().setRejected();
                      rejected++;
                    }
                    return rejected;
                  });

          Map<String, Object> result = new HashMap<>();
          result.put("action", "reject_bulk");
          result.put("rejected_count", rejectedCount);
          if (maxSimilarity.isPresent()) {
            result.put("max_similarity", maxSimilarity.get());
          }
          if (maxConfidence.isPresent()) {
            result.put("max_confidence", maxConfidence.get());
          }

          return result;
        });
  }

  // =================== Match Reading ===================

  private Object handleListMatches(Map<String, Object> args) throws GhidraMcpException {
    String sessionName = getRequiredStringArgument(args, ARG_SESSION_NAME);
    Optional<String> sourceAddr = getOptionalStringArgument(args, ARG_SOURCE_ADDRESS);
    Optional<String> destAddr = getOptionalStringArgument(args, ARG_DESTINATION_ADDRESS);
    validateSingleMatchAddressArguments(sourceAddr, destAddr);

    return withSession(
        sessionName,
        false,
        session -> {
          if (sourceAddr.isPresent() && destAddr.isPresent()) {
            return getSingleMatch(session, sourceAddr.get(), destAddr.get());
          }

          return listMatches(session, args);
        });
  }

  static void validateSingleMatchAddressArguments(
      Optional<String> sourceAddr, Optional<String> destAddr) throws GhidraMcpException {
    if (sourceAddr.isPresent() != destAddr.isPresent()) {
      throw new GhidraMcpException(
          GhidraMcpError.conflict(
              "source_address and destination_address must both be provided for single match"
                  + " lookup"));
    }
  }

  private VTMatchInfo getSingleMatch(VTSession session, String sourceAddrStr, String destAddrStr)
      throws GhidraMcpException {
    Program sourceProgram = session.getSourceProgram();
    Program destProgram = session.getDestinationProgram();
    VTMatchResolver.ResolvedMatch resolvedMatch =
        VTMatchResolver.findMatch(
            session, sourceAddrStr, destAddrStr, ARG_SOURCE_ADDRESS, ARG_DESTINATION_ADDRESS);

    return buildMatchInfo(
        resolvedMatch.match(), resolvedMatch.matchSet(), sourceProgram, destProgram);
  }

  private PaginatedResult<VTMatchInfo> listMatches(VTSession session, Map<String, Object> args)
      throws GhidraMcpException {
    // Get filter parameters
    Optional<String> statusFilter = getOptionalStringArgument(args, ARG_STATUS);
    Optional<String> typeFilter = getOptionalStringArgument(args, ARG_MATCH_TYPE);
    Optional<Double> minSimilarity =
        getOptionalBoundedDoubleArgument(args, ARG_MIN_SIMILARITY, 0.0, 1.0);
    Optional<Double> minConfidence =
        getOptionalBoundedDoubleArgument(args, ARG_MIN_CONFIDENCE, 0.0, null);
    Optional<String> correlatorFilter = getOptionalStringArgument(args, ARG_CORRELATOR);
    boolean excludeDefaultNames =
        getOptionalBooleanArgument(args, ARG_EXCLUDE_DEFAULT_NAMES).orElse(false);
    Optional<String> cursorOpt = getOptionalStringArgument(args, ARG_CURSOR);
    int pageSize = getPageSizeArgument(args, DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT);

    Program sourceProgram = session.getSourceProgram();
    Program destProgram = session.getDestinationProgram();

    // Parse cursor
    int startMatchSetIndex = 0;
    int startMatchIndex = 0;
    if (cursorOpt.isPresent()) {
      String cursorValue = cursorOpt.get();
      List<String> parts =
          decodeOpaqueCursorV1(
              cursorValue, 2, ARG_CURSOR, "v1:<base64url_match_set_index>:<base64url_match_index>");

      try {
        startMatchSetIndex = Integer.parseInt(parts.get(0));
        startMatchIndex = Integer.parseInt(parts.get(1));
      } catch (NumberFormatException e) {
        throw new GhidraMcpException(
            GhidraMcpError.invalid(
                ARG_CURSOR, cursorValue, "must contain numeric match set and match indexes"));
      }

      if (startMatchSetIndex < 0 || startMatchIndex < 0) {
        throw new GhidraMcpException(
            GhidraMcpError.invalid(ARG_CURSOR, cursorValue, "cursor indexes must be non-negative"));
      }
    }

    List<VTMatchInfo> results = new ArrayList<>();
    List<VTMatchSet> matchSets = session.getMatchSets();

    if (cursorOpt.isPresent()) {
      if (startMatchSetIndex >= matchSets.size()) {
        throw new GhidraMcpException(
            GhidraMcpError.invalid(
                ARG_CURSOR,
                cursorOpt.orElse(null),
                "cursor match set index is out of bounds for current result set"));
      }

      List<VTMatch> cursorMatchList =
          new ArrayList<>(matchSets.get(startMatchSetIndex).getMatches());
      if (startMatchIndex > cursorMatchList.size()) {
        throw new GhidraMcpException(
            GhidraMcpError.invalid(
                ARG_CURSOR,
                cursorOpt.orElse(null),
                "cursor match index is out of bounds for the selected match set"));
      }
    }

    int lastMatchSetIndex = startMatchSetIndex;
    int lastMatchIndex = startMatchIndex;
    boolean hasMore = false;

    outer:
    for (int msIdx = startMatchSetIndex; msIdx < matchSets.size(); msIdx++) {
      VTMatchSet matchSet = matchSets.get(msIdx);
      String correlatorName = matchSet.getProgramCorrelatorInfo().getName();

      // Apply correlator filter
      if (correlatorFilter.isPresent()
          && !correlatorName.toLowerCase().contains(correlatorFilter.get().toLowerCase())) {
        continue;
      }

      Collection<VTMatch> matches = matchSet.getMatches();
      List<VTMatch> matchList = new ArrayList<>(matches);
      matchList.sort(
          Comparator.comparing(
                  (VTMatch match) -> match.getAssociation().getSourceAddress().toString(),
                  String.CASE_INSENSITIVE_ORDER)
              .thenComparing(
                  match -> match.getAssociation().getDestinationAddress().toString(),
                  String.CASE_INSENSITIVE_ORDER));

      int startIdx = (msIdx == startMatchSetIndex) ? startMatchIndex : 0;
      for (int mIdx = startIdx; mIdx < matchList.size(); mIdx++) {
        VTMatch match = matchList.get(mIdx);

        // Apply filters
        if (!matchesFilters(match, statusFilter, typeFilter, minSimilarity, minConfidence)) {
          continue;
        }

        if (excludeDefaultNames) {
          String sourceName =
              getSymbolOrFunctionName(sourceProgram, match.getAssociation().getSourceAddress());
          if (sourceName != null && hasDefaultNamePrefix(sourceName)) {
            continue;
          }
        }

        if (results.size() >= pageSize) {
          hasMore = true;
          lastMatchSetIndex = msIdx;
          lastMatchIndex = mIdx;
          break outer;
        }

        results.add(buildMatchInfo(match, matchSet, sourceProgram, destProgram));
        lastMatchSetIndex = msIdx;
        lastMatchIndex = mIdx + 1;
      }
    }

    String nextCursor = null;
    if (hasMore) {
      nextCursor =
          OpaqueCursorCodec.encodeV1(
              String.valueOf(lastMatchSetIndex), String.valueOf(lastMatchIndex));
    }

    return new PaginatedResult<>(results, nextCursor);
  }

  private boolean matchesFilters(
      VTMatch match,
      Optional<String> statusFilter,
      Optional<String> typeFilter,
      Optional<Double> minSimilarity,
      Optional<Double> minConfidence) {

    if (statusFilter.isPresent()) {
      VTAssociationStatus status = match.getAssociation().getStatus();
      if (!status.name().equalsIgnoreCase(statusFilter.get())) {
        return false;
      }
    }

    if (typeFilter.isPresent()) {
      VTAssociationType type = match.getAssociation().getType();
      if (!type.name().equalsIgnoreCase(typeFilter.get())) {
        return false;
      }
    }

    if (minSimilarity.isPresent()) {
      double similarity = match.getSimilarityScore().getScore();
      if (similarity < minSimilarity.get()) {
        return false;
      }
    }

    if (minConfidence.isPresent()) {
      double confidence = match.getConfidenceScore().getScore();
      if (confidence < minConfidence.get()) {
        return false;
      }
    }

    return true;
  }

  private VTMatchInfo buildMatchInfo(
      VTMatch match, VTMatchSet matchSet, Program sourceProgram, Program destProgram) {

    Address sourceAddr = match.getAssociation().getSourceAddress();
    Address destAddr = match.getAssociation().getDestinationAddress();

    String sourceName = getSymbolOrFunctionName(sourceProgram, sourceAddr);
    String destName = getSymbolOrFunctionName(destProgram, destAddr);

    int markupCount = 0;

    return new VTMatchInfo(
        sourceAddr.toString(),
        destAddr.toString(),
        match.getAssociation().getType().name(),
        match.getSimilarityScore().getScore(),
        match.getConfidenceScore().getScore(),
        match.getAssociation().getStatus().name(),
        matchSet.getProgramCorrelatorInfo().getName(),
        sourceName,
        destName,
        markupCount);
  }

  private String getSymbolOrFunctionName(Program program, Address address) {
    Function func = program.getFunctionManager().getFunctionAt(address);
    if (func != null) {
      return func.getName();
    }

    Symbol symbol = program.getSymbolTable().getPrimarySymbol(address);
    if (symbol != null) {
      return symbol.getName();
    }

    return null;
  }

  private static boolean hasDefaultNamePrefix(String name) {
    for (String prefix : DEFAULT_NAME_PREFIXES) {
      if (name.startsWith(prefix)) {
        return true;
      }
    }
    return false;
  }

  // =================== Correlators ===================

  private List<VTCorrelatorInfo> handleListCorrelators() {
    List<VTCorrelatorInfo> correlators = new ArrayList<>();

    correlators.add(
        new VTCorrelatorInfo(
            "Exact Bytes Match", "exact_bytes", "Finds functions with identical byte sequences"));

    correlators.add(
        new VTCorrelatorInfo(
            "Exact Instructions Match",
            "exact_instructions",
            "Finds functions with identical instruction sequences (ignoring operand" + " values)"));

    correlators.add(
        new VTCorrelatorInfo(
            "Exact Data Match", "exact_data", "Finds data items with identical byte values"));

    correlators.add(
        new VTCorrelatorInfo(
            "Symbol Name Match", "symbol_name", "Finds symbols with matching names"));

    return correlators;
  }

  private Object handleRunCorrelator(Map<String, Object> args) throws GhidraMcpException {
    String sessionName = getRequiredStringArgument(args, ARG_SESSION_NAME);
    String correlatorType = getRequiredStringArgument(args, ARG_CORRELATOR_TYPE);
    Optional<String> sourceMinAddr = getOptionalStringArgument(args, ARG_SOURCE_MIN_ADDRESS);
    Optional<String> sourceMaxAddr = getOptionalStringArgument(args, ARG_SOURCE_MAX_ADDRESS);
    Optional<String> destMinAddr = getOptionalStringArgument(args, ARG_DEST_MIN_ADDRESS);
    Optional<String> destMaxAddr = getOptionalStringArgument(args, ARG_DEST_MAX_ADDRESS);
    boolean excludeAccepted = getOptionalBooleanArgument(args, ARG_EXCLUDE_ACCEPTED).orElse(true);

    String factoryClassName = CORRELATOR_CLASS_MAP.get(correlatorType.toLowerCase());
    if (factoryClassName == null) {
      throw new GhidraMcpException(
          GhidraMcpError.invalid(
              ARG_CORRELATOR_TYPE,
              correlatorType,
              "must be one of: exact_bytes, exact_instructions, exact_data, symbol_name"));
    }

    return withSession(
        sessionName,
        session -> {
          ghidra.util.Msg.info(
              this,
              "[run_correlator] Starting "
                  + correlatorType
                  + " (large binaries may take minutes — check vt_sessions info if client times"
                  + " out)");
          Program sourceProgram = session.getSourceProgram();
          Program destProgram = session.getDestinationProgram();

          AddressSetView sourceSet =
              buildAddressSet(
                  sourceProgram, sourceMinAddr, sourceMaxAddr, session, excludeAccepted, true);
          AddressSetView destSet =
              buildAddressSet(
                  destProgram, destMinAddr, destMaxAddr, session, excludeAccepted, false);

          VTMatchSet matchSet =
              runCorrelatorReflective(
                  session, factoryClassName, sourceProgram, sourceSet, destProgram, destSet);

          ghidra.util.Msg.info(this, "[run_correlator] Correlator finished, building result");
          Map<String, Object> result = new HashMap<>();
          result.put("correlator", correlatorType);
          result.put("session_name", sessionName);
          try {
            result.put("match_count", matchSet.getMatchCount());
            result.put("correlator_name", matchSet.getProgramCorrelatorInfo().getName());
          } catch (Exception e) {
            // Fallback: count from session if matchSet methods fail
            int totalMatches = 0;
            for (VTMatchSet ms : session.getMatchSets()) {
              totalMatches += ms.getMatchCount();
            }
            result.put("match_count", totalMatches);
            result.put("correlator_name", correlatorType);
            result.put("warning", "match_count is session total: " + e.getMessage());
          }

          ghidra.util.Msg.info(this, "[run_correlator] Returning result: " + result);
          return result;
        });
  }

  private VTMatchSet runCorrelatorReflective(
      VTSession session,
      String factoryClassName,
      Program sourceProgram,
      AddressSetView sourceSet,
      Program destProgram,
      AddressSetView destSet)
      throws GhidraMcpException {
    try {
      Class<?> factoryClass = Class.forName(factoryClassName);
      Constructor<?> constructor = factoryClass.getDeclaredConstructor();
      Object factory = constructor.newInstance();

      Class<?> vtOptionsClass = Class.forName("ghidra.feature.vt.api.util.VTOptions");
      Method createDefaultOptionsMethod = factoryClass.getMethod("createDefaultOptions");
      Object options = createDefaultOptionsMethod.invoke(factory);
      if (!vtOptionsClass.isInstance(options)) {
        throw new GhidraMcpException(
            GhidraMcpError.execution()
                .errorCode(GhidraMcpError.ErrorCode.UNEXPECTED_ERROR)
                .message("Correlator factory returned invalid options type")
                .build());
      }

      Class<?> addressSetViewClass = AddressSetView.class;
      Method createCorrelatorMethod =
          factoryClass.getMethod(
              "createCorrelator",
              Class.forName("ghidra.framework.plugintool.ServiceProvider"),
              Program.class,
              addressSetViewClass,
              Program.class,
              addressSetViewClass,
              vtOptionsClass);

      Object correlator =
          createCorrelatorMethod.invoke(
              factory, null, sourceProgram, sourceSet, destProgram, destSet, options);

      return inSessionTransaction(
          session,
          "Run Correlator",
          "Correlation failed: ",
          () -> {
            Class<?> vtSessionClass = VTSession.class;
            Method correlateMethod =
                correlator.getClass().getMethod("correlate", vtSessionClass, TaskMonitor.class);
            return (VTMatchSet) correlateMethod.invoke(correlator, session, TaskMonitor.DUMMY);
          });
    } catch (ClassNotFoundException e) {
      throw new GhidraMcpException(
          GhidraMcpError.execution()
              .message(
                  "Correlator not available. Ensure all required Ghidra libraries are in" + " lib/")
              .build());
    } catch (GhidraMcpException e) {
      throw e;
    } catch (Exception e) {
      Throwable cause = e.getCause() != null ? e.getCause() : e;
      throw new GhidraMcpException(
          GhidraMcpError.execution()
              .errorCode(GhidraMcpError.ErrorCode.UNEXPECTED_ERROR)
              .message("Failed to run correlator: " + cause.getMessage())
              .build());
    }
  }

  private AddressSetView buildAddressSet(
      Program program,
      Optional<String> minAddr,
      Optional<String> maxAddr,
      VTSession session,
      boolean excludeAccepted,
      boolean isSource)
      throws GhidraMcpException {

    AddressSet set;

    if (minAddr.isPresent() && maxAddr.isPresent()) {
      Address min =
          VTMatchResolver.parseAddress(
              program, minAddr.get(), isSource ? ARG_SOURCE_MIN_ADDRESS : ARG_DEST_MIN_ADDRESS);
      Address max =
          VTMatchResolver.parseAddress(
              program, maxAddr.get(), isSource ? ARG_SOURCE_MAX_ADDRESS : ARG_DEST_MAX_ADDRESS);
      if (min.compareTo(max) > 0) {
        throw new GhidraMcpException(
            GhidraMcpError.invalid(
                isSource
                    ? ARG_SOURCE_MIN_ADDRESS + "/" + ARG_SOURCE_MAX_ADDRESS
                    : ARG_DEST_MIN_ADDRESS + "/" + ARG_DEST_MAX_ADDRESS,
                minAddr.get() + ".." + maxAddr.get(),
                "minimum address must be less than or equal to maximum address"));
      }
      set = new AddressSet(min, max);
    } else if (minAddr.isPresent() || maxAddr.isPresent()) {
      throw new GhidraMcpException(
          GhidraMcpError.validation()
              .errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
              .message("Both min and max addresses must be provided together, or neither")
              .build());
    } else {
      set = new AddressSet(program.getMemory());
    }

    if (excludeAccepted) {
      for (VTMatchSet matchSet : session.getMatchSets()) {
        for (VTMatch match : matchSet.getMatches()) {
          if (match.getAssociation().getStatus() == VTAssociationStatus.ACCEPTED) {
            Address addr =
                isSource
                    ? match.getAssociation().getSourceAddress()
                    : match.getAssociation().getDestinationAddress();
            int matchLength = isSource ? match.getSourceLength() : match.getDestinationLength();
            deleteAddressRange(set, addr, matchLength);
          }
        }
      }
    }

    return set;
  }

  private void deleteAddressRange(AddressSet set, Address start, int length) {
    if (start == null) {
      return;
    }

    Address end = start;
    if (length > 1) {
      try {
        end = start.addNoWrap(length - 1L);
      } catch (Exception e) {
        try {
          end = start.add(length - 1L);
        } catch (Exception ignored) {
          end = start;
        }
      }
    }

    set.delete(start, end);
  }

  // =================== Markup Operations ===================

  private Object handleListMarkup(Map<String, Object> args) throws GhidraMcpException {
    String sessionName = getRequiredStringArgument(args, ARG_SESSION_NAME);
    return withSession(
        sessionName,
        false,
        session -> {
          VTMatch match = findMatchForMarkup(session, args);
          Collection<VTMarkupItem> markupItems = getMarkupItems(match);

          List<VTMarkupItemInfo> results = new ArrayList<>();
          for (VTMarkupItem item : markupItems) {
            results.add(buildMarkupItemInfo(item));
          }

          return results;
        });
  }

  private Object handleApplyMarkup(Map<String, Object> args) throws GhidraMcpException {
    String sessionName = getRequiredStringArgument(args, ARG_SESSION_NAME);
    return withSession(
        sessionName,
        true,
        session -> {
          VTMatch match = findMatchForMarkup(session, args);

          if (match.getAssociation().getStatus() != VTAssociationStatus.ACCEPTED) {
            throw new GhidraMcpException(
                GhidraMcpError.validation()
                    .errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
                    .message(
                        "Markup can only be applied to ACCEPTED matches. Current status: "
                            + match.getAssociation().getStatus())
                    .build());
          }

          Set<String> requestedTypes = getMarkupTypesFilter(args);
          String applyActionStr = resolveApplyAction(args);

          List<String> failures = new ArrayList<>();

          int appliedCount =
              inSessionTransaction(
                  session,
                  "Apply Markup",
                  "Failed to apply markup: ",
                  () -> {
                    int applied = 0;
                    Collection<VTMarkupItem> markupItems = getMarkupItems(match);

                    for (VTMarkupItem item : markupItems) {
                      if (!shouldApplyMarkupItem(item, requestedTypes)) {
                        continue;
                      }

                      try {
                        applyMarkupItem(item, applyActionStr);
                        applied++;
                      } catch (Exception e) {
                        failures.add(getMarkupTypeName(item) + ": " + e.getMessage());
                      }
                    }
                    return applied;
                  });

          Map<String, Object> result = new HashMap<>();
          result.put("action", "apply");
          result.put("applied_count", appliedCount);
          if (!failures.isEmpty()) {
            result.put("failures", failures);
          }

          return result;
        });
  }

  private Object handleApplyAllMarkup(Map<String, Object> args) throws GhidraMcpException {
    String sessionName = getRequiredStringArgument(args, ARG_SESSION_NAME);
    return withSession(
        sessionName,
        true,
        session -> {
          Optional<Double> minSimilarity =
              getOptionalBoundedDoubleArgument(args, ARG_MIN_SIMILARITY, 0.0, 1.0);
          Optional<Double> minConfidence =
              getOptionalBoundedDoubleArgument(args, ARG_MIN_CONFIDENCE, 0.0, null);
          Set<String> requestedTypes = getMarkupTypesFilter(args);
          String applyActionStr = resolveApplyAction(args);

          List<String> failures = new ArrayList<>();

          int[] applyAllResult =
              inSessionTransaction(
                  session,
                  "Apply All Markup",
                  "Failed to apply all markup: ",
                  () -> {
                    int applied = 0;
                    int processed = 0;

                    for (VTMatchSet matchSet : session.getMatchSets()) {
                      for (VTMatch match : matchSet.getMatches()) {
                        if (match.getAssociation().getStatus() != VTAssociationStatus.ACCEPTED) {
                          continue;
                        }

                        double similarity = match.getSimilarityScore().getScore();
                        double confidence = match.getConfidenceScore().getScore();

                        if (minSimilarity.isPresent() && similarity < minSimilarity.get()) {
                          continue;
                        }
                        if (minConfidence.isPresent() && confidence < minConfidence.get()) {
                          continue;
                        }

                        processed++;

                        try {
                          Collection<VTMarkupItem> markupItems = getMarkupItems(match);
                          for (VTMarkupItem item : markupItems) {
                            if (!shouldApplyMarkupItem(item, requestedTypes)) {
                              continue;
                            }

                            try {
                              applyMarkupItem(item, applyActionStr);
                              applied++;
                            } catch (Exception e) {
                              if (failures.size() < 10) {
                                failures.add(
                                    match.getAssociation().getSourceAddress()
                                        + " - "
                                        + getMarkupTypeName(item)
                                        + ": "
                                        + e.getMessage());
                              }
                            }
                          }
                        } catch (GhidraMcpException e) {
                          if (failures.size() < 10) {
                            failures.add(
                                match.getAssociation().getSourceAddress() + ": " + e.getMessage());
                          }
                        }
                      }
                    }

                    return new int[] {processed, applied};
                  });

          Map<String, Object> result = new HashMap<>();
          result.put("action", "apply_all");
          result.put("matches_processed", applyAllResult[0]);
          result.put("applied_count", applyAllResult[1]);
          if (!failures.isEmpty()) {
            result.put("failures", failures);
            if (failures.size() >= 10) {
              result.put("failures_truncated", true);
            }
          }

          return result;
        });
  }

  private Object handleUnapplyMarkup(Map<String, Object> args) throws GhidraMcpException {
    String sessionName = getRequiredStringArgument(args, ARG_SESSION_NAME);
    return withSession(
        sessionName,
        true,
        session -> {
          VTMatch match = findMatchForMarkup(session, args);
          Set<String> requestedTypes = getMarkupTypesFilter(args);

          int unappliedCount =
              inSessionTransaction(
                  session,
                  "Unapply Markup",
                  "Failed to unapply markup: ",
                  () -> {
                    int unapplied = 0;
                    Collection<VTMarkupItem> markupItems = getMarkupItems(match);

                    for (VTMarkupItem item : markupItems) {
                      if (!shouldApplyMarkupItem(item, requestedTypes)) {
                        continue;
                      }

                      if (isMarkupApplied(item)) {
                        try {
                          unapplyMarkupItem(item);
                          unapplied++;
                        } catch (Exception e) {
                          // Skip items that can't be unapplied
                        }
                      }
                    }

                    return unapplied;
                  });

          Map<String, Object> result = new HashMap<>();
          result.put("action", "unapply");
          result.put("unapplied_count", unappliedCount);

          return result;
        });
  }

  private VTMatch findMatchForMarkup(VTSession session, Map<String, Object> args)
      throws GhidraMcpException {
    String sourceAddrStr = getRequiredStringArgument(args, ARG_SOURCE_ADDRESS);
    String destAddrStr = getRequiredStringArgument(args, ARG_DESTINATION_ADDRESS);
    return VTMatchResolver.findMatch(
            session, sourceAddrStr, destAddrStr, ARG_SOURCE_ADDRESS, ARG_DESTINATION_ADDRESS)
        .match();
  }

  private Collection<VTMarkupItem> getMarkupItems(VTMatch match) throws GhidraMcpException {
    try {
      return match.getAssociation().getMarkupItems(TaskMonitor.DUMMY);
    } catch (CancelledException e) {
      throw new GhidraMcpException(
          GhidraMcpError.execution().message("Markup item retrieval was cancelled").build());
    } catch (Exception e) {
      throw new GhidraMcpException(
          GhidraMcpError.execution()
              .message("Failed to get markup items: " + e.getMessage())
              .build());
    }
  }

  private Set<String> getMarkupTypesFilter(Map<String, Object> args) throws GhidraMcpException {
    Object typesObj = args.get(ARG_MARKUP_TYPES);
    if (typesObj == null) {
      return null; // null means apply all types
    }

    if (!(typesObj instanceof List<?> typesList)) {
      throw new GhidraMcpException(
          GhidraMcpError.invalid(ARG_MARKUP_TYPES, typesObj, "must be an array of strings"));
    }

    if (typesList.isEmpty()) {
      throw new GhidraMcpException(
          GhidraMcpError.invalid(
              ARG_MARKUP_TYPES, typesObj, "must include at least one supported markup type"));
    }

    Set<String> types = new HashSet<>();
    List<String> unsupportedTypes = new ArrayList<>();

    for (Object typeObj : typesList) {
      if (!(typeObj instanceof String type)) {
        throw new GhidraMcpException(
            GhidraMcpError.invalid(
                ARG_MARKUP_TYPES, typeObj, "all markup_types entries must be strings"));
      }

      String mappedType = MARKUP_TYPE_MAP.get(type.trim().toLowerCase(Locale.ROOT));
      if (mappedType == null) {
        unsupportedTypes.add(type);
      } else {
        types.add(mappedType);
      }
    }

    if (!unsupportedTypes.isEmpty()) {
      List<String> supportedTypes = new ArrayList<>(MARKUP_TYPE_MAP.keySet());
      Collections.sort(supportedTypes);
      throw new GhidraMcpException(
          GhidraMcpError.invalid(
              ARG_MARKUP_TYPES,
              unsupportedTypes,
              "unsupported markup type(s): "
                  + String.join(", ", unsupportedTypes)
                  + ". Supported values: "
                  + String.join(", ", supportedTypes)));
    }

    if (types.isEmpty()) {
      throw new GhidraMcpException(
          GhidraMcpError.invalid(
              ARG_MARKUP_TYPES, typesObj, "must include at least one supported markup type"));
    }

    return types;
  }

  private String resolveApplyAction(Map<String, Object> args) throws GhidraMcpException {
    String applyAction = getOptionalStringArgument(args, ARG_APPLY_ACTION).orElse("REPLACE");
    if ("REPLACE".equalsIgnoreCase(applyAction)) {
      return "REPLACE";
    }
    if ("ADD".equalsIgnoreCase(applyAction)) {
      return "ADD";
    }

    throw new GhidraMcpException(
        GhidraMcpError.invalid(ARG_APPLY_ACTION, applyAction, "must be one of: REPLACE, ADD"));
  }

  private boolean shouldApplyMarkupItem(VTMarkupItem item, Set<String> requestedTypes) {
    if (requestedTypes == null) {
      return true;
    }

    // Check both the display name and the class simple name for matching,
    // since MARKUP_TYPE_MAP values (e.g. "FunctionName") match class names
    // while display names may contain spaces (e.g. "Function Name").
    String displayName = item.getMarkupType().getDisplayName();
    String className = item.getMarkupType().getClass().getSimpleName();

    for (String requested : requestedTypes) {
      if ((displayName != null && displayName.contains(requested))
          || (className != null && className.contains(requested))) {
        return true;
      }
    }

    return false;
  }

  private String getMarkupTypeName(VTMarkupItem item) {
    return item.getMarkupType().getDisplayName();
  }

  private void applyMarkupItem(VTMarkupItem item, String applyActionStr)
      throws VersionTrackingApplyException {
    VTMarkupItemApplyActionType applyAction =
        "ADD".equalsIgnoreCase(applyActionStr)
            ? VTMarkupItemApplyActionType.ADD
            : VTMarkupItemApplyActionType.REPLACE;

    item.apply(applyAction, new ToolOptions("VTMarkup"));
  }

  private boolean isMarkupApplied(VTMarkupItem item) {
    return item.getStatus().isUnappliable();
  }

  private void unapplyMarkupItem(VTMarkupItem item) throws VersionTrackingApplyException {
    item.unapply();
  }

  private VTMarkupItemInfo buildMarkupItemInfo(VTMarkupItem item) {
    String typeName = item.getMarkupType().getDisplayName();
    Address srcAddr = item.getSourceAddress();
    Address dstAddr = item.getDestinationAddress();
    Object srcVal = item.getSourceValue();
    Object dstVal = item.getCurrentDestinationValue();

    return new VTMarkupItemInfo(
        typeName,
        srcAddr != null ? srcAddr.toString() : null,
        dstAddr != null ? dstAddr.toString() : null,
        srcVal != null ? srcVal.toString() : null,
        dstVal != null ? dstVal.toString() : null,
        item.getStatus().toString());
  }
}
