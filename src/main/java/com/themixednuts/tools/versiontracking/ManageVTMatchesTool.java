package com.themixednuts.tools.versiontracking;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.draft7.SchemaBuilder;
import ghidra.feature.vt.api.main.VTAssociation;
import ghidra.feature.vt.api.main.VTAssociationStatus;
import ghidra.feature.vt.api.main.VTMatch;
import ghidra.feature.vt.api.main.VTMatchSet;
import ghidra.feature.vt.api.main.VTSession;
import ghidra.framework.plugintool.PluginTool;
import io.modelcontextprotocol.common.McpTransportContext;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import reactor.core.publisher.Mono;

@GhidraMcpTool(
    name = "Manage VT Matches",
    description = "Accept, reject, or clear Version Tracking matches.",
    mcpName = "manage_vt_matches",
    mcpDescription =
        """
        <use_case>
        Manage the status of Version Tracking matches. Accepting a match indicates that the
        source and destination addresses correspond to the same entity. Rejected matches are
        excluded from future consideration. Matches can also be bulk-accepted or bulk-rejected
        based on similarity and confidence thresholds.
        </use_case>

        <important_notes>
        - Accepting a match may block other matches that conflict with it
        - Bulk operations can process many matches at once based on score thresholds
        - Clear operation resets a match status back to AVAILABLE
        - Changes are persisted to the VT session file
        </important_notes>

        <return_value_summary>
        Returns a count of matches affected by the operation, along with any blocked matches
        for single-match operations.
        </return_value_summary>
        """)
public class ManageVTMatchesTool extends BaseVTTool {

  public static final String ARG_SOURCE_ADDRESS = "source_address";
  public static final String ARG_DESTINATION_ADDRESS = "destination_address";
  public static final String ARG_MIN_SIMILARITY = "min_similarity";
  public static final String ARG_MIN_CONFIDENCE = "min_confidence";
  public static final String ARG_MAX_SIMILARITY = "max_similarity";
  public static final String ARG_MAX_CONFIDENCE = "max_confidence";

  private static final String ACTION_ACCEPT = "accept";
  private static final String ACTION_REJECT = "reject";
  private static final String ACTION_CLEAR = "clear";
  private static final String ACTION_ACCEPT_BULK = "accept_bulk";
  private static final String ACTION_REJECT_BULK = "reject_bulk";

  @Override
  public JsonSchema schema() {
    var schemaRoot = createDraft7SchemaNode();

    schemaRoot.property(
        ARG_ACTION,
        SchemaBuilder.string(mapper)
            .enumValues(
                ACTION_ACCEPT, ACTION_REJECT, ACTION_CLEAR, ACTION_ACCEPT_BULK, ACTION_REJECT_BULK)
            .description("The match management operation to perform"));

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
            .description("Minimum similarity score for bulk operations (0.0 to 1.0)")
            .minimum(0.0)
            .maximum(1.0));

    schemaRoot.property(
        ARG_MIN_CONFIDENCE,
        SchemaBuilder.number(mapper)
            .description("Minimum confidence score for bulk operations (>= 0.0)")
            .minimum(0.0));

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

    schemaRoot.requiredProperty(ARG_ACTION);
    schemaRoot.requiredProperty(ARG_SESSION_NAME);

    // Conditional requirements
    schemaRoot.allOf(
        // accept/reject/clear require source_address and destination_address
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(ARG_ACTION, SchemaBuilder.string(mapper).constValue(ACTION_ACCEPT)),
                SchemaBuilder.objectDraft7(mapper)
                    .requiredProperty(ARG_SOURCE_ADDRESS)
                    .requiredProperty(ARG_DESTINATION_ADDRESS)),
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(ARG_ACTION, SchemaBuilder.string(mapper).constValue(ACTION_REJECT)),
                SchemaBuilder.objectDraft7(mapper)
                    .requiredProperty(ARG_SOURCE_ADDRESS)
                    .requiredProperty(ARG_DESTINATION_ADDRESS)),
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(ARG_ACTION, SchemaBuilder.string(mapper).constValue(ACTION_CLEAR)),
                SchemaBuilder.objectDraft7(mapper)
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
          String sessionName = getRequiredStringArgument(args, ARG_SESSION_NAME);
          String normalizedAction = action.toLowerCase();

          return withSession(
              sessionName,
              session ->
                  switch (normalizedAction) {
                    case ACTION_ACCEPT ->
                        handleSingleMatch(session, args, VTAssociationStatus.ACCEPTED);
                    case ACTION_REJECT ->
                        handleSingleMatch(session, args, VTAssociationStatus.REJECTED);
                    case ACTION_CLEAR ->
                        handleSingleMatch(session, args, VTAssociationStatus.AVAILABLE);
                    case ACTION_ACCEPT_BULK -> handleBulkAccept(session, args);
                    case ACTION_REJECT_BULK -> handleBulkReject(session, args);
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
                                    + ACTION_REJECT_BULK));
                  });
        });
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

  private Map<String, Object> handleBulkAccept(VTSession session, Map<String, Object> args)
      throws GhidraMcpException {
    Optional<Double> minSimilarity =
        getOptionalBoundedDoubleArgument(args, ARG_MIN_SIMILARITY, 0.0, 1.0);
    Optional<Double> minConfidence =
        getOptionalBoundedDoubleArgument(args, ARG_MIN_CONFIDENCE, 0.0, null);

    if (minSimilarity.isEmpty() && minConfidence.isEmpty()) {
      throw new GhidraMcpException(
          GhidraMcpError.validation()
              .errorCode(GhidraMcpError.ErrorCode.MISSING_REQUIRED_ARGUMENT)
              .message(
                  "At least one of min_similarity or min_confidence is required for bulk accept")
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

    int acceptedCount;
    int blockedBefore =
        VTMatchResolver.countMatchesWithStatus(session, VTAssociationStatus.BLOCKED);
    int blockedCount;

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
                  // Skip matches that can't be accepted (might be blocked by earlier accepts)
                }
              }

              int blockedAfter =
                  VTMatchResolver.countMatchesWithStatus(session, VTAssociationStatus.BLOCKED);
              return new int[] {accepted, Math.max(0, blockedAfter - blockedBefore)};
            });
    acceptedCount = transactionResult[0];
    blockedCount = transactionResult[1];

    Map<String, Object> result = new HashMap<>();
    result.put("action", "accept_bulk");
    result.put("accepted_count", acceptedCount);
    result.put("blocked_count", blockedCount);
    if (minSimilarity.isPresent()) {
      result.put("min_similarity", minSimilarity.get());
    }
    if (minConfidence.isPresent()) {
      result.put("min_confidence", minConfidence.get());
    }

    return result;
  }

  private Map<String, Object> handleBulkReject(VTSession session, Map<String, Object> args)
      throws GhidraMcpException {
    Optional<Double> maxSimilarity =
        getOptionalBoundedDoubleArgument(args, ARG_MAX_SIMILARITY, 0.0, 1.0);
    Optional<Double> maxConfidence =
        getOptionalBoundedDoubleArgument(args, ARG_MAX_CONFIDENCE, 0.0, null);

    if (maxSimilarity.isEmpty() && maxConfidence.isEmpty()) {
      throw new GhidraMcpException(
          GhidraMcpError.validation()
              .errorCode(GhidraMcpError.ErrorCode.MISSING_REQUIRED_ARGUMENT)
              .message(
                  "At least one of max_similarity or max_confidence is required for bulk reject")
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
  }
}
