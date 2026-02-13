package com.themixednuts.tools.versiontracking;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.tools.BaseMcpTool;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.draft7.SchemaBuilder;
import ghidra.feature.vt.api.db.VTSessionDB;
import ghidra.feature.vt.api.main.VTAssociation;
import ghidra.feature.vt.api.main.VTAssociationStatus;
import ghidra.feature.vt.api.main.VTMatch;
import ghidra.feature.vt.api.main.VTMatchSet;
import ghidra.feature.vt.api.main.VTSession;
import ghidra.framework.main.AppInfo;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainObject;
import ghidra.framework.model.Project;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
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
public class ManageVTMatchesTool extends BaseMcpTool {

  public static final String ARG_SESSION_NAME = "session_name";
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
        SchemaBuilder.string(mapper)
            .description("Source address of the match")
            .pattern("^(0x)?[0-9a-fA-F]+$"));

    schemaRoot.property(
        ARG_DESTINATION_ADDRESS,
        SchemaBuilder.string(mapper)
            .description("Destination address of the match")
            .pattern("^(0x)?[0-9a-fA-F]+$"));

    schemaRoot.property(
        ARG_MIN_SIMILARITY,
        SchemaBuilder.number(mapper)
            .description("Minimum similarity score for bulk operations (0.0 to 1.0)")
            .minimum(0.0)
            .maximum(1.0));

    schemaRoot.property(
        ARG_MIN_CONFIDENCE,
        SchemaBuilder.number(mapper)
            .description("Minimum confidence score for bulk operations (0.0 to 1.0)")
            .minimum(0.0)
            .maximum(1.0));

    schemaRoot.property(
        ARG_MAX_SIMILARITY,
        SchemaBuilder.number(mapper)
            .description("Maximum similarity score for bulk reject (0.0 to 1.0)")
            .minimum(0.0)
            .maximum(1.0));

    schemaRoot.property(
        ARG_MAX_CONFIDENCE,
        SchemaBuilder.number(mapper)
            .description("Maximum confidence score for bulk reject (0.0 to 1.0)")
            .minimum(0.0)
            .maximum(1.0));

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

          VTSession session = openVTSession(sessionName);
          try {
            return switch (normalizedAction) {
              case ACTION_ACCEPT -> handleSingleMatch(session, args, VTAssociationStatus.ACCEPTED);
              case ACTION_REJECT -> handleSingleMatch(session, args, VTAssociationStatus.REJECTED);
              case ACTION_CLEAR -> handleSingleMatch(session, args, VTAssociationStatus.AVAILABLE);
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
            };
          } finally {
            session.release(this);
          }
        });
  }

  private Map<String, Object> handleSingleMatch(
      VTSession session, Map<String, Object> args, VTAssociationStatus newStatus)
      throws GhidraMcpException {
    String sourceAddrStr = getRequiredStringArgument(args, ARG_SOURCE_ADDRESS);
    String destAddrStr = getRequiredStringArgument(args, ARG_DESTINATION_ADDRESS);

    Program sourceProgram = session.getSourceProgram();
    Program destProgram = session.getDestinationProgram();

    Address sourceAddr = sourceProgram.getAddressFactory().getAddress(sourceAddrStr);
    Address destAddr = destProgram.getAddressFactory().getAddress(destAddrStr);

    if (sourceAddr == null || destAddr == null) {
      throw new GhidraMcpException(
          GhidraMcpError.validation()
              .errorCode(GhidraMcpError.ErrorCode.ADDRESS_PARSE_FAILED)
              .message("Invalid address")
              .build());
    }

    // Find the match
    VTMatch targetMatch = null;
    for (VTMatchSet matchSet : session.getMatchSets()) {
      for (VTMatch match : matchSet.getMatches()) {
        if (match.getAssociation().getSourceAddress().equals(sourceAddr)
            && match.getAssociation().getDestinationAddress().equals(destAddr)) {
          targetMatch = match;
          break;
        }
      }
      if (targetMatch != null) break;
    }

    if (targetMatch == null) {
      throw new GhidraMcpException(
          GhidraMcpError.notFound("match", sourceAddrStr + " -> " + destAddrStr));
    }

    VTSessionDB sessionDB = (VTSessionDB) session;
    int txId = sessionDB.startTransaction("Set Match Status");
    int blockedCount = 0;

    try {
      VTAssociation association = targetMatch.getAssociation();

      if (newStatus == VTAssociationStatus.ACCEPTED) {
        association.setAccepted();
        // Count newly blocked matches
        for (VTMatchSet ms : session.getMatchSets()) {
          for (VTMatch m : ms.getMatches()) {
            if (m.getAssociation().getStatus() == VTAssociationStatus.BLOCKED) {
              blockedCount++;
            }
          }
        }
      } else if (newStatus == VTAssociationStatus.REJECTED) {
        association.setRejected();
      } else {
        association.clearStatus();
      }

      sessionDB.endTransaction(txId, true);
    } catch (Exception e) {
      sessionDB.endTransaction(txId, false);
      throw new GhidraMcpException(
          GhidraMcpError.execution()
              .errorCode(GhidraMcpError.ErrorCode.UNEXPECTED_ERROR)
              .message("Failed to update match status: " + e.getMessage())
              .build());
    }

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
    Optional<Double> minSimilarity = getOptionalDoubleArgument(args, ARG_MIN_SIMILARITY);
    Optional<Double> minConfidence = getOptionalDoubleArgument(args, ARG_MIN_CONFIDENCE);

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

    VTSessionDB sessionDB = (VTSessionDB) session;
    int txId = sessionDB.startTransaction("Bulk Accept Matches");
    int acceptedCount = 0;
    int blockedCount = 0;

    try {
      for (VTMatch match : matchesToAccept) {
        try {
          match.getAssociation().setAccepted();
          acceptedCount++;
        } catch (Exception e) {
          // Skip matches that can't be accepted (might be blocked by earlier accepts)
        }
      }

      // Count blocked matches
      for (VTMatchSet ms : session.getMatchSets()) {
        for (VTMatch m : ms.getMatches()) {
          if (m.getAssociation().getStatus() == VTAssociationStatus.BLOCKED) {
            blockedCount++;
          }
        }
      }

      sessionDB.endTransaction(txId, true);
    } catch (Exception e) {
      sessionDB.endTransaction(txId, false);
      throw new GhidraMcpException(
          GhidraMcpError.execution()
              .errorCode(GhidraMcpError.ErrorCode.UNEXPECTED_ERROR)
              .message("Bulk accept failed: " + e.getMessage())
              .build());
    }

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
    Optional<Double> maxSimilarity = getOptionalDoubleArgument(args, ARG_MAX_SIMILARITY);
    Optional<Double> maxConfidence = getOptionalDoubleArgument(args, ARG_MAX_CONFIDENCE);

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

    VTSessionDB sessionDB = (VTSessionDB) session;
    int txId = sessionDB.startTransaction("Bulk Reject Matches");
    int rejectedCount = 0;

    try {
      for (VTMatch match : matchesToReject) {
        match.getAssociation().setRejected();
        rejectedCount++;
      }

      sessionDB.endTransaction(txId, true);
    } catch (Exception e) {
      sessionDB.endTransaction(txId, false);
      throw new GhidraMcpException(
          GhidraMcpError.execution()
              .errorCode(GhidraMcpError.ErrorCode.UNEXPECTED_ERROR)
              .message("Bulk reject failed: " + e.getMessage())
              .build());
    }

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

  private Optional<Double> getOptionalDoubleArgument(
      Map<String, Object> args, String argumentName) {
    return Optional.ofNullable(args.get(argumentName))
        .flatMap(
            value -> {
              if (value instanceof Number) {
                return Optional.of(((Number) value).doubleValue());
              } else if (value instanceof String) {
                try {
                  return Optional.of(Double.parseDouble((String) value));
                } catch (NumberFormatException e) {
                  return Optional.empty();
                }
              }
              return Optional.empty();
            });
  }

  private VTSession openVTSession(String sessionName) throws GhidraMcpException {
    Project project = AppInfo.getActiveProject();
    if (project == null) {
      throw new GhidraMcpException(
          GhidraMcpError.permissionState()
              .errorCode(GhidraMcpError.ErrorCode.PROGRAM_NOT_OPEN)
              .message("No active project found")
              .build());
    }

    DomainFile sessionFile =
        VTDomainFileResolver.resolveSessionFile(project, sessionName, ARG_SESSION_NAME);

    try {
      DomainObject obj = sessionFile.getDomainObject(this, true, false, TaskMonitor.DUMMY);
      if (obj instanceof VTSession) {
        return (VTSession) obj;
      }
      if (obj != null) {
        obj.release(this);
      }
      throw new GhidraMcpException(
          GhidraMcpError.validation()
              .errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
              .message("File '" + sessionName + "' is not a VT session")
              .build());
    } catch (GhidraMcpException e) {
      throw e;
    } catch (Exception e) {
      throw new GhidraMcpException(
          GhidraMcpError.execution()
              .errorCode(GhidraMcpError.ErrorCode.UNEXPECTED_ERROR)
              .message("Failed to open VT session: " + e.getMessage())
              .build());
    }
  }
}
