package com.themixednuts.tools.versiontracking;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.models.versiontracking.VTMatchInfo;
import com.themixednuts.tools.BaseMcpTool;
import com.themixednuts.utils.OpaqueCursorCodec;
import com.themixednuts.utils.PaginatedResult;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.google.SchemaBuilder;
import com.themixednuts.utils.jsonschema.google.SchemaBuilder.IObjectSchemaBuilder;
import ghidra.feature.vt.api.main.VTAssociationStatus;
import ghidra.feature.vt.api.main.VTAssociationType;
import ghidra.feature.vt.api.main.VTMatch;
import ghidra.feature.vt.api.main.VTMatchSet;
import ghidra.feature.vt.api.main.VTSession;
import ghidra.framework.main.AppInfo;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainObject;
import ghidra.framework.model.Project;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.common.McpTransportContext;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import reactor.core.publisher.Mono;

@GhidraMcpTool(
    name = "Read VT Matches",
    description = "Read and list Version Tracking matches with filtering and pagination.",
    mcpName = "read_vt_matches",
    readOnlyHint = true,
    idempotentHint = true,
    mcpDescription =
        """
        <use_case>
        Read matches from a Version Tracking session. Can retrieve a single match by addresses
        or list all matches with optional filtering by status, type, similarity scores, and correlator.
        </use_case>

        <important_notes>
        - Provide both source_address and destination_address to get a single specific match
        - Omit addresses to list all matches with optional filtering
        - Results are paginated - use opaque v1 cursor parameter for subsequent pages
        - Similarity and confidence scores range from 0.0 to 1.0
        - Status values: AVAILABLE, ACCEPTED, REJECTED, BLOCKED
        - Match types: FUNCTION, DATA
        </important_notes>

        <return_value_summary>
        Returns a paginated list of VTMatchInfo objects containing addresses, scores, status,
        correlator info, and symbol names where available.
        </return_value_summary>
        """)
public class ReadVTMatchesTool extends BaseMcpTool {

  public static final String ARG_SESSION_NAME = "session_name";
  public static final String ARG_SOURCE_ADDRESS = "source_address";
  public static final String ARG_DESTINATION_ADDRESS = "destination_address";
  public static final String ARG_STATUS = "status";
  public static final String ARG_MATCH_TYPE = "match_type";
  public static final String ARG_MIN_SIMILARITY = "min_similarity";
  public static final String ARG_MIN_CONFIDENCE = "min_confidence";
  public static final String ARG_CORRELATOR = "correlator";

  @Override
  public JsonSchema schema() {
    IObjectSchemaBuilder schemaRoot = createBaseSchemaNode();

    schemaRoot.property(
        ARG_SESSION_NAME, SchemaBuilder.string(mapper).description("Name of the VT session"));

    schemaRoot.property(
        ARG_SOURCE_ADDRESS,
        SchemaBuilder.string(mapper)
            .description("Source address for single match lookup")
            .pattern("^(0x)?[0-9a-fA-F]+$"));

    schemaRoot.property(
        ARG_DESTINATION_ADDRESS,
        SchemaBuilder.string(mapper)
            .description("Destination address for single match lookup")
            .pattern("^(0x)?[0-9a-fA-F]+$"));

    schemaRoot.property(
        ARG_STATUS,
        SchemaBuilder.string(mapper)
            .enumValues("AVAILABLE", "ACCEPTED", "REJECTED", "BLOCKED")
            .description("Filter by match status"));

    schemaRoot.property(
        ARG_MATCH_TYPE,
        SchemaBuilder.string(mapper)
            .enumValues("FUNCTION", "DATA")
            .description("Filter by match type"));

    schemaRoot.property(
        ARG_MIN_SIMILARITY,
        SchemaBuilder.number(mapper)
            .description("Minimum similarity score (0.0 to 1.0)")
            .minimum(0.0)
            .maximum(1.0));

    schemaRoot.property(
        ARG_MIN_CONFIDENCE,
        SchemaBuilder.number(mapper)
            .description("Minimum confidence score (0.0 to 1.0)")
            .minimum(0.0)
            .maximum(1.0));

    schemaRoot.property(
        ARG_CORRELATOR, SchemaBuilder.string(mapper).description("Filter by correlator name"));

    schemaRoot.property(
        ARG_CURSOR,
        SchemaBuilder.string(mapper)
            .description(
                "Pagination cursor from previous request (format:"
                    + " v1:<base64url_match_set_index>:<base64url_match_index>)"));

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

    schemaRoot.requiredProperty(ARG_SESSION_NAME);

    return schemaRoot.build();
  }

  @Override
  public Mono<? extends Object> execute(
      McpTransportContext context, Map<String, Object> args, PluginTool tool) {
    return Mono.fromCallable(
        () -> {
          String sessionName = getRequiredStringArgument(args, ARG_SESSION_NAME);
          Optional<String> sourceAddr = getOptionalStringArgument(args, ARG_SOURCE_ADDRESS);
          Optional<String> destAddr = getOptionalStringArgument(args, ARG_DESTINATION_ADDRESS);
          validateSingleMatchAddressArguments(sourceAddr, destAddr);

          VTSession session = openVTSession(sessionName);
          try {
            // If both addresses provided, return single match
            if (sourceAddr.isPresent() && destAddr.isPresent()) {
              return getSingleMatch(session, sourceAddr.get(), destAddr.get());
            }

            // Otherwise, list matches with filtering
            return listMatches(session, args);
          } finally {
            session.release(this);
          }
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

    Address sourceAddr = sourceProgram.getAddressFactory().getAddress(sourceAddrStr);
    Address destAddr = destProgram.getAddressFactory().getAddress(destAddrStr);

    if (sourceAddr == null || destAddr == null) {
      throw new GhidraMcpException(
          GhidraMcpError.validation()
              .errorCode(GhidraMcpError.ErrorCode.ADDRESS_PARSE_FAILED)
              .message("Invalid address")
              .build());
    }

    // Search all match sets for the specific match
    for (VTMatchSet matchSet : session.getMatchSets()) {
      for (VTMatch match : matchSet.getMatches()) {
        if (match.getAssociation().getSourceAddress().equals(sourceAddr)
            && match.getAssociation().getDestinationAddress().equals(destAddr)) {
          return buildMatchInfo(match, matchSet, sourceProgram, destProgram);
        }
      }
    }

    throw new GhidraMcpException(
        GhidraMcpError.notFound("match", sourceAddrStr + " -> " + destAddrStr));
  }

  private PaginatedResult<VTMatchInfo> listMatches(VTSession session, Map<String, Object> args)
      throws GhidraMcpException {
    // Get filter parameters
    Optional<String> statusFilter = getOptionalStringArgument(args, ARG_STATUS);
    Optional<String> typeFilter = getOptionalStringArgument(args, ARG_MATCH_TYPE);
    Optional<Double> minSimilarity = getOptionalDoubleArgument(args, ARG_MIN_SIMILARITY);
    Optional<Double> minConfidence = getOptionalDoubleArgument(args, ARG_MIN_CONFIDENCE);
    Optional<String> correlatorFilter = getOptionalStringArgument(args, ARG_CORRELATOR);
    Optional<String> cursorOpt = getOptionalStringArgument(args, ARG_CURSOR);
    int pageSize =
        getOptionalIntArgument(args, ARG_PAGE_SIZE)
            .filter(size -> size > 0)
            .map(size -> Math.min(size, MAX_PAGE_LIMIT))
            .orElse(DEFAULT_PAGE_LIMIT);

    Program sourceProgram = session.getSourceProgram();
    Program destProgram = session.getDestinationProgram();

    // Parse cursor (opaque format: v1:<base64url_match_set_index>:<base64url_match_index>)
    int startMatchSetIndex = 0;
    int startMatchIndex = 0;
    if (cursorOpt.isPresent()) {
      String cursorValue = cursorOpt.get();
      List<String> parts =
          OpaqueCursorCodec.decodeV1(
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

    // Status filter
    if (statusFilter.isPresent()) {
      VTAssociationStatus status = match.getAssociation().getStatus();
      if (!status.name().equalsIgnoreCase(statusFilter.get())) {
        return false;
      }
    }

    // Type filter
    if (typeFilter.isPresent()) {
      VTAssociationType type = match.getAssociation().getType();
      if (!type.name().equalsIgnoreCase(typeFilter.get())) {
        return false;
      }
    }

    // Similarity filter
    if (minSimilarity.isPresent()) {
      double similarity = match.getSimilarityScore().getScore();
      if (similarity < minSimilarity.get()) {
        return false;
      }
    }

    // Confidence filter
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

    // Markup count requires additional dependencies - set to 0 for now
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
    // First try to get function name
    Function func = program.getFunctionManager().getFunctionAt(address);
    if (func != null) {
      return func.getName();
    }

    // Fall back to symbol name
    Symbol symbol = program.getSymbolTable().getPrimarySymbol(address);
    if (symbol != null) {
      return symbol.getName();
    }

    return null;
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
