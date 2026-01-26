package com.themixednuts.tools.versiontracking;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.models.versiontracking.VTMarkupItemInfo;
import com.themixednuts.tools.BaseMcpTool;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.draft7.SchemaBuilder;
import ghidra.feature.vt.api.db.VTSessionDB;
import ghidra.feature.vt.api.main.VTAssociationStatus;
import ghidra.feature.vt.api.main.VTMatch;
import ghidra.feature.vt.api.main.VTMatchSet;
import ghidra.feature.vt.api.main.VTSession;
import ghidra.framework.main.AppInfo;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.DomainObject;
import ghidra.framework.model.Project;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.common.McpTransportContext;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import reactor.core.publisher.Mono;

@GhidraMcpTool(
    name = "Manage VT Markup",
    description = "Apply, unapply, or list Version Tracking markup items.",
    mcpName = "manage_vt_markup",
    mcpDescription =
        """
        <use_case>
        Manage Version Tracking markup items which represent transferable analysis data
        (function names, signatures, comments, labels, etc.) between matched source and
        destination addresses. Use this to migrate analysis from a source program to a
        destination program.
        </use_case>

        <important_notes>
        - Markup can only be applied to ACCEPTED matches
        - Available markup types: function_name, function_signature, labels,
          comment_eol, comment_plate, comment_pre, comment_post, comment_repeatable
        - Apply action can be REPLACE (overwrite) or ADD (merge)
        - apply_all operates on all accepted matches meeting score thresholds
        - Unapply reverses previously applied markup
        - NOTE: This tool requires additional Ghidra libraries (DB.jar) to be present
        </important_notes>

        <return_value_summary>
        - list: Returns list of VTMarkupItemInfo for the specified match
        - apply/apply_all: Returns count of applied items and any failures
        - unapply: Returns count of unapplied items
        </return_value_summary>
        """)
public class ManageVTMarkupTool extends BaseMcpTool {

  public static final String ARG_SESSION_NAME = "session_name";
  public static final String ARG_SOURCE_ADDRESS = "source_address";
  public static final String ARG_DESTINATION_ADDRESS = "destination_address";
  public static final String ARG_MARKUP_TYPES = "markup_types";
  public static final String ARG_APPLY_ACTION = "apply_action";
  public static final String ARG_MIN_SIMILARITY = "min_similarity";
  public static final String ARG_MIN_CONFIDENCE = "min_confidence";

  private static final String ACTION_LIST = "list";
  private static final String ACTION_APPLY = "apply";
  private static final String ACTION_APPLY_ALL = "apply_all";
  private static final String ACTION_UNAPPLY = "unapply";

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
            .enumValues(ACTION_LIST, ACTION_APPLY, ACTION_APPLY_ALL, ACTION_UNAPPLY)
            .description("The markup operation to perform"));

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
        ARG_MIN_SIMILARITY,
        SchemaBuilder.number(mapper)
            .description("Minimum similarity score for apply_all (0.0 to 1.0)")
            .minimum(0.0)
            .maximum(1.0));

    schemaRoot.property(
        ARG_MIN_CONFIDENCE,
        SchemaBuilder.number(mapper)
            .description("Minimum confidence score for apply_all (0.0 to 1.0)")
            .minimum(0.0)
            .maximum(1.0));

    schemaRoot.requiredProperty(ARG_ACTION);
    schemaRoot.requiredProperty(ARG_SESSION_NAME);

    // Conditional requirements
    schemaRoot.allOf(
        // list requires source_address and destination_address
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(ARG_ACTION, SchemaBuilder.string(mapper).constValue(ACTION_LIST)),
                SchemaBuilder.objectDraft7(mapper)
                    .requiredProperty(ARG_SOURCE_ADDRESS)
                    .requiredProperty(ARG_DESTINATION_ADDRESS)),
        // apply requires source_address and destination_address
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(ARG_ACTION, SchemaBuilder.string(mapper).constValue(ACTION_APPLY)),
                SchemaBuilder.objectDraft7(mapper)
                    .requiredProperty(ARG_SOURCE_ADDRESS)
                    .requiredProperty(ARG_DESTINATION_ADDRESS)),
        // unapply requires source_address and destination_address
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(ARG_ACTION, SchemaBuilder.string(mapper).constValue(ACTION_UNAPPLY)),
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
              case ACTION_LIST -> handleList(session, args);
              case ACTION_APPLY -> handleApply(session, args);
              case ACTION_APPLY_ALL -> handleApplyAll(session, args);
              case ACTION_UNAPPLY -> handleUnapply(session, args);
              default ->
                  throw new GhidraMcpException(
                      GhidraMcpError.invalid(
                          ARG_ACTION,
                          action,
                          "must be one of: "
                              + ACTION_LIST
                              + ", "
                              + ACTION_APPLY
                              + ", "
                              + ACTION_APPLY_ALL
                              + ", "
                              + ACTION_UNAPPLY));
            };
          } finally {
            session.release(this);
          }
        });
  }

  /** Gets markup items from a match using reflection to avoid compile-time dependency issues. */
  @SuppressWarnings("unchecked")
  private Collection<Object> getMarkupItemsReflective(VTMatch match) throws GhidraMcpException {
    try {
      Method getMarkupItems = match.getClass().getMethod("getMarkupItems", TaskMonitor.class);
      return (Collection<Object>) getMarkupItems.invoke(match, TaskMonitor.DUMMY);
    } catch (NoSuchMethodException e) {
      throw new GhidraMcpException(
          GhidraMcpError.execution()
              .message("Markup operations not available. Ensure DB.jar is in the lib folder.")
              .hint("Copy DB.jar from <GHIDRA_INSTALL>/Ghidra/Framework/DB/lib/DB.jar to lib/")
              .build());
    } catch (Exception e) {
      throw new GhidraMcpException(
          GhidraMcpError.execution()
              .message("Failed to get markup items: " + e.getMessage())
              .build());
    }
  }

  private List<VTMarkupItemInfo> handleList(VTSession session, Map<String, Object> args)
      throws GhidraMcpException {
    VTMatch match = findMatch(session, args);
    Collection<Object> markupItems = getMarkupItemsReflective(match);

    List<VTMarkupItemInfo> results = new ArrayList<>();
    for (Object item : markupItems) {
      results.add(buildMarkupItemInfo(item));
    }

    return results;
  }

  private Map<String, Object> handleApply(VTSession session, Map<String, Object> args)
      throws GhidraMcpException {
    VTMatch match = findMatch(session, args);

    // Check if match is accepted
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
    String applyActionStr = getOptionalStringArgument(args, ARG_APPLY_ACTION).orElse("REPLACE");

    VTSessionDB sessionDB = (VTSessionDB) session;
    int txId = sessionDB.startTransaction("Apply Markup");
    int appliedCount = 0;
    List<String> failures = new ArrayList<>();

    try {
      Collection<Object> markupItems = getMarkupItemsReflective(match);

      for (Object item : markupItems) {
        if (!shouldApplyMarkupItem(item, requestedTypes)) {
          continue;
        }

        try {
          applyMarkupItem(item, applyActionStr);
          appliedCount++;
        } catch (Exception e) {
          failures.add(getMarkupTypeName(item) + ": " + e.getMessage());
        }
      }

      sessionDB.endTransaction(txId, true);
    } catch (GhidraMcpException e) {
      sessionDB.endTransaction(txId, false);
      throw e;
    } catch (Exception e) {
      sessionDB.endTransaction(txId, false);
      throw new GhidraMcpException(
          GhidraMcpError.execution()
              .errorCode(GhidraMcpError.ErrorCode.UNEXPECTED_ERROR)
              .message("Failed to apply markup: " + e.getMessage())
              .build());
    }

    Map<String, Object> result = new HashMap<>();
    result.put("action", "apply");
    result.put("applied_count", appliedCount);
    if (!failures.isEmpty()) {
      result.put("failures", failures);
    }

    return result;
  }

  private Map<String, Object> handleApplyAll(VTSession session, Map<String, Object> args)
      throws GhidraMcpException {
    Optional<Double> minSimilarity = getOptionalDoubleArgument(args, ARG_MIN_SIMILARITY);
    Optional<Double> minConfidence = getOptionalDoubleArgument(args, ARG_MIN_CONFIDENCE);
    Set<String> requestedTypes = getMarkupTypesFilter(args);
    String applyActionStr = getOptionalStringArgument(args, ARG_APPLY_ACTION).orElse("REPLACE");

    VTSessionDB sessionDB = (VTSessionDB) session;
    int txId = sessionDB.startTransaction("Apply All Markup");
    int totalApplied = 0;
    int matchesProcessed = 0;
    List<String> failures = new ArrayList<>();

    try {
      for (VTMatchSet matchSet : session.getMatchSets()) {
        for (VTMatch match : matchSet.getMatches()) {
          // Only process accepted matches
          if (match.getAssociation().getStatus() != VTAssociationStatus.ACCEPTED) {
            continue;
          }

          // Apply score filters
          double similarity = match.getSimilarityScore().getScore();
          double confidence = match.getConfidenceScore().getScore();

          if (minSimilarity.isPresent() && similarity < minSimilarity.get()) {
            continue;
          }
          if (minConfidence.isPresent() && confidence < minConfidence.get()) {
            continue;
          }

          matchesProcessed++;

          try {
            Collection<Object> markupItems = getMarkupItemsReflective(match);
            for (Object item : markupItems) {
              if (!shouldApplyMarkupItem(item, requestedTypes)) {
                continue;
              }

              try {
                applyMarkupItem(item, applyActionStr);
                totalApplied++;
              } catch (Exception e) {
                if (failures.size() < 10) { // Limit failure messages
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
            // Skip matches where we can't get markup items
            if (failures.size() < 10) {
              failures.add(match.getAssociation().getSourceAddress() + ": " + e.getMessage());
            }
          }
        }
      }

      sessionDB.endTransaction(txId, true);
    } catch (Exception e) {
      sessionDB.endTransaction(txId, false);
      throw new GhidraMcpException(
          GhidraMcpError.execution()
              .errorCode(GhidraMcpError.ErrorCode.UNEXPECTED_ERROR)
              .message("Failed to apply all markup: " + e.getMessage())
              .build());
    }

    Map<String, Object> result = new HashMap<>();
    result.put("action", "apply_all");
    result.put("matches_processed", matchesProcessed);
    result.put("applied_count", totalApplied);
    if (!failures.isEmpty()) {
      result.put("failures", failures);
      if (failures.size() >= 10) {
        result.put("failures_truncated", true);
      }
    }

    return result;
  }

  private Map<String, Object> handleUnapply(VTSession session, Map<String, Object> args)
      throws GhidraMcpException {
    VTMatch match = findMatch(session, args);
    Set<String> requestedTypes = getMarkupTypesFilter(args);

    VTSessionDB sessionDB = (VTSessionDB) session;
    int txId = sessionDB.startTransaction("Unapply Markup");
    int unappliedCount = 0;

    try {
      Collection<Object> markupItems = getMarkupItemsReflective(match);

      for (Object item : markupItems) {
        if (!shouldApplyMarkupItem(item, requestedTypes)) {
          continue;
        }

        // Only unapply items that have been applied
        if (isMarkupApplied(item)) {
          try {
            unapplyMarkupItem(item);
            unappliedCount++;
          } catch (Exception e) {
            // Skip items that can't be unapplied
          }
        }
      }

      sessionDB.endTransaction(txId, true);
    } catch (GhidraMcpException e) {
      sessionDB.endTransaction(txId, false);
      throw e;
    } catch (Exception e) {
      sessionDB.endTransaction(txId, false);
      throw new GhidraMcpException(
          GhidraMcpError.execution()
              .errorCode(GhidraMcpError.ErrorCode.UNEXPECTED_ERROR)
              .message("Failed to unapply markup: " + e.getMessage())
              .build());
    }

    Map<String, Object> result = new HashMap<>();
    result.put("action", "unapply");
    result.put("unapplied_count", unappliedCount);

    return result;
  }

  private VTMatch findMatch(VTSession session, Map<String, Object> args) throws GhidraMcpException {
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

    for (VTMatchSet matchSet : session.getMatchSets()) {
      for (VTMatch match : matchSet.getMatches()) {
        if (match.getAssociation().getSourceAddress().equals(sourceAddr)
            && match.getAssociation().getDestinationAddress().equals(destAddr)) {
          return match;
        }
      }
    }

    throw new GhidraMcpException(
        GhidraMcpError.notFound("match", sourceAddrStr + " -> " + destAddrStr));
  }

  @SuppressWarnings("unchecked")
  private Set<String> getMarkupTypesFilter(Map<String, Object> args) {
    Object typesObj = args.get(ARG_MARKUP_TYPES);
    if (typesObj == null) {
      return null; // null means apply all types
    }

    Set<String> types = new HashSet<>();
    if (typesObj instanceof List) {
      List<String> typesList = (List<String>) typesObj;
      for (String type : typesList) {
        String mappedType = MARKUP_TYPE_MAP.get(type.toLowerCase());
        if (mappedType != null) {
          types.add(mappedType);
        }
      }
    }

    return types.isEmpty() ? null : types;
  }

  private boolean shouldApplyMarkupItem(Object item, Set<String> requestedTypes) {
    // If no filter, apply all
    if (requestedTypes == null) {
      return true;
    }

    String typeName = getMarkupTypeName(item);
    if (typeName == null) {
      return false;
    }

    for (String requested : requestedTypes) {
      if (typeName.contains(requested)) {
        return true;
      }
    }

    return false;
  }

  private String getMarkupTypeName(Object item) {
    try {
      Method getMarkupType = item.getClass().getMethod("getMarkupType");
      Object markupType = getMarkupType.invoke(item);
      if (markupType != null) {
        return markupType.getClass().getSimpleName();
      }
    } catch (Exception e) {
      // Fall back to class name
    }
    return item.getClass().getSimpleName();
  }

  private void applyMarkupItem(Object item, String applyActionStr) throws Exception {
    // Get the apply action type enum value
    Class<?> actionTypeClass =
        Class.forName("ghidra.feature.vt.api.main.VTMarkupItemApplyActionType");
    Object applyAction =
        "ADD".equalsIgnoreCase(applyActionStr)
            ? Enum.valueOf((Class<Enum>) actionTypeClass, "ADD")
            : Enum.valueOf((Class<Enum>) actionTypeClass, "REPLACE");

    // Get ToolOptions class and create instance
    Class<?> toolOptionsClass = Class.forName("ghidra.framework.options.ToolOptions");
    Object toolOptions = toolOptionsClass.getConstructor(String.class).newInstance("VTMarkup");

    // Call apply method
    Method applyMethod = item.getClass().getMethod("apply", actionTypeClass, toolOptionsClass);
    applyMethod.invoke(item, applyAction, toolOptions);
  }

  private boolean isMarkupApplied(Object item) {
    try {
      Method getStatus = item.getClass().getMethod("getStatus");
      Object status = getStatus.invoke(item);
      if (status != null) {
        Method isUnappliable = status.getClass().getMethod("isUnappliable");
        return (Boolean) isUnappliable.invoke(status);
      }
    } catch (Exception e) {
      // Default to not applied
    }
    return false;
  }

  private void unapplyMarkupItem(Object item) throws Exception {
    Method unapplyMethod = item.getClass().getMethod("unapply");
    unapplyMethod.invoke(item);
  }

  private VTMarkupItemInfo buildMarkupItemInfo(Object item) {
    String sourceValue = null;
    String destValue = null;
    String sourceAddr = null;
    String destAddr = null;
    String typeName = "Unknown";
    String status = "UNKNOWN";

    try {
      Method getSourceValue = item.getClass().getMethod("getSourceValue");
      Object srcVal = getSourceValue.invoke(item);
      if (srcVal != null) {
        sourceValue = srcVal.toString();
      }
    } catch (Exception e) {
      // Skip if can't get source value
    }

    try {
      Method getDestValue = item.getClass().getMethod("getCurrentDestinationValue");
      Object destVal = getDestValue.invoke(item);
      if (destVal != null) {
        destValue = destVal.toString();
      }
    } catch (Exception e) {
      // Skip if can't get dest value
    }

    try {
      Method getSourceAddress = item.getClass().getMethod("getSourceAddress");
      Object addr = getSourceAddress.invoke(item);
      if (addr != null) {
        sourceAddr = addr.toString();
      }
    } catch (Exception e) {
      // Skip
    }

    try {
      Method getDestAddress = item.getClass().getMethod("getDestinationAddress");
      Object addr = getDestAddress.invoke(item);
      if (addr != null) {
        destAddr = addr.toString();
      }
    } catch (Exception e) {
      // Skip
    }

    try {
      Method getMarkupType = item.getClass().getMethod("getMarkupType");
      Object markupType = getMarkupType.invoke(item);
      if (markupType != null) {
        Method getDisplayName = markupType.getClass().getMethod("getDisplayName");
        Object name = getDisplayName.invoke(markupType);
        if (name != null) {
          typeName = name.toString();
        }
      }
    } catch (Exception e) {
      // Use default
    }

    try {
      Method getStatus = item.getClass().getMethod("getStatus");
      Object statusObj = getStatus.invoke(item);
      if (statusObj != null) {
        status = statusObj.toString();
      }
    } catch (Exception e) {
      // Use default
    }

    return new VTMarkupItemInfo(typeName, sourceAddr, destAddr, sourceValue, destValue, status);
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

    DomainFile sessionFile = findSessionFile(project, sessionName);
    if (sessionFile == null) {
      throw new GhidraMcpException(GhidraMcpError.notFound("VT session", sessionName));
    }

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

  private DomainFile findSessionFile(Project project, String sessionName) {
    return findDomainFileRecursive(project.getProjectData().getRootFolder(), sessionName);
  }

  private DomainFile findDomainFileRecursive(DomainFolder folder, String name) {
    for (DomainFile file : folder.getFiles()) {
      if (file.getName().equals(name)) {
        return file;
      }
    }
    for (DomainFolder subfolder : folder.getFolders()) {
      DomainFile found = findDomainFileRecursive(subfolder, name);
      if (found != null) {
        return found;
      }
    }
    return null;
  }
}
