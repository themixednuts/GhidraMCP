package com.themixednuts.tools.versiontracking;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.models.versiontracking.VTMarkupItemInfo;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.draft7.SchemaBuilder;
import ghidra.feature.vt.api.main.VTAssociationStatus;
import ghidra.feature.vt.api.main.VTMatch;
import ghidra.feature.vt.api.main.VTMatchSet;
import ghidra.feature.vt.api.main.VTSession;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.common.McpTransportContext;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
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
public class ManageVTMarkupTool extends BaseVTTool {

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
        SchemaBuilder.string(mapper).description("Source address of the match"));

    schemaRoot.property(
        ARG_DESTINATION_ADDRESS,
        SchemaBuilder.string(mapper).description("Destination address of the match"));

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
            .description("Minimum confidence score for apply_all (>= 0.0)")
            .minimum(0.0));

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
          boolean forUpdate = !ACTION_LIST.equals(normalizedAction);

          return withSession(
              sessionName,
              forUpdate,
              session ->
                  switch (normalizedAction) {
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
                  });
        });
  }

  /**
   * Gets markup items from a match's association using reflection to avoid compile-time dependency
   * issues. The getMarkupItems method is defined on VTAssociation (VTAssociationDB), not VTMatch.
   */
  @SuppressWarnings("unchecked")
  private Collection<Object> getMarkupItemsReflective(VTMatch match) throws GhidraMcpException {
    try {
      Object association = match.getAssociation();
      Method getMarkupItems = association.getClass().getMethod("getMarkupItems", TaskMonitor.class);
      return (Collection<Object>) getMarkupItems.invoke(association, TaskMonitor.DUMMY);
    } catch (NoSuchMethodException e) {
      throw new GhidraMcpException(
          GhidraMcpError.execution()
              .message("Markup operations not available. Ensure DB.jar is in the lib folder.")
              .hint("Copy DB.jar from <GHIDRA_INSTALL>/Ghidra/Framework/DB/lib/DB.jar to lib/")
              .build());
    } catch (Exception e) {
      Throwable cause = e.getCause() != null ? e.getCause() : e;
      throw new GhidraMcpException(
          GhidraMcpError.execution()
              .message("Failed to get markup items: " + cause.getMessage())
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
    String applyActionStr = resolveApplyAction(args);

    int appliedCount;
    List<String> failures = new ArrayList<>();

    appliedCount =
        inSessionTransaction(
            session,
            "Apply Markup",
            "Failed to apply markup: ",
            () -> {
              int applied = 0;
              Collection<Object> markupItems = getMarkupItemsReflective(match);

              for (Object item : markupItems) {
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
  }

  private Map<String, Object> handleApplyAll(VTSession session, Map<String, Object> args)
      throws GhidraMcpException {
    Optional<Double> minSimilarity =
        getOptionalBoundedDoubleArgument(args, ARG_MIN_SIMILARITY, 0.0, 1.0);
    Optional<Double> minConfidence =
        getOptionalBoundedDoubleArgument(args, ARG_MIN_CONFIDENCE, 0.0, null);
    Set<String> requestedTypes = getMarkupTypesFilter(args);
    String applyActionStr = resolveApplyAction(args);

    int totalApplied;
    int matchesProcessed;
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
                    Collection<Object> markupItems = getMarkupItemsReflective(match);
                    for (Object item : markupItems) {
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
    matchesProcessed = applyAllResult[0];
    totalApplied = applyAllResult[1];

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

    int unappliedCount =
        inSessionTransaction(
            session,
            "Unapply Markup",
            "Failed to unapply markup: ",
            () -> {
              int unapplied = 0;
              Collection<Object> markupItems = getMarkupItemsReflective(match);

              for (Object item : markupItems) {
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
  }

  private VTMatch findMatch(VTSession session, Map<String, Object> args) throws GhidraMcpException {
    String sourceAddrStr = getRequiredStringArgument(args, ARG_SOURCE_ADDRESS);
    String destAddrStr = getRequiredStringArgument(args, ARG_DESTINATION_ADDRESS);
    return VTMatchResolver.findMatch(
            session, sourceAddrStr, destAddrStr, ARG_SOURCE_ADDRESS, ARG_DESTINATION_ADDRESS)
        .match();
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
}
