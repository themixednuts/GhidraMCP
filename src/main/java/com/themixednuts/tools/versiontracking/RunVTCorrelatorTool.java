package com.themixednuts.tools.versiontracking;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.models.versiontracking.VTCorrelatorInfo;
import com.themixednuts.tools.BaseMcpTool;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.draft7.SchemaBuilder;
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
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.common.McpTransportContext;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import reactor.core.publisher.Mono;

@GhidraMcpTool(
    name = "Run VT Correlator",
    description = "Run Version Tracking correlators to find matches between programs.",
    mcpName = "run_vt_correlator",
    mcpDescription =
        """
        <use_case>
        Run correlators on a Version Tracking session to find matches between source and
        destination programs. Correlators use different algorithms to identify corresponding
        functions/data between program versions.
        </use_case>

        <important_notes>
        - Session must be created first with manage_vt_session
        - Different correlators find different types of matches:
          * exact_bytes: Functions with identical byte sequences
          * exact_instructions: Functions with identical instruction sequences
          * exact_data: Data items with identical byte values
          * symbol_name: Symbols with matching names
        - Running the same correlator twice does not create duplicates
        - Can optionally limit to specific address ranges
        </important_notes>

        <return_value_summary>
        - list: Returns list of available correlator types with descriptions
        - run: Returns match count and correlator info for the run
        </return_value_summary>
        """)
public class RunVTCorrelatorTool extends BaseMcpTool {

  public static final String ARG_SESSION_NAME = "session_name";
  public static final String ARG_CORRELATOR_TYPE = "correlator_type";
  public static final String ARG_SOURCE_MIN_ADDRESS = "source_min_address";
  public static final String ARG_SOURCE_MAX_ADDRESS = "source_max_address";
  public static final String ARG_DEST_MIN_ADDRESS = "destination_min_address";
  public static final String ARG_DEST_MAX_ADDRESS = "destination_max_address";
  public static final String ARG_EXCLUDE_ACCEPTED = "exclude_accepted";

  private static final String ACTION_LIST = "list";
  private static final String ACTION_RUN = "run";

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

  @Override
  public JsonSchema schema() {
    var schemaRoot = createDraft7SchemaNode();

    schemaRoot.property(
        ARG_ACTION,
        SchemaBuilder.string(mapper)
            .enumValues(ACTION_LIST, ACTION_RUN)
            .description("The correlator operation to perform"));

    schemaRoot.property(
        ARG_SESSION_NAME, SchemaBuilder.string(mapper).description("Name of the VT session"));

    schemaRoot.property(
        ARG_CORRELATOR_TYPE,
        SchemaBuilder.string(mapper)
            .enumValues("exact_bytes", "exact_instructions", "exact_data", "symbol_name")
            .description("Type of correlator to run"));

    schemaRoot.property(
        ARG_SOURCE_MIN_ADDRESS,
        SchemaBuilder.string(mapper)
            .description("Minimum address in source program to correlate")
            .pattern("^(0x)?[0-9a-fA-F]+$"));

    schemaRoot.property(
        ARG_SOURCE_MAX_ADDRESS,
        SchemaBuilder.string(mapper)
            .description("Maximum address in source program to correlate")
            .pattern("^(0x)?[0-9a-fA-F]+$"));

    schemaRoot.property(
        ARG_DEST_MIN_ADDRESS,
        SchemaBuilder.string(mapper)
            .description("Minimum address in destination program to correlate")
            .pattern("^(0x)?[0-9a-fA-F]+$"));

    schemaRoot.property(
        ARG_DEST_MAX_ADDRESS,
        SchemaBuilder.string(mapper)
            .description("Maximum address in destination program to correlate")
            .pattern("^(0x)?[0-9a-fA-F]+$"));

    schemaRoot.property(
        ARG_EXCLUDE_ACCEPTED,
        SchemaBuilder.bool(mapper)
            .description("Exclude addresses that already have accepted matches (default: true)"));

    schemaRoot.requiredProperty(ARG_ACTION);

    // Conditional requirements
    schemaRoot.allOf(
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(ARG_ACTION, SchemaBuilder.string(mapper).constValue(ACTION_RUN)),
                SchemaBuilder.objectDraft7(mapper)
                    .requiredProperty(ARG_SESSION_NAME)
                    .requiredProperty(ARG_CORRELATOR_TYPE)));

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
            case ACTION_LIST -> handleList();
            case ACTION_RUN -> handleRun(args);
            default ->
                throw new GhidraMcpException(
                    GhidraMcpError.invalid(
                        ARG_ACTION, action, "must be one of: " + ACTION_LIST + ", " + ACTION_RUN));
          };
        });
  }

  private List<VTCorrelatorInfo> handleList() {
    List<VTCorrelatorInfo> correlators = new ArrayList<>();

    correlators.add(
        new VTCorrelatorInfo(
            "Exact Bytes Match", "exact_bytes", "Finds functions with identical byte sequences"));

    correlators.add(
        new VTCorrelatorInfo(
            "Exact Instructions Match",
            "exact_instructions",
            "Finds functions with identical instruction sequences (ignoring operand values)"));

    correlators.add(
        new VTCorrelatorInfo(
            "Exact Data Match", "exact_data", "Finds data items with identical byte values"));

    correlators.add(
        new VTCorrelatorInfo(
            "Symbol Name Match", "symbol_name", "Finds symbols with matching names"));

    return correlators;
  }

  private Map<String, Object> handleRun(Map<String, Object> args) throws GhidraMcpException {
    String sessionName = getRequiredStringArgument(args, ARG_SESSION_NAME);
    String correlatorType = getRequiredStringArgument(args, ARG_CORRELATOR_TYPE);
    Optional<String> sourceMinAddr = getOptionalStringArgument(args, ARG_SOURCE_MIN_ADDRESS);
    Optional<String> sourceMaxAddr = getOptionalStringArgument(args, ARG_SOURCE_MAX_ADDRESS);
    Optional<String> destMinAddr = getOptionalStringArgument(args, ARG_DEST_MIN_ADDRESS);
    Optional<String> destMaxAddr = getOptionalStringArgument(args, ARG_DEST_MAX_ADDRESS);
    boolean excludeAccepted = getOptionalBooleanArgument(args, ARG_EXCLUDE_ACCEPTED).orElse(true);

    // Get the correlator factory class name
    String factoryClassName = CORRELATOR_CLASS_MAP.get(correlatorType.toLowerCase());
    if (factoryClassName == null) {
      throw new GhidraMcpException(
          GhidraMcpError.invalid(
              ARG_CORRELATOR_TYPE,
              correlatorType,
              "must be one of: exact_bytes, exact_instructions, exact_data, symbol_name"));
    }

    VTSession session = openVTSession(sessionName);
    try {
      Program sourceProgram = session.getSourceProgram();
      Program destProgram = session.getDestinationProgram();

      // Build address sets
      AddressSetView sourceSet =
          buildAddressSet(
              sourceProgram, sourceMinAddr, sourceMaxAddr, session, excludeAccepted, true);
      AddressSetView destSet =
          buildAddressSet(destProgram, destMinAddr, destMaxAddr, session, excludeAccepted, false);

      // Run correlation using reflection
      VTMatchSet matchSet =
          runCorrelatorReflective(
              session, factoryClassName, sourceProgram, sourceSet, destProgram, destSet);

      // Build result
      Collection<VTMatch> matches = matchSet.getMatches();
      Map<String, Object> result = new HashMap<>();
      result.put("correlator", correlatorType);
      result.put("correlator_name", matchSet.getProgramCorrelatorInfo().getName());
      result.put("match_count", matches.size());
      result.put("session_name", sessionName);

      return result;
    } finally {
      session.release(this);
    }
  }

  /** Runs a correlator using reflection to avoid compile-time dependency on correlator classes. */
  private VTMatchSet runCorrelatorReflective(
      VTSession session,
      String factoryClassName,
      Program sourceProgram,
      AddressSetView sourceSet,
      Program destProgram,
      AddressSetView destSet)
      throws GhidraMcpException {
    try {
      // Load the factory class
      Class<?> factoryClass = Class.forName(factoryClassName);

      // Create factory instance
      Constructor<?> constructor = factoryClass.getDeclaredConstructor();
      Object factory = constructor.newInstance();

      // Get VTOptions class and create instance
      Class<?> vtOptionsClass = Class.forName("ghidra.feature.vt.api.util.VTOptions");
      Object options = vtOptionsClass.getConstructor(String.class).newInstance("Options");

      // Get createCorrelator method
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

      // Create correlator (null serviceProvider works for basic correlators)
      Object correlator =
          createCorrelatorMethod.invoke(
              factory, null, sourceProgram, sourceSet, destProgram, destSet, options);

      // Get VTSessionDB class for transaction handling
      Class<?> vtSessionDBClass = Class.forName("ghidra.feature.vt.api.db.VTSessionDB");

      // Start transaction
      Method startTxMethod = vtSessionDBClass.getMethod("startTransaction", String.class);
      int txId = (Integer) startTxMethod.invoke(session, "Run Correlator");

      VTMatchSet matchSet;
      try {
        // Run correlation: correlator.correlate(session, TaskMonitor.DUMMY)
        Class<?> vtSessionClass = VTSession.class;
        Method correlateMethod =
            correlator.getClass().getMethod("correlate", vtSessionClass, TaskMonitor.class);
        matchSet = (VTMatchSet) correlateMethod.invoke(correlator, session, TaskMonitor.DUMMY);

        // Commit transaction
        Method endTxMethod = vtSessionDBClass.getMethod("endTransaction", int.class, boolean.class);
        endTxMethod.invoke(session, txId, true);
      } catch (Exception e) {
        // Rollback transaction
        try {
          Method endTxMethod =
              vtSessionDBClass.getMethod("endTransaction", int.class, boolean.class);
          endTxMethod.invoke(session, txId, false);
        } catch (Exception ignored) {
        }

        Throwable cause = e.getCause() != null ? e.getCause() : e;
        throw new GhidraMcpException(
            GhidraMcpError.execution()
                .errorCode(GhidraMcpError.ErrorCode.UNEXPECTED_ERROR)
                .message("Correlation failed: " + cause.getMessage())
                .build());
      }

      return matchSet;
    } catch (ClassNotFoundException e) {
      throw new GhidraMcpException(
          GhidraMcpError.execution()
              .message("Correlator not available. Ensure all required Ghidra libraries are in lib/")
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

  private AddressSetView buildAddressSet(
      Program program,
      Optional<String> minAddr,
      Optional<String> maxAddr,
      VTSession session,
      boolean excludeAccepted,
      boolean isSource)
      throws GhidraMcpException {

    AddressFactory factory = program.getAddressFactory();
    AddressSet set;

    if (minAddr.isPresent() && maxAddr.isPresent()) {
      Address min = factory.getAddress(minAddr.get());
      Address max = factory.getAddress(maxAddr.get());
      if (min == null || max == null) {
        throw new GhidraMcpException(
            GhidraMcpError.validation()
                .errorCode(GhidraMcpError.ErrorCode.ADDRESS_PARSE_FAILED)
                .message("Invalid address range")
                .build());
      }
      set = new AddressSet(min, max);
    } else if (minAddr.isPresent() || maxAddr.isPresent()) {
      throw new GhidraMcpException(
          GhidraMcpError.validation()
              .errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
              .message("Both min and max addresses must be provided together, or neither")
              .build());
    } else {
      // Use entire memory space
      set = new AddressSet(program.getMemory());
    }

    // Optionally exclude already-accepted addresses
    if (excludeAccepted) {
      for (VTMatchSet matchSet : session.getMatchSets()) {
        for (VTMatch match : matchSet.getMatches()) {
          if (match.getAssociation().getStatus()
              == ghidra.feature.vt.api.main.VTAssociationStatus.ACCEPTED) {
            Address addr =
                isSource
                    ? match.getAssociation().getSourceAddress()
                    : match.getAssociation().getDestinationAddress();
            set.delete(addr, addr);
          }
        }
      }
    }

    return set;
  }
}
