package com.themixednuts.tools.versiontracking;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.models.OperationResult;
import com.themixednuts.models.versiontracking.VTSessionInfo;
import com.themixednuts.utils.GhidraStateUtils;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.draft7.SchemaBuilder;
import ghidra.feature.vt.api.main.VTMatch;
import ghidra.feature.vt.api.main.VTMatchSet;
import ghidra.feature.vt.api.main.VTSession;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.DomainObject;
import ghidra.framework.model.Project;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.InvalidNameException;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.common.McpTransportContext;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import reactor.core.publisher.Mono;

@GhidraMcpTool(
    name = "VT Sessions",
    description = "Create, open, close, list, and get info about Version Tracking sessions.",
    mcpName = "vt_sessions",
    mcpDescription =
        """
        <use_case>
        Manage Version Tracking sessions which are used to compare different versions of programs
        and migrate analysis (functions, symbols, data types, comments) between them. Sessions
        store matches and markup state between source and destination programs.
        </use_case>

        <important_notes>
        - VT sessions require both source and destination programs to exist in the project
        - Sessions are stored as .vt files in the project
        - Creating a session does not automatically run correlators - use vt_operations after
        - Close sessions when done to release resources
        - NOTE: Session creation requires DB.jar to be present in lib/
        </important_notes>

        <return_value_summary>
        - create/open/info: Returns VTSessionInfo with program names and match statistics
        - list: Returns list of available VT session project paths (for example, /Folder/Session.vt)
        - close: Returns OperationResult confirming closure
        </return_value_summary>
        """)
public class VTSessionsTool extends BaseVTTool {
  public static final String ARG_SOURCE_FILE = "source_file";
  public static final String ARG_DESTINATION_FILE = "destination_file";

  record CreateTarget(DomainFolder folder, String fileName) {}

  private static final String ACTION_CREATE = "create";
  private static final String ACTION_OPEN = "open";
  private static final String ACTION_LIST = "list";
  private static final String ACTION_CLOSE = "close";
  private static final String ACTION_INFO = "info";

  @Override
  public JsonSchema schema() {
    var schemaRoot = createDraft7SchemaNode();

    schemaRoot.property(
        ARG_ACTION,
        SchemaBuilder.string(mapper)
            .enumValues(ACTION_CREATE, ACTION_OPEN, ACTION_LIST, ACTION_CLOSE, ACTION_INFO)
            .description("The VT session operation to perform"));

    schemaRoot.property(
        ARG_SESSION_NAME,
        SchemaBuilder.string(mapper)
            .description("Name of the VT session (used for create, open, close, info)"));

    schemaRoot.property(
        ARG_SOURCE_FILE,
        SchemaBuilder.string(mapper)
            .description("Name of the source program file (for create action)"));

    schemaRoot.property(
        ARG_DESTINATION_FILE,
        SchemaBuilder.string(mapper)
            .description("Name of the destination program file (for create action)"));

    schemaRoot.requiredProperty(ARG_ACTION);

    // Conditional requirements based on action
    schemaRoot.allOf(
        // create requires session_name, source_file, destination_file
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(ARG_ACTION, SchemaBuilder.string(mapper).constValue(ACTION_CREATE)),
                SchemaBuilder.objectDraft7(mapper)
                    .requiredProperty(ARG_SESSION_NAME)
                    .requiredProperty(ARG_SOURCE_FILE)
                    .requiredProperty(ARG_DESTINATION_FILE)),
        // open requires session_name
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(ARG_ACTION, SchemaBuilder.string(mapper).constValue(ACTION_OPEN)),
                SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_SESSION_NAME)),
        // close requires session_name
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(ARG_ACTION, SchemaBuilder.string(mapper).constValue(ACTION_CLOSE)),
                SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_SESSION_NAME)),
        // info requires session_name
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(ARG_ACTION, SchemaBuilder.string(mapper).constValue(ACTION_INFO)),
                SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_SESSION_NAME)));

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
    return switch (normalizedAction) {
      case ACTION_CREATE ->
          withTaskMonitor("vt_sessions.create", monitor -> handleCreate(args, monitor));
      case ACTION_OPEN -> withTaskMonitor("vt_sessions.open", monitor -> handleOpen(args, monitor));
      case ACTION_LIST -> Mono.fromCallable(this::handleList);
      case ACTION_CLOSE ->
          withTaskMonitor("vt_sessions.close", monitor -> handleClose(args, monitor));
      case ACTION_INFO -> withTaskMonitor("vt_sessions.info", monitor -> handleInfo(args, monitor));
      default ->
          Mono.error(
              new GhidraMcpException(
                  GhidraMcpError.invalid(
                      ARG_ACTION,
                      action,
                      "must be one of: "
                          + ACTION_CREATE
                          + ", "
                          + ACTION_OPEN
                          + ", "
                          + ACTION_LIST
                          + ", "
                          + ACTION_CLOSE
                          + ", "
                          + ACTION_INFO)));
    };
  }

  /** Creates a VT session using reflection to avoid compile-time dependency on VTSessionDB. */
  private Object createVTSessionReflective(
      String sessionName, Program sourceProgram, Program destProgram) throws GhidraMcpException {
    try {
      Class<?> vtSessionDBClass = Class.forName("ghidra.feature.vt.api.db.VTSessionDB");

      try {
        Constructor<?> constructor =
            vtSessionDBClass.getConstructor(
                String.class, Program.class, Program.class, Object.class);
        return constructor.newInstance(sessionName, sourceProgram, destProgram, this);
      } catch (NoSuchMethodException noConstructor) {
        Method createMethod =
            vtSessionDBClass.getMethod(
                "createVTSession", String.class, Program.class, Program.class, Object.class);
        return createMethod.invoke(null, sessionName, sourceProgram, destProgram, this);
      }
    } catch (ClassNotFoundException e) {
      throw new GhidraMcpException(
          GhidraMcpError.execution()
              .message("VT session creation not available. Ensure DB.jar is in the lib folder.")
              .hint("Copy DB.jar from <GHIDRA_INSTALL>/Ghidra/Framework/DB/lib/DB.jar to lib/")
              .build());
    } catch (Exception e) {
      Throwable cause = e.getCause() != null ? e.getCause() : e;
      throw new GhidraMcpException(
          GhidraMcpError.execution()
              .errorCode(GhidraMcpError.ErrorCode.UNEXPECTED_ERROR)
              .message("Failed to create VT session: " + cause.getMessage())
              .build());
    }
  }

  private VTSessionInfo handleCreate(Map<String, Object> args, TaskMonitor monitor)
      throws GhidraMcpException {
    String sessionName = getRequiredStringArgument(args, ARG_SESSION_NAME);
    String sourceFile = getRequiredStringArgument(args, ARG_SOURCE_FILE);
    String destinationFile = getRequiredStringArgument(args, ARG_DESTINATION_FILE);

    Project project = getActiveProject();
    CreateTarget createTarget = resolveCreateTarget(project, sessionName);

    DomainFile existingFile = createTarget.folder().getFile(createTarget.fileName());
    if (existingFile != null) {
      throw new GhidraMcpException(
          GhidraMcpError.conflict(
              "VT session already exists at path: " + existingFile.getPathname()));
    }

    DomainFile sourceDomainFile =
        VTDomainFileResolver.resolveProgramFile(project, sourceFile, ARG_SOURCE_FILE);
    DomainFile destinationDomainFile =
        VTDomainFileResolver.resolveProgramFile(project, destinationFile, ARG_DESTINATION_FILE);

    if (sameDomainFilePath(sourceDomainFile, destinationDomainFile)) {
      throw new GhidraMcpException(
          GhidraMcpError.invalid(
              ARG_DESTINATION_FILE,
              destinationFile,
              "must reference a different program than source_file"));
    }

    Program sourceProgram = openProgram(sourceDomainFile, sourceFile, false, monitor);
    Program destProgram = openProgram(destinationDomainFile, destinationFile, true, monitor);

    try {
      // Create VT session using reflection
      Object session =
          createVTSessionReflective(createTarget.fileName(), sourceProgram, destProgram);

      try {
        // Save the session to the project
        DomainFile sessionFile =
            createTarget
                .folder()
                .createFile(createTarget.fileName(), (DomainObject) session, monitor);

        Msg.info(this, "Created VT session: " + sessionFile.getPathname());

        VTSessionInfo info = buildSessionInfo((VTSession) session);

        // Release the session
        Method releaseMethod = session.getClass().getMethod("release", Object.class);
        releaseMethod.invoke(session, this);

        return info;
      } catch (Exception e) {
        // Release the session on error
        try {
          Method releaseMethod = session.getClass().getMethod("release", Object.class);
          releaseMethod.invoke(session, this);
        } catch (Exception ignored) {
        }

        throw new GhidraMcpException(
            GhidraMcpError.execution()
                .errorCode(GhidraMcpError.ErrorCode.UNEXPECTED_ERROR)
                .message("Failed to save VT session: " + e.getMessage())
                .build());
      }
    } finally {
      // Release programs
      sourceProgram.release(this);
      destProgram.release(this);
    }
  }

  private VTSessionInfo handleOpen(Map<String, Object> args, TaskMonitor monitor)
      throws GhidraMcpException {
    String sessionName = getRequiredStringArgument(args, ARG_SESSION_NAME);
    return readSessionInfo(sessionName, monitor);
  }

  private List<String> handleList() throws GhidraMcpException {
    Project project = getActiveProject();
    List<String> sessionPaths = new ArrayList<>();
    List<DomainFile> allFiles = new ArrayList<>();
    GhidraStateUtils.collectFilesRecursive(project.getProjectData().getRootFolder(), allFiles);
    for (DomainFile file : allFiles) {
      String contentType = file.getContentType();
      if ((contentType != null && contentType.contains("VersionTracking"))
          || file.getName().endsWith(".vt")) {
        sessionPaths.add(file.getPathname());
      }
    }
    sessionPaths.sort(String.CASE_INSENSITIVE_ORDER);
    return sessionPaths;
  }

  private OperationResult handleClose(Map<String, Object> args, TaskMonitor monitor)
      throws GhidraMcpException {
    String sessionName = getRequiredStringArgument(args, ARG_SESSION_NAME);

    Project project = getActiveProject();
    DomainFile sessionFile =
        VTDomainFileResolver.resolveSessionFile(project, sessionName, ARG_SESSION_NAME);

    // Check if the session is currently open
    if (!sessionFile.isOpen()) {
      return OperationResult.success(
          ACTION_CLOSE, sessionFile.getPathname(), "Session was not open");
    }

    // Acquire and release one reference from this tool instance.
    DomainObject sessionObject = null;
    try {
      sessionObject = sessionFile.getDomainObject(this, false, false, monitor);
    } catch (Exception e) {
      throw new GhidraMcpException(
          GhidraMcpError.execution()
              .errorCode(GhidraMcpError.ErrorCode.UNEXPECTED_ERROR)
              .message("Failed to close session: " + e.getMessage())
              .build());
    } finally {
      if (sessionObject != null) {
        try {
          sessionObject.release(this);
        } catch (Exception ignored) {
        }
      }
    }

    if (sessionFile.isOpen()) {
      return closeResult(sessionFile.getPathname(), true);
    }

    return closeResult(sessionFile.getPathname(), false);
  }

  static OperationResult closeResult(String sessionName, boolean stillOpenByAnotherConsumer) {
    if (stillOpenByAnotherConsumer) {
      return OperationResult.success(
          ACTION_CLOSE,
          sessionName,
          "Released tool reference, but session remains open by another consumer");
    }
    return OperationResult.success(ACTION_CLOSE, sessionName, "Session closed successfully");
  }

  private VTSessionInfo handleInfo(Map<String, Object> args, TaskMonitor monitor)
      throws GhidraMcpException {
    String sessionName = getRequiredStringArgument(args, ARG_SESSION_NAME);
    return readSessionInfo(sessionName, monitor);
  }

  private VTSessionInfo readSessionInfo(String sessionName, TaskMonitor monitor)
      throws GhidraMcpException {
    return withSession(sessionName, false, monitor, this::buildSessionInfo);
  }

  private Program openProgram(
      DomainFile domainFile, String identifierForErrors, boolean forUpdate, TaskMonitor monitor)
      throws GhidraMcpException {
    try {
      DomainObject obj = domainFile.getDomainObject(this, forUpdate, false, monitor);
      if (obj instanceof Program) {
        return (Program) obj;
      }
      if (obj != null) {
        obj.release(this);
      }
      throw new GhidraMcpException(
          GhidraMcpError.validation()
              .errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
              .message("File '" + identifierForErrors + "' is not a Program")
              .build());
    } catch (GhidraMcpException e) {
      throw e;
    } catch (Exception e) {
      throw new GhidraMcpException(
          GhidraMcpError.execution()
              .errorCode(GhidraMcpError.ErrorCode.UNEXPECTED_ERROR)
              .message("Failed to open program '" + identifierForErrors + "': " + e.getMessage())
              .build());
    }
  }

  static boolean sameDomainFilePath(DomainFile first, DomainFile second) {
    return normalizeProjectPath(first.getPathname())
        .equals(normalizeProjectPath(second.getPathname()));
  }

  static String normalizeProjectPath(String path) {
    return VTDomainFileResolver.normalizeProjectPath(path);
  }

  private CreateTarget resolveCreateTarget(Project project, String sessionName)
      throws GhidraMcpException {
    String identifier = sessionName.trim();
    String normalized = identifier.replace('\\', '/');

    if (!normalized.contains("/")) {
      validateFileName(project, identifier, ARG_SESSION_NAME);
      return new CreateTarget(project.getProjectData().getRootFolder(), identifier);
    }

    if (!normalized.startsWith("/")) {
      throw new GhidraMcpException(
          GhidraMcpError.invalid(
              ARG_SESSION_NAME,
              sessionName,
              "path must be absolute (start with '/') when specifying a folder"));
    }
    if (normalized.endsWith("/")) {
      throw new GhidraMcpException(
          GhidraMcpError.invalid(
              ARG_SESSION_NAME,
              sessionName,
              "must include a session file name after the folder path"));
    }

    int lastSeparator = normalized.lastIndexOf('/');
    String folderPath = lastSeparator == 0 ? "/" : normalized.substring(0, lastSeparator);
    String fileName = normalized.substring(lastSeparator + 1);

    validateFileName(project, fileName, ARG_SESSION_NAME);

    DomainFolder folder = project.getProjectData().getFolder(folderPath);
    if (folder == null) {
      throw new GhidraMcpException(
          GhidraMcpError.notFound(
              "folder",
              folderPath,
              "Create the folder in Ghidra first or provide an existing folder path."));
    }

    return new CreateTarget(folder, fileName);
  }

  private void validateFileName(Project project, String fileName, String argumentName)
      throws GhidraMcpException {
    try {
      project.getProjectData().testValidName(fileName, false);
    } catch (InvalidNameException e) {
      throw new GhidraMcpException(
          GhidraMcpError.invalid(argumentName, fileName, "contains invalid characters"));
    }
  }

  private VTSessionInfo buildSessionInfo(VTSession session) {
    String name = session.getName();
    String sourceProgram = session.getSourceProgram().getName();
    String destProgram = session.getDestinationProgram().getName();

    int totalMatches = 0;
    int acceptedMatches = 0;
    int rejectedMatches = 0;
    int blockedMatches = 0;
    List<String> matchSetNames = new ArrayList<>();

    List<VTMatchSet> matchSets = session.getMatchSets();
    for (VTMatchSet matchSet : matchSets) {
      matchSetNames.add(matchSet.getProgramCorrelatorInfo().getName());
      Collection<VTMatch> matches = matchSet.getMatches();
      for (VTMatch match : matches) {
        totalMatches++;
        switch (match.getAssociation().getStatus()) {
          case ACCEPTED -> acceptedMatches++;
          case REJECTED -> rejectedMatches++;
          case BLOCKED -> blockedMatches++;
          default -> {} // AVAILABLE
        }
      }
    }

    // Markup count requires additional dependencies - set to 0 for now
    int appliedMarkupCount = 0;

    return new VTSessionInfo(
        name,
        sourceProgram,
        destProgram,
        totalMatches,
        acceptedMatches,
        rejectedMatches,
        blockedMatches,
        appliedMarkupCount,
        matchSetNames);
  }
}
