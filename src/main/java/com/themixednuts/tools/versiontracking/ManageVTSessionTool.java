package com.themixednuts.tools.versiontracking;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.models.OperationResult;
import com.themixednuts.models.versiontracking.VTSessionInfo;
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
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.common.McpTransportContext;
import reactor.core.publisher.Mono;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

@GhidraMcpTool(
    name = "Manage VT Session",
    description = "Create, open, close, list, and get info about Version Tracking sessions.",
    mcpName = "manage_vt_session",
    mcpDescription = """
        <use_case>
        Manage Version Tracking sessions which are used to compare different versions of programs
        and migrate analysis (functions, symbols, data types, comments) between them. Sessions
        store matches and markup state between source and destination programs.
        </use_case>

        <important_notes>
        - VT sessions require both source and destination programs to exist in the project
        - Sessions are stored as .vt files in the project
        - Creating a session does not automatically run correlators - use run_vt_correlator after
        - Close sessions when done to release resources
        - NOTE: Session creation requires DB.jar to be present in lib/
        </important_notes>

        <return_value_summary>
        - create/open/info: Returns VTSessionInfo with program names and match statistics
        - list: Returns list of available VT session names in the project
        - close: Returns OperationResult confirming closure
        </return_value_summary>
        """)
public class ManageVTSessionTool extends BaseMcpTool {

    public static final String ARG_SESSION_NAME = "session_name";
    public static final String ARG_SOURCE_FILE = "source_file";
    public static final String ARG_DESTINATION_FILE = "destination_file";

    private static final String ACTION_CREATE = "create";
    private static final String ACTION_OPEN = "open";
    private static final String ACTION_LIST = "list";
    private static final String ACTION_CLOSE = "close";
    private static final String ACTION_INFO = "info";

    @Override
    public JsonSchema schema() {
        var schemaRoot = createDraft7SchemaNode();

        schemaRoot.property(ARG_ACTION, SchemaBuilder.string(mapper)
                .enumValues(ACTION_CREATE, ACTION_OPEN, ACTION_LIST, ACTION_CLOSE, ACTION_INFO)
                .description("The VT session operation to perform"));

        schemaRoot.property(ARG_SESSION_NAME, SchemaBuilder.string(mapper)
                .description("Name of the VT session (used for create, open, close, info)"));

        schemaRoot.property(ARG_SOURCE_FILE, SchemaBuilder.string(mapper)
                .description("Name of the source program file (for create action)"));

        schemaRoot.property(ARG_DESTINATION_FILE, SchemaBuilder.string(mapper)
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
                                SchemaBuilder.objectDraft7(mapper)
                                        .requiredProperty(ARG_SESSION_NAME)),
                // close requires session_name
                SchemaBuilder.objectDraft7(mapper)
                        .ifThen(
                                SchemaBuilder.objectDraft7(mapper)
                                        .property(ARG_ACTION, SchemaBuilder.string(mapper).constValue(ACTION_CLOSE)),
                                SchemaBuilder.objectDraft7(mapper)
                                        .requiredProperty(ARG_SESSION_NAME)),
                // info requires session_name
                SchemaBuilder.objectDraft7(mapper)
                        .ifThen(
                                SchemaBuilder.objectDraft7(mapper)
                                        .property(ARG_ACTION, SchemaBuilder.string(mapper).constValue(ACTION_INFO)),
                                SchemaBuilder.objectDraft7(mapper)
                                        .requiredProperty(ARG_SESSION_NAME)));

        return schemaRoot.build();
    }

    @Override
    public Mono<? extends Object> execute(McpTransportContext context, Map<String, Object> args, PluginTool tool) {
        return Mono.fromCallable(() -> {
            String action = getRequiredStringArgument(args, ARG_ACTION);
            String normalizedAction = action.toLowerCase();

            return switch (normalizedAction) {
                case ACTION_CREATE -> handleCreate(args);
                case ACTION_OPEN -> handleOpen(args);
                case ACTION_LIST -> handleList();
                case ACTION_CLOSE -> handleClose(args);
                case ACTION_INFO -> handleInfo(args);
                default -> throw new GhidraMcpException(GhidraMcpError.invalid(ARG_ACTION, action,
                        "must be one of: " + ACTION_CREATE + ", " + ACTION_OPEN + ", " + ACTION_LIST + ", "
                        + ACTION_CLOSE + ", " + ACTION_INFO));
            };
        });
    }

    /**
     * Creates a VT session using reflection to avoid compile-time dependency on VTSessionDB.
     */
    private Object createVTSessionReflective(String sessionName, Program sourceProgram, Program destProgram)
            throws GhidraMcpException {
        try {
            Class<?> vtSessionDBClass = Class.forName("ghidra.feature.vt.api.db.VTSessionDB");
            Method createMethod = vtSessionDBClass.getMethod("createVTSession",
                    String.class, Program.class, Program.class, Object.class);
            return createMethod.invoke(null, sessionName, sourceProgram, destProgram, this);
        } catch (ClassNotFoundException e) {
            throw new GhidraMcpException(GhidraMcpError.execution()
                    .message("VT session creation not available. Ensure DB.jar is in the lib folder.")
                    .hint("Copy DB.jar from <GHIDRA_INSTALL>/Ghidra/Framework/DB/lib/DB.jar to lib/")
                    .build());
        } catch (Exception e) {
            Throwable cause = e.getCause() != null ? e.getCause() : e;
            throw new GhidraMcpException(GhidraMcpError.execution()
                    .errorCode(GhidraMcpError.ErrorCode.UNEXPECTED_ERROR)
                    .message("Failed to create VT session: " + cause.getMessage())
                    .build());
        }
    }

    private VTSessionInfo handleCreate(Map<String, Object> args) throws GhidraMcpException {
        String sessionName = getRequiredStringArgument(args, ARG_SESSION_NAME);
        String sourceFile = getRequiredStringArgument(args, ARG_SOURCE_FILE);
        String destinationFile = getRequiredStringArgument(args, ARG_DESTINATION_FILE);

        Project project = getActiveProject();
        DomainFolder rootFolder = project.getProjectData().getRootFolder();

        // Get source and destination programs
        Program sourceProgram = openProgram(project, sourceFile);
        Program destProgram = openProgram(project, destinationFile);

        try {
            // Create VT session using reflection
            Object session = createVTSessionReflective(sessionName, sourceProgram, destProgram);

            try {
                // Save the session to the project
                DomainFile sessionFile = rootFolder.createFile(
                        sessionName,
                        (DomainObject) session,
                        TaskMonitor.DUMMY);

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
                } catch (Exception ignored) {}

                throw new GhidraMcpException(GhidraMcpError.execution()
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

    private VTSessionInfo handleOpen(Map<String, Object> args) throws GhidraMcpException {
        String sessionName = getRequiredStringArgument(args, ARG_SESSION_NAME);
        VTSession session = openVTSession(sessionName);
        VTSessionInfo info = buildSessionInfo(session);
        return info;
    }

    private List<String> handleList() throws GhidraMcpException {
        Project project = getActiveProject();
        List<String> sessionNames = new ArrayList<>();
        collectVTSessions(project.getProjectData().getRootFolder(), sessionNames);
        return sessionNames;
    }

    private OperationResult handleClose(Map<String, Object> args) throws GhidraMcpException {
        String sessionName = getRequiredStringArgument(args, ARG_SESSION_NAME);

        Project project = getActiveProject();
        DomainFile sessionFile = findSessionFile(project, sessionName);

        if (sessionFile == null) {
            throw new GhidraMcpException(GhidraMcpError.notFound("VT session", sessionName));
        }

        // Check if the session is currently open
        if (!sessionFile.isOpen()) {
            return OperationResult.success(ACTION_CLOSE, sessionName, "Session was not open");
        }

        // Get and release the domain object to close it
        try {
            DomainObject obj = sessionFile.getDomainObject(this, false, false, TaskMonitor.DUMMY);
            if (obj != null) {
                obj.release(this);
            }
            return OperationResult.success(ACTION_CLOSE, sessionName, "Session closed successfully");
        } catch (Exception e) {
            throw new GhidraMcpException(GhidraMcpError.execution()
                    .errorCode(GhidraMcpError.ErrorCode.UNEXPECTED_ERROR)
                    .message("Failed to close session: " + e.getMessage())
                    .build());
        }
    }

    private VTSessionInfo handleInfo(Map<String, Object> args) throws GhidraMcpException {
        String sessionName = getRequiredStringArgument(args, ARG_SESSION_NAME);
        VTSession session = openVTSession(sessionName);
        return buildSessionInfo(session);
    }

    private Project getActiveProject() throws GhidraMcpException {
        Project project = AppInfo.getActiveProject();
        if (project == null) {
            throw new GhidraMcpException(GhidraMcpError.permissionState()
                    .errorCode(GhidraMcpError.ErrorCode.PROGRAM_NOT_OPEN)
                    .message("No active project found")
                    .build());
        }
        return project;
    }

    private Program openProgram(Project project, String fileName) throws GhidraMcpException {
        DomainFile domainFile = findProgramFile(project, fileName);
        if (domainFile == null) {
            throw new GhidraMcpException(GhidraMcpError.notFound("program", fileName));
        }

        try {
            DomainObject obj = domainFile.getDomainObject(this, true, false, TaskMonitor.DUMMY);
            if (obj instanceof Program) {
                return (Program) obj;
            }
            if (obj != null) {
                obj.release(this);
            }
            throw new GhidraMcpException(GhidraMcpError.validation()
                    .errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
                    .message("File '" + fileName + "' is not a Program")
                    .build());
        } catch (GhidraMcpException e) {
            throw e;
        } catch (Exception e) {
            throw new GhidraMcpException(GhidraMcpError.execution()
                    .errorCode(GhidraMcpError.ErrorCode.UNEXPECTED_ERROR)
                    .message("Failed to open program '" + fileName + "': " + e.getMessage())
                    .build());
        }
    }

    private VTSession openVTSession(String sessionName) throws GhidraMcpException {
        Project project = getActiveProject();
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
            throw new GhidraMcpException(GhidraMcpError.validation()
                    .errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
                    .message("File '" + sessionName + "' is not a VT session")
                    .build());
        } catch (GhidraMcpException e) {
            throw e;
        } catch (Exception e) {
            throw new GhidraMcpException(GhidraMcpError.execution()
                    .errorCode(GhidraMcpError.ErrorCode.UNEXPECTED_ERROR)
                    .message("Failed to open VT session '" + sessionName + "': " + e.getMessage())
                    .build());
        }
    }

    private DomainFile findProgramFile(Project project, String fileName) {
        return findDomainFileRecursive(project.getProjectData().getRootFolder(), fileName, "Program");
    }

    private DomainFile findSessionFile(Project project, String sessionName) {
        return findDomainFileRecursive(project.getProjectData().getRootFolder(), sessionName, null);
    }

    private DomainFile findDomainFileRecursive(DomainFolder folder, String name, String contentType) {
        for (DomainFile file : folder.getFiles()) {
            if (file.getName().equals(name)) {
                if (contentType == null || file.getContentType().contains(contentType)) {
                    return file;
                }
            }
        }
        for (DomainFolder subfolder : folder.getFolders()) {
            DomainFile found = findDomainFileRecursive(subfolder, name, contentType);
            if (found != null) {
                return found;
            }
        }
        return null;
    }

    private void collectVTSessions(DomainFolder folder, List<String> sessionNames) {
        for (DomainFile file : folder.getFiles()) {
            // VT sessions have content type containing "VersionTracking"
            if (file.getContentType().contains("VersionTracking") ||
                file.getName().endsWith(".vt")) {
                sessionNames.add(file.getName());
            }
        }
        for (DomainFolder subfolder : folder.getFolders()) {
            collectVTSessions(subfolder, sessionNames);
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
