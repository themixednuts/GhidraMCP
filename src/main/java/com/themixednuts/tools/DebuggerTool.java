package com.themixednuts.tools;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.models.OperationResult;
import com.themixednuts.ui.GhidraUiCoordinator;
import com.themixednuts.ui.NavigateDebuggerAddressEffect;
import com.themixednuts.ui.NavigateToAddressEffect;
import com.themixednuts.ui.ToolOutcome;
import com.themixednuts.utils.CursorDataResult;
import com.themixednuts.utils.GhidraMcpErrorUtils;
import com.themixednuts.utils.OpaqueCursorCodec;
import com.themixednuts.utils.TypedMemoryMapper;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.draft7.SchemaBuilder;
import ghidra.app.services.DebuggerControlService;
import ghidra.app.services.DebuggerEmulationService;
import ghidra.app.services.DebuggerListingService;
import ghidra.app.services.DebuggerLogicalBreakpointService;
import ghidra.app.services.DebuggerPlatformService;
import ghidra.app.services.DebuggerStaticMappingService;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.app.services.DebuggerWatchesService;
import ghidra.app.services.TraceRmiLauncherService;
import ghidra.app.services.TraceRmiService;
import ghidra.debug.api.ValStr;
import ghidra.debug.api.action.LocationTrackingSpec;
import ghidra.debug.api.action.LocationTrackingSpecFactory;
import ghidra.debug.api.breakpoint.LogicalBreakpoint;
import ghidra.debug.api.control.ControlMode;
import ghidra.debug.api.emulation.EmulatorFactory;
import ghidra.debug.api.modules.MapEntry;
import ghidra.debug.api.modules.ModuleMapProposal;
import ghidra.debug.api.modules.RegionMapProposal;
import ghidra.debug.api.modules.SectionMapProposal;
import ghidra.debug.api.platform.DebuggerPlatformMapper;
import ghidra.debug.api.target.ActionName;
import ghidra.debug.api.target.Target;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.debug.api.tracermi.LaunchParameter;
import ghidra.debug.api.tracermi.RemoteMethod;
import ghidra.debug.api.tracermi.RemoteParameter;
import ghidra.debug.api.tracermi.TraceRmiAcceptor;
import ghidra.debug.api.tracermi.TraceRmiConnection;
import ghidra.debug.api.tracermi.TraceRmiLaunchOffer;
import ghidra.debug.api.watch.WatchRow;
import ghidra.framework.model.DomainFile;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.trace.model.DefaultTraceLocation;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.Trace;
import ghidra.trace.model.TraceExecutionState;
import ghidra.trace.model.TraceLocation;
import ghidra.trace.model.breakpoint.TraceBreakpointKind;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.memory.TraceMemoryFlag;
import ghidra.trace.model.memory.TraceMemoryRegion;
import ghidra.trace.model.memory.TraceMemorySpace;
import ghidra.trace.model.memory.TraceMemoryState;
import ghidra.trace.model.modules.TraceModule;
import ghidra.trace.model.modules.TraceSection;
import ghidra.trace.model.program.TraceProgramView;
import ghidra.trace.model.stack.TraceStack;
import ghidra.trace.model.stack.TraceStackFrame;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.target.TraceObjectValue;
import ghidra.trace.model.target.path.KeyPath;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.time.TraceSnapshot;
import ghidra.trace.model.time.schedule.Scheduler;
import ghidra.trace.model.time.schedule.TraceSchedule;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.common.McpTransportContext;
import java.io.IOException;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import java.util.stream.Collectors;
import reactor.core.publisher.Mono;

@GhidraMcpTool(
    name = "Debugger",
    description =
        "Debugger lifecycle, live target control, trace memory/model inspection, mappings,"
            + " registers, watches, remote methods, emulation, and UI navigation.",
    mcpName = "debugger",
    mcpDescription =
        """
        <use_case>
        Connect, launch, control, and inspect Ghidra debugger sessions. Use this tool when you need
        to start/accept/connect Trace RMI, launch a debugger from a static Program, activate traces
        or targets, inspect threads/stack/snapshots/objects, map a running module/section/region
        back to a static Program, resume/interrupt/step, execute debugger console commands, manage
        breakpoints/watchpoints, inspect/update registers and watches, read/write live target
        memory, manage trace-backed bytes/states, map trace bytes to data types, invoke Trace RMI
        remote methods, run debugger emulation, or navigate/select in the Debugger listing.
        </use_case>

        <important_notes>
        - Connection/launch actions require Ghidra's Trace RMI services.
        - Control actions require Ghidra's Debugger services and an active trace/target.
        - status reports open traces plus the current target, thread, snap, frame, control mode,
          and execution state when available.
        - list_launchers/launch wrap Ghidra Trace RMI launcher offers for a static Program.
        - apply_mapping supports mapping_kind=module, section, region, address, and identity.
          module is the normal "running executable -> analyzed program" bridge; section/region
          are better when module-wide scoring is ambiguous.
        - map_dynamic_to_static and map_static_to_dynamic resolve existing static mappings.
        - read_memory refreshes from the live target by default when a target is selected, then
          reads trace-backed bytes. read_trace_bytes skips the live target and only reads the trace.
        - write_memory writes the live target. write_trace_bytes writes cached trace bytes only.
        - execute sends a raw command to the current target; prefer structured actions like
          resume, interrupt, detach, kill, read_memory, and write_memory when they express the
          operation.
        - Breakpoint actions use the current trace and accept breakpoint_kinds values:
          sw_execute, hw_execute, read, write, access. Defaults to sw_execute; access expands to
          read+write because those are Ghidra's concrete trace breakpoint kinds.
        - list_remote_methods/invoke_remote_method expose backend-specific Trace RMI methods. Use
          them when a debugger adapter supports an action that does not yet have a structured MCP
          wrapper.
        - list_threads/list_stack/list_snapshots/list_objects/get_object are cursor-paged trace
          model views for discovering coordinates before activation.
        - Emulation actions use Ghidra's DebuggerEmulationService and operate on trace schedules.
        - map_data_type applies the selected data type in the current trace view and returns a
          bounded field/byte mapping. Use next_cursor/cursor to continue large mappings.
        - read_registers refreshes from the live target when possible before reading trace-backed
          register values. list_registers/read_registers are cursor-paged.
        - Watch actions use Ghidra's Debugger watch service and update the visible Watches UI.
        - go_to_address navigates the active Debugger listing. select_range updates the visible
          Debugger listing selection. Address-affecting actions return UI effects so the visible
          Ghidra UI follows successful MCP calls when the service is available.
        </important_notes>

        <return_value_summary>
        - status: map with current debugger coordinates and target state.
        - connection/launch/lifecycle actions: Trace RMI server, connection, target, trace, or
          launcher metadata.
        - list_* discovery actions: bounded rows and optional next_cursor.
        - mapping actions: proposal/application metadata or translated dynamic/static addresses.
        - execute/control actions: map or OperationResult describing the completed target action.
        - list_breakpoints: list of logical breakpoints in the current trace.
        - breakpoint mutations: OperationResult with affected address/count metadata.
        - memory actions: hex_data/ascii/state rows or OperationResult for writes/cache changes.
        - map_data_type: typed bytes plus bounded field rows and optional next_cursor.
        - register/watch/object/remote/emulation actions: bounded rows or structured metadata.
        </return_value_summary>
        """,
    readOnlyHint = false)
public class DebuggerTool extends BaseMcpTool {

  private static final String ACTION_STATUS = "status";
  private static final String ACTION_EXECUTE = "execute";
  private static final String ACTION_RESUME = "resume";
  private static final String ACTION_INTERRUPT = "interrupt";
  private static final String ACTION_STEP_INTO = "step_into";
  private static final String ACTION_STEP_OVER = "step_over";
  private static final String ACTION_STEP_OUT = "step_out";
  private static final String ACTION_STEP_SKIP = "step_skip";
  private static final String ACTION_STEP_BACK = "step_back";
  private static final String ACTION_ATTACH = "attach";
  private static final String ACTION_DETACH = "detach";
  private static final String ACTION_KILL = "kill";
  private static final String ACTION_DISCONNECT = "disconnect";
  private static final String ACTION_CLOSE_CONNECTION = "close_connection";
  private static final String ACTION_CLOSE_TRACE = "close_trace";
  private static final String ACTION_SAVE_TRACE = "save_trace";
  private static final String ACTION_CLOSE_DEAD_TRACES = "close_dead_traces";
  private static final String ACTION_GET_CONTROL_MODE = "get_control_mode";
  private static final String ACTION_SET_CONTROL_MODE = "set_control_mode";
  private static final String ACTION_SET_BREAKPOINT = "set_breakpoint";
  private static final String ACTION_SET_STATIC_BREAKPOINT = "set_static_breakpoint";
  private static final String ACTION_SET_WATCHPOINT = "set_watchpoint";
  private static final String ACTION_LIST_SUPPORTED_BREAKPOINT_KINDS =
      "list_supported_breakpoint_kinds";
  private static final String ACTION_LIST_BREAKPOINTS = "list_breakpoints";
  private static final String ACTION_ENABLE_BREAKPOINT = "enable_breakpoint";
  private static final String ACTION_DISABLE_BREAKPOINT = "disable_breakpoint";
  private static final String ACTION_DELETE_BREAKPOINT = "delete_breakpoint";
  private static final String ACTION_GO_TO_ADDRESS = "go_to_address";
  private static final String ACTION_READ_MEMORY = "read_memory";
  private static final String ACTION_REFRESH_MEMORY = "refresh_memory";
  private static final String ACTION_WRITE_MEMORY = "write_memory";
  private static final String ACTION_INVALIDATE_MEMORY_CACHE = "invalidate_memory_cache";
  private static final String ACTION_READ_TRACE_BYTES = "read_trace_bytes";
  private static final String ACTION_WRITE_TRACE_BYTES = "write_trace_bytes";
  private static final String ACTION_GET_MEMORY_STATE = "get_memory_state";
  private static final String ACTION_SET_MEMORY_STATE = "set_memory_state";
  private static final String ACTION_LIST_MEMORY_REGIONS = "list_memory_regions";
  private static final String ACTION_SELECT_RANGE = "select_range";
  private static final String ACTION_LIST_TRACKING_SPECS = "list_tracking_specs";
  private static final String ACTION_SET_TRACKING_SPEC = "set_tracking_spec";
  private static final String ACTION_MAP_DATA_TYPE = "map_data_type";
  private static final String ACTION_LIST_REGISTERS = "list_registers";
  private static final String ACTION_READ_REGISTERS = "read_registers";
  private static final String ACTION_WRITE_REGISTER = "write_register";
  private static final String ACTION_LIST_WATCHES = "list_watches";
  private static final String ACTION_ADD_WATCH = "add_watch";
  private static final String ACTION_UPDATE_WATCH = "update_watch";
  private static final String ACTION_REMOVE_WATCH = "remove_watch";
  private static final String ACTION_START_SERVER = "start_server";
  private static final String ACTION_STOP_SERVER = "stop_server";
  private static final String ACTION_CONNECT = "connect";
  private static final String ACTION_ACCEPT = "accept";
  private static final String ACTION_LIST_CONNECTIONS = "list_connections";
  private static final String ACTION_LIST_LAUNCHERS = "list_launchers";
  private static final String ACTION_LAUNCH = "launch";
  private static final String ACTION_LIST_TRACES = "list_traces";
  private static final String ACTION_LIST_TARGETS = "list_targets";
  private static final String ACTION_ACTIVATE_TRACE = "activate_trace";
  private static final String ACTION_ACTIVATE_TARGET = "activate_target";
  private static final String ACTION_ACTIVATE_THREAD = "activate_thread";
  private static final String ACTION_ACTIVATE_OBJECT = "activate_object";
  private static final String ACTION_ACTIVATE_TIME = "activate_time";
  private static final String ACTION_ACTIVATE_PLATFORM = "activate_platform";
  private static final String ACTION_ACTIVATE_SNAP = "activate_snap";
  private static final String ACTION_ACTIVATE_FRAME = "activate_frame";
  private static final String ACTION_LIST_THREADS = "list_threads";
  private static final String ACTION_LIST_STACK = "list_stack";
  private static final String ACTION_LIST_SNAPSHOTS = "list_snapshots";
  private static final String ACTION_LIST_OBJECTS = "list_objects";
  private static final String ACTION_GET_OBJECT = "get_object";
  private static final String ACTION_LIST_MODULES = "list_modules";
  private static final String ACTION_LIST_SECTIONS = "list_sections";
  private static final String ACTION_PROPOSE_MAPPING = "propose_mapping";
  private static final String ACTION_APPLY_MAPPING = "apply_mapping";
  private static final String ACTION_ADD_IDENTITY_MAPPING = "add_identity_mapping";
  private static final String ACTION_MAP_DYNAMIC_TO_STATIC = "map_dynamic_to_static";
  private static final String ACTION_MAP_STATIC_TO_DYNAMIC = "map_static_to_dynamic";
  private static final String ACTION_FIND_BEST_MODULE_PROGRAM = "find_best_module_program";
  private static final String ACTION_OPEN_MAPPED_PROGRAMS = "open_mapped_programs";
  private static final String ACTION_LIST_MAPPED_VIEWS = "list_mapped_views";
  private static final String ACTION_LIST_PLATFORMS = "list_platforms";
  private static final String ACTION_GET_PLATFORM_MAPPER = "get_platform_mapper";
  private static final String ACTION_SET_PLATFORM_MAPPER = "set_platform_mapper";
  private static final String ACTION_LIST_REMOTE_METHODS = "list_remote_methods";
  private static final String ACTION_INVOKE_REMOTE_METHOD = "invoke_remote_method";
  private static final String ACTION_LIST_EMULATOR_FACTORIES = "list_emulator_factories";
  private static final String ACTION_SET_EMULATOR_FACTORY = "set_emulator_factory";
  private static final String ACTION_LAUNCH_EMULATOR = "launch_emulator";
  private static final String ACTION_EMULATE = "emulate";
  private static final String ACTION_RUN_EMULATION = "run_emulation";
  private static final String ACTION_LIST_BUSY_EMULATORS = "list_busy_emulators";
  private static final String ACTION_INVALIDATE_EMULATOR_CACHE = "invalidate_emulator_cache";

  private static final String ARG_COMMAND = "command";
  private static final String ARG_CAPTURE = "capture";
  private static final String ARG_TIMEOUT_MS = "timeout_ms";
  private static final String ARG_HOST = "host";
  private static final String ARG_PORT = "port";
  private static final String ARG_WAIT = "wait";
  private static final String ARG_FILE_NAME = "file_name";
  private static final String ARG_BREAKPOINT_KINDS = "breakpoint_kinds";
  private static final String ARG_LENGTH = "length";
  private static final String ARG_BYTES_HEX = "bytes_hex";
  private static final String ARG_ADDRESS_END = "address_end";
  private static final String ARG_MEMORY_STATE = "memory_state";
  private static final String ARG_NAME = "name";
  private static final String ARG_MAX_FIELDS = "max_fields";
  private static final String ARG_MAX_VALUES = "max_values";
  private static final String ARG_LAUNCHER_INDEX = "launcher_index";
  private static final String ARG_LAUNCHER_NAME = "launcher_name";
  private static final String ARG_LAUNCH_ARGUMENTS = "launch_arguments";
  private static final String ARG_CONNECTION_INDEX = "connection_index";
  private static final String ARG_TRACE_INDEX = "trace_index";
  private static final String ARG_TRACE_NAME = "trace_name";
  private static final String ARG_TARGET_INDEX = "target_index";
  private static final String ARG_THREAD_KEY = "thread_key";
  private static final String ARG_THREAD_PATH = "thread_path";
  private static final String ARG_OBJECT_PATH = "object_path";
  private static final String ARG_TIME = "time";
  private static final String ARG_PLATFORM_INDEX = "platform_index";
  private static final String ARG_SNAP = "snap";
  private static final String ARG_FRAME = "frame";
  private static final String ARG_MODULE_NAME = "module_name";
  private static final String ARG_MODULE_PATH = "module_path";
  private static final String ARG_SECTION_NAME = "section_name";
  private static final String ARG_SECTION_PATH = "section_path";
  private static final String ARG_REGION_NAME = "region_name";
  private static final String ARG_REGION_PATH = "region_path";
  private static final String ARG_MAPPING_KIND = "mapping_kind";
  private static final String ARG_STATIC_ADDRESS = "static_address";
  private static final String ARG_TRUNCATE_EXISTING = "truncate_existing";
  private static final String ARG_MEMORIZE = "memorize";
  private static final String ARG_CONTROL_MODE = "control_mode";
  private static final String ARG_REGISTER_NAME = "register_name";
  private static final String ARG_REGISTER_NAMES = "register_names";
  private static final String ARG_VALUE = "value";
  private static final String ARG_REFRESH = "refresh";
  private static final String ARG_INCLUDE_ALL = "include_all";
  private static final String ARG_INCLUDE_HIDDEN = "include_hidden";
  private static final String ARG_MAX_REGISTERS = "max_registers";
  private static final String ARG_MAX_WATCHES = "max_watches";
  private static final String ARG_EXPRESSION = "expression";
  private static final String ARG_WATCH_INDEX = "watch_index";
  private static final String ARG_COMMENT = "comment";
  private static final String ARG_METHOD_NAME = "method_name";
  private static final String ARG_METHOD_ARGUMENTS = "method_arguments";
  private static final String ARG_TRACKING_SPEC = "tracking_spec";
  private static final String ARG_EMULATOR_INDEX = "emulator_index";
  private static final String ARG_EMULATOR_NAME = "emulator_name";

  private static final int DEFAULT_TIMEOUT_MS = 10_000;
  private static final int DEFAULT_MAX_FIELDS = 256;
  private static final int MAX_FIELDS_LIMIT = 4096;
  private static final int DEFAULT_MAX_REGISTERS = 128;
  private static final int MAX_REGISTERS_LIMIT = 4096;
  private static final int DEFAULT_MAX_WATCHES = 128;
  private static final int MAX_WATCHES_LIMIT = 4096;
  private static final int DEFAULT_PAGE_SIZE = 128;
  private static final int MAX_PAGE_SIZE = 4096;
  private static final int MAX_MEMORY_LENGTH = 1_048_576;

  @Override
  public JsonSchema schema() {
    var schemaRoot = createDraft7SchemaNode();

    schemaRoot.property(
        ARG_ACTION,
        SchemaBuilder.string(mapper)
            .description("Debugger action to perform.")
            .enumValues(
                ACTION_STATUS,
                ACTION_EXECUTE,
                ACTION_RESUME,
                ACTION_INTERRUPT,
                ACTION_STEP_INTO,
                ACTION_STEP_OVER,
                ACTION_STEP_OUT,
                ACTION_STEP_SKIP,
                ACTION_STEP_BACK,
                ACTION_ATTACH,
                ACTION_DETACH,
                ACTION_KILL,
                ACTION_DISCONNECT,
                ACTION_CLOSE_CONNECTION,
                ACTION_CLOSE_TRACE,
                ACTION_SAVE_TRACE,
                ACTION_CLOSE_DEAD_TRACES,
                ACTION_GET_CONTROL_MODE,
                ACTION_SET_CONTROL_MODE,
                ACTION_SET_BREAKPOINT,
                ACTION_SET_STATIC_BREAKPOINT,
                ACTION_SET_WATCHPOINT,
                ACTION_LIST_SUPPORTED_BREAKPOINT_KINDS,
                ACTION_LIST_BREAKPOINTS,
                ACTION_ENABLE_BREAKPOINT,
                ACTION_DISABLE_BREAKPOINT,
                ACTION_DELETE_BREAKPOINT,
                ACTION_GO_TO_ADDRESS,
                ACTION_READ_MEMORY,
                ACTION_REFRESH_MEMORY,
                ACTION_WRITE_MEMORY,
                ACTION_INVALIDATE_MEMORY_CACHE,
                ACTION_READ_TRACE_BYTES,
                ACTION_WRITE_TRACE_BYTES,
                ACTION_GET_MEMORY_STATE,
                ACTION_SET_MEMORY_STATE,
                ACTION_LIST_MEMORY_REGIONS,
                ACTION_SELECT_RANGE,
                ACTION_LIST_TRACKING_SPECS,
                ACTION_SET_TRACKING_SPEC,
                ACTION_MAP_DATA_TYPE,
                ACTION_LIST_REGISTERS,
                ACTION_READ_REGISTERS,
                ACTION_WRITE_REGISTER,
                ACTION_LIST_WATCHES,
                ACTION_ADD_WATCH,
                ACTION_UPDATE_WATCH,
                ACTION_REMOVE_WATCH,
                ACTION_START_SERVER,
                ACTION_STOP_SERVER,
                ACTION_CONNECT,
                ACTION_ACCEPT,
                ACTION_LIST_CONNECTIONS,
                ACTION_LIST_LAUNCHERS,
                ACTION_LAUNCH,
                ACTION_LIST_TRACES,
                ACTION_LIST_TARGETS,
                ACTION_ACTIVATE_TRACE,
                ACTION_ACTIVATE_TARGET,
                ACTION_ACTIVATE_THREAD,
                ACTION_ACTIVATE_OBJECT,
                ACTION_ACTIVATE_TIME,
                ACTION_ACTIVATE_PLATFORM,
                ACTION_ACTIVATE_SNAP,
                ACTION_ACTIVATE_FRAME,
                ACTION_LIST_THREADS,
                ACTION_LIST_STACK,
                ACTION_LIST_SNAPSHOTS,
                ACTION_LIST_OBJECTS,
                ACTION_GET_OBJECT,
                ACTION_LIST_MODULES,
                ACTION_LIST_SECTIONS,
                ACTION_PROPOSE_MAPPING,
                ACTION_APPLY_MAPPING,
                ACTION_ADD_IDENTITY_MAPPING,
                ACTION_MAP_DYNAMIC_TO_STATIC,
                ACTION_MAP_STATIC_TO_DYNAMIC,
                ACTION_FIND_BEST_MODULE_PROGRAM,
                ACTION_OPEN_MAPPED_PROGRAMS,
                ACTION_LIST_MAPPED_VIEWS,
                ACTION_LIST_PLATFORMS,
                ACTION_GET_PLATFORM_MAPPER,
                ACTION_SET_PLATFORM_MAPPER,
                ACTION_LIST_REMOTE_METHODS,
                ACTION_INVOKE_REMOTE_METHOD,
                ACTION_LIST_EMULATOR_FACTORIES,
                ACTION_SET_EMULATOR_FACTORY,
                ACTION_LAUNCH_EMULATOR,
                ACTION_EMULATE,
                ACTION_RUN_EMULATION,
                ACTION_LIST_BUSY_EMULATORS,
                ACTION_INVALIDATE_EMULATOR_CACHE));

    schemaRoot.property(
        ARG_FILE_NAME,
        SchemaBuilder.string(mapper)
            .description("Static program file name for launcher and static mapping actions."));
    schemaRoot.property(
        ARG_COMMAND,
        SchemaBuilder.string(mapper)
            .description("Raw debugger command for action=execute, sent to the current target."));
    schemaRoot.property(
        ARG_CAPTURE,
        SchemaBuilder.bool(mapper)
            .description("Whether action=execute should capture command output. Default: true.")
            .defaultValue(true));
    schemaRoot.property(
        ARG_HOST,
        SchemaBuilder.string(mapper)
            .description("Trace RMI host for connect/accept/start_server. Default: 127.0.0.1."));
    schemaRoot.property(
        ARG_PORT,
        SchemaBuilder.integer(mapper)
            .description("Trace RMI TCP port for connect/accept/start_server.")
            .minimum(0)
            .maximum(65535));
    schemaRoot.property(
        ARG_WAIT,
        SchemaBuilder.bool(mapper)
            .description("For accept, wait for one inbound debugger connection before returning."));
    schemaRoot.property(
        ARG_ADDRESS,
        SchemaBuilder.string(mapper)
            .description(
                "Trace/view address for memory, breakpoint, debugger navigation, and dynamic"
                    + " mapping actions. Supports normal and image-base-relative address syntax."));
    schemaRoot.property(
        ARG_ADDRESS_END,
        SchemaBuilder.string(mapper)
            .description(
                "Optional inclusive end address for debugger range selection and mapped-view"
                    + " queries. Supports normal and image-base-relative syntax."));
    schemaRoot.property(
        ARG_STATIC_ADDRESS,
        SchemaBuilder.string(mapper)
            .description(
                "Static program address for apply_mapping/map_static_to_dynamic. Supports normal"
                    + " and image-base-relative address syntax in the static program."));
    schemaRoot.property(
        ARG_DATA_TYPE_PATH,
        SchemaBuilder.string(mapper)
            .description(
                "Data type path for map_data_type and watch data type updates, e.g. '/MyStruct',"
                    + " 'int', or 'char[16]'."));
    schemaRoot.property(
        ARG_DATA_TYPE_ID,
        SchemaBuilder.integer(mapper)
            .description("Data type ID as an alternative to data_type_path."));
    schemaRoot.property(
        ARG_MAX_FIELDS,
        SchemaBuilder.integer(mapper)
            .description(
                "map_data_type: maximum typed fields/components to return (default: 256, max:"
                    + " 4096). Use next_cursor/cursor to continue.")
            .minimum(1)
            .maximum(MAX_FIELDS_LIMIT));
    schemaRoot.property(
        ARG_LENGTH,
        SchemaBuilder.integer(mapper)
            .description(
                "Length in bytes for memory, range, and breakpoint actions. Default: 1 for"
                    + " breakpoints. Memory actions require an explicit length. Max: "
                    + MAX_MEMORY_LENGTH
                    + ".")
            .minimum(1)
            .maximum(MAX_MEMORY_LENGTH)
            .defaultValue(1));
    schemaRoot.property(
        ARG_BYTES_HEX,
        SchemaBuilder.string(mapper)
            .description(
                "Hex bytes for write_memory/write_trace_bytes, e.g. '4889e5' or '48 89 e5'."));
    schemaRoot.property(
        ARG_MEMORY_STATE,
        SchemaBuilder.string(mapper)
            .description("Trace memory state for set_memory_state: unknown, known, or error.")
            .enumValues("unknown", "known", "error"));
    schemaRoot.property(
        ARG_BREAKPOINT_KINDS,
        SchemaBuilder.array(mapper)
            .description(
                "Breakpoint kinds: sw_execute, hw_execute, read, write, access. Default:"
                    + " sw_execute. access expands to read+write.")
            .items(SchemaBuilder.string(mapper)));
    schemaRoot.property(
        ARG_NAME, SchemaBuilder.string(mapper).description("Optional breakpoint name/comment."));
    schemaRoot.property(
        ARG_TIMEOUT_MS,
        SchemaBuilder.integer(mapper)
            .description("Timeout for target actions and futures in milliseconds. Default: 10000.")
            .minimum(1)
            .defaultValue(DEFAULT_TIMEOUT_MS));
    schemaRoot.property(
        ARG_LAUNCHER_INDEX,
        SchemaBuilder.integer(mapper)
            .description("Zero-based launcher index from list_launchers.")
            .minimum(0));
    schemaRoot.property(
        ARG_LAUNCHER_NAME,
        SchemaBuilder.string(mapper)
            .description("Launcher config name or title from list_launchers."));
    schemaRoot.property(
        ARG_LAUNCH_ARGUMENTS,
        SchemaBuilder.objectDraft7(mapper)
            .description(
                "Launcher parameter values keyed by parameter name. Values are decoded using the"
                    + " launcher parameter decoder."));
    schemaRoot.property(
        ARG_CONNECTION_INDEX,
        SchemaBuilder.integer(mapper)
            .description("Zero-based Trace RMI connection index from list_connections.")
            .minimum(0));
    schemaRoot.property(
        ARG_TRACE_INDEX,
        SchemaBuilder.integer(mapper)
            .description("Zero-based trace index from list_traces/status open_traces.")
            .minimum(0));
    schemaRoot.property(
        ARG_TRACE_NAME, SchemaBuilder.string(mapper).description("Trace name for activate_trace."));
    schemaRoot.property(
        ARG_TARGET_INDEX,
        SchemaBuilder.integer(mapper)
            .description("Zero-based target index from list_targets.")
            .minimum(0));
    schemaRoot.property(
        ARG_THREAD_KEY,
        SchemaBuilder.integer(mapper).description("Trace thread key for activate_thread."));
    schemaRoot.property(
        ARG_THREAD_PATH,
        SchemaBuilder.string(mapper).description("Trace thread path for activate_thread."));
    schemaRoot.property(
        ARG_OBJECT_PATH,
        SchemaBuilder.string(mapper)
            .description(
                "Canonical trace object path for get_object/activate_object/platform mapper and"
                    + " remote method object arguments, e.g. 'Processes[1].Threads[2]'."));
    schemaRoot.property(
        ARG_TIME,
        SchemaBuilder.string(mapper)
            .description(
                "Trace schedule string for activate_time/emulation. Defaults to current debugger"
                    + " coordinates when omitted."));
    schemaRoot.property(
        ARG_PLATFORM_INDEX,
        SchemaBuilder.integer(mapper)
            .description("Zero-based platform index from list_platforms.")
            .minimum(0));
    schemaRoot.property(
        ARG_SNAP,
        SchemaBuilder.integer(mapper)
            .description("Trace snap for activation and mapping. Defaults to current snap."));
    schemaRoot.property(
        ARG_FRAME,
        SchemaBuilder.integer(mapper)
            .description("Stack frame index for activate_frame and register actions.")
            .minimum(0));
    schemaRoot.property(
        ARG_MODULE_NAME,
        SchemaBuilder.string(mapper)
            .description("Loaded trace module name for module mapping actions."));
    schemaRoot.property(
        ARG_MODULE_PATH,
        SchemaBuilder.string(mapper)
            .description("Loaded trace module path for module mapping actions."));
    schemaRoot.property(
        ARG_SECTION_NAME,
        SchemaBuilder.string(mapper).description("Loaded trace section name for section mapping."));
    schemaRoot.property(
        ARG_SECTION_PATH,
        SchemaBuilder.string(mapper).description("Loaded trace section path for section mapping."));
    schemaRoot.property(
        ARG_REGION_NAME,
        SchemaBuilder.string(mapper).description("Live memory region name for region mapping."));
    schemaRoot.property(
        ARG_REGION_PATH,
        SchemaBuilder.string(mapper).description("Live memory region path for region mapping."));
    schemaRoot.property(
        ARG_MAPPING_KIND,
        SchemaBuilder.string(mapper)
            .description("Mapping mode for propose_mapping/apply_mapping.")
            .enumValues("module", "section", "region", "address", "identity"));
    schemaRoot.property(
        ARG_TRUNCATE_EXISTING,
        SchemaBuilder.bool(mapper)
            .description("Whether static mapping additions may truncate conflicting mappings.")
            .defaultValue(false));
    schemaRoot.property(
        ARG_MEMORIZE,
        SchemaBuilder.bool(mapper)
            .description("For module proposals, memorize the accepted module-program association.")
            .defaultValue(false));
    schemaRoot.property(
        ARG_CONTROL_MODE,
        SchemaBuilder.string(mapper)
            .description(
                "Debugger control mode: ro_target, rw_target, ro_trace, rw_trace, rw_emulator.")
            .enumValues("ro_target", "rw_target", "ro_trace", "rw_trace", "rw_emulator"));
    schemaRoot.property(
        ARG_REGISTER_NAME,
        SchemaBuilder.string(mapper).description("Single register name for write_register."));
    schemaRoot.property(
        ARG_REGISTER_NAMES,
        SchemaBuilder.array(mapper)
            .description("Optional register names for read_registers.")
            .items(SchemaBuilder.string(mapper)));
    schemaRoot.property(
        ARG_NAME_PATTERN,
        SchemaBuilder.string(mapper)
            .description(
                "Optional regex filter for list_registers/read_registers register names."));
    schemaRoot.property(
        ARG_VALUE,
        SchemaBuilder.string(mapper)
            .description(
                "Value for write_register as decimal or 0x-prefixed hex, or update_watch value"
                    + " text."));
    schemaRoot.property(
        ARG_REFRESH,
        SchemaBuilder.bool(mapper)
            .description(
                "For read_registers/read_memory, ask the live target to refresh values before"
                    + " reading trace-backed state when possible. Default: true when a live target"
                    + " is selected."));
    schemaRoot.property(
        ARG_INCLUDE_ALL,
        SchemaBuilder.bool(mapper)
            .description(
                "Include non-live historical rows where supported, e.g. all threads instead of"
                    + " only live threads at the active snap."));
    schemaRoot.property(
        ARG_INCLUDE_HIDDEN,
        SchemaBuilder.bool(mapper)
            .description("Include hidden/context registers in list_registers/read_registers."));
    schemaRoot.property(
        ARG_MAX_REGISTERS,
        SchemaBuilder.integer(mapper)
            .description("Maximum register rows to return (default: 128, max: 4096).")
            .minimum(1)
            .maximum(MAX_REGISTERS_LIMIT));
    schemaRoot.property(
        ARG_MAX_WATCHES,
        SchemaBuilder.integer(mapper)
            .description("Maximum watch rows to return (default: 128, max: 4096).")
            .minimum(1)
            .maximum(MAX_WATCHES_LIMIT));
    schemaRoot.property(
        ARG_MAX_VALUES,
        SchemaBuilder.integer(mapper)
            .description(
                "Maximum trace object values to return for get_object (default 128, max 4096).")
            .minimum(1)
            .maximum(MAX_PAGE_SIZE));
    schemaRoot.property(
        ARG_PAGE_SIZE,
        SchemaBuilder.integer(mapper)
            .description(
                "Maximum rows for list_launchers, list_traces, list_targets, and list_modules.")
            .minimum(1)
            .maximum(MAX_PAGE_SIZE));
    schemaRoot.property(
        ARG_CURSOR,
        SchemaBuilder.string(mapper)
            .description(
                "Opaque cursor copied from previous map_data_type/list_registers/read_registers/"
                    + "list_watches/list_* next_cursor; keep the same filters and target args."));
    schemaRoot.property(
        ARG_EXPRESSION,
        SchemaBuilder.string(mapper).description("Watch expression for add_watch/update_watch."));
    schemaRoot.property(
        ARG_WATCH_INDEX,
        SchemaBuilder.integer(mapper)
            .description("Zero-based watch index from list_watches.")
            .minimum(0));
    schemaRoot.property(
        ARG_COMMENT, SchemaBuilder.string(mapper).description("Optional watch comment."));
    schemaRoot.property(
        ARG_METHOD_NAME,
        SchemaBuilder.string(mapper)
            .description("Remote Trace RMI method name for invoke_remote_method."));
    schemaRoot.property(
        ARG_METHOD_ARGUMENTS,
        SchemaBuilder.objectDraft7(mapper)
            .description(
                "Remote method arguments keyed by parameter name. Primitive values pass through;"
                    + " addresses, objects, traces, targets, bytes_hex, and schedules are decoded"
                    + " from strings where the remote parameter type requires it."));
    schemaRoot.property(
        ARG_TRACKING_SPEC,
        SchemaBuilder.string(mapper)
            .description("Debugger listing tracking spec config name from list_tracking_specs."));
    schemaRoot.property(
        ARG_EMULATOR_INDEX,
        SchemaBuilder.integer(mapper)
            .description("Zero-based emulator factory index from list_emulator_factories.")
            .minimum(0));
    schemaRoot.property(
        ARG_EMULATOR_NAME,
        SchemaBuilder.string(mapper)
            .description(
                "Emulator factory title or class simple name from list_emulator_factories."));

    schemaRoot.requiredProperty(ARG_ACTION);
    schemaRoot.allOf(
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(ARG_ACTION, SchemaBuilder.string(mapper).constValue(ACTION_EXECUTE)),
                SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_COMMAND)),
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_ACTION,
                        SchemaBuilder.string(mapper).constValue(ACTION_SET_CONTROL_MODE)),
                SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_CONTROL_MODE)),
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_ACTION, SchemaBuilder.string(mapper).constValue(ACTION_READ_MEMORY)),
                SchemaBuilder.objectDraft7(mapper)
                    .requiredProperty(ARG_ADDRESS)
                    .requiredProperty(ARG_LENGTH)),
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_ACTION, SchemaBuilder.string(mapper).constValue(ACTION_REFRESH_MEMORY)),
                SchemaBuilder.objectDraft7(mapper)
                    .requiredProperty(ARG_ADDRESS)
                    .requiredProperty(ARG_LENGTH)),
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_ACTION, SchemaBuilder.string(mapper).constValue(ACTION_WRITE_MEMORY)),
                SchemaBuilder.objectDraft7(mapper)
                    .requiredProperty(ARG_ADDRESS)
                    .requiredProperty(ARG_BYTES_HEX)),
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_ACTION,
                        SchemaBuilder.string(mapper).constValue(ACTION_READ_TRACE_BYTES)),
                SchemaBuilder.objectDraft7(mapper)
                    .requiredProperty(ARG_ADDRESS)
                    .requiredProperty(ARG_LENGTH)),
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_ACTION,
                        SchemaBuilder.string(mapper).constValue(ACTION_WRITE_TRACE_BYTES)),
                SchemaBuilder.objectDraft7(mapper)
                    .requiredProperty(ARG_ADDRESS)
                    .requiredProperty(ARG_BYTES_HEX)),
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_ACTION,
                        SchemaBuilder.string(mapper).constValue(ACTION_GET_MEMORY_STATE)),
                SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_ADDRESS)),
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_ACTION,
                        SchemaBuilder.string(mapper).constValue(ACTION_SET_MEMORY_STATE)),
                SchemaBuilder.objectDraft7(mapper)
                    .requiredProperty(ARG_ADDRESS)
                    .requiredProperty(ARG_LENGTH)
                    .requiredProperty(ARG_MEMORY_STATE)),
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_ACTION, SchemaBuilder.string(mapper).constValue(ACTION_SET_BREAKPOINT)),
                SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_ADDRESS)),
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_ACTION, SchemaBuilder.string(mapper).constValue(ACTION_SET_WATCHPOINT)),
                SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_ADDRESS)),
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_ACTION,
                        SchemaBuilder.string(mapper).constValue(ACTION_SET_STATIC_BREAKPOINT)),
                SchemaBuilder.objectDraft7(mapper)
                    .requiredProperty(ARG_FILE_NAME)
                    .requiredProperty(ARG_STATIC_ADDRESS)),
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_ACTION,
                        SchemaBuilder.string(mapper).constValue(ACTION_ENABLE_BREAKPOINT)),
                SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_ADDRESS)),
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_ACTION,
                        SchemaBuilder.string(mapper).constValue(ACTION_DISABLE_BREAKPOINT)),
                SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_ADDRESS)),
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_ACTION,
                        SchemaBuilder.string(mapper).constValue(ACTION_DELETE_BREAKPOINT)),
                SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_ADDRESS)),
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_ACTION, SchemaBuilder.string(mapper).constValue(ACTION_GO_TO_ADDRESS)),
                SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_ADDRESS)),
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_ACTION, SchemaBuilder.string(mapper).constValue(ACTION_SELECT_RANGE)),
                SchemaBuilder.objectDraft7(mapper)
                    .requiredProperty(ARG_ADDRESS)
                    .requiredProperty(ARG_LENGTH)),
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_ACTION,
                        SchemaBuilder.string(mapper).constValue(ACTION_SET_TRACKING_SPEC)),
                SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_TRACKING_SPEC)),
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_ACTION, SchemaBuilder.string(mapper).constValue(ACTION_MAP_DATA_TYPE)),
                SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_ADDRESS)),
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_ACTION, SchemaBuilder.string(mapper).constValue(ACTION_WRITE_REGISTER)),
                SchemaBuilder.objectDraft7(mapper)
                    .requiredProperty(ARG_REGISTER_NAME)
                    .requiredProperty(ARG_VALUE)),
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_ACTION, SchemaBuilder.string(mapper).constValue(ACTION_ADD_WATCH)),
                SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_EXPRESSION)),
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_ACTION, SchemaBuilder.string(mapper).constValue(ACTION_UPDATE_WATCH)),
                SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_WATCH_INDEX)),
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_ACTION, SchemaBuilder.string(mapper).constValue(ACTION_REMOVE_WATCH)),
                SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_WATCH_INDEX)),
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_ACTION, SchemaBuilder.string(mapper).constValue(ACTION_GET_OBJECT)),
                SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_OBJECT_PATH)),
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_ACTION,
                        SchemaBuilder.string(mapper).constValue(ACTION_ACTIVATE_OBJECT)),
                SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_OBJECT_PATH)),
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_ACTION,
                        SchemaBuilder.string(mapper).constValue(ACTION_INVOKE_REMOTE_METHOD)),
                SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_METHOD_NAME)),
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_ACTION, SchemaBuilder.string(mapper).constValue(ACTION_LIST_LAUNCHERS)),
                SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_FILE_NAME)),
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(ARG_ACTION, SchemaBuilder.string(mapper).constValue(ACTION_LAUNCH)),
                SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_FILE_NAME)),
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_ACTION,
                        SchemaBuilder.string(mapper).constValue(ACTION_LAUNCH_EMULATOR)),
                SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_FILE_NAME)),
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_ACTION,
                        SchemaBuilder.string(mapper).constValue(ACTION_ADD_IDENTITY_MAPPING)),
                SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_FILE_NAME)),
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_ACTION,
                        SchemaBuilder.string(mapper).constValue(ACTION_PROPOSE_MAPPING)),
                SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_FILE_NAME)),
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_ACTION, SchemaBuilder.string(mapper).constValue(ACTION_APPLY_MAPPING)),
                SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_FILE_NAME)),
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_ACTION,
                        SchemaBuilder.string(mapper).constValue(ACTION_MAP_DYNAMIC_TO_STATIC)),
                SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_ADDRESS)),
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_ACTION,
                        SchemaBuilder.string(mapper).constValue(ACTION_MAP_STATIC_TO_DYNAMIC)),
                SchemaBuilder.objectDraft7(mapper)
                    .requiredProperty(ARG_FILE_NAME)
                    .requiredProperty(ARG_STATIC_ADDRESS)));

    return schemaRoot.build();
  }

  @Override
  public Mono<? extends Object> execute(
      McpTransportContext context, Map<String, Object> args, PluginTool tool) {
    String action;
    try {
      action = getRequiredStringArgument(args, ARG_ACTION).toLowerCase();
    } catch (GhidraMcpException e) {
      return Mono.error(e);
    }

    if (ACTION_MAP_DATA_TYPE.equals(action)) {
      return handleMapDataType(tool, args);
    }
    if (ACTION_LIST_LAUNCHERS.equals(action)) {
      return getProgram(args, tool).map(program -> handleListLaunchers(tool, program, args));
    }
    if (ACTION_LAUNCH.equals(action)) {
      return getProgram(args, tool)
          .flatMap(
              program ->
                  withTaskMonitor(
                      "debugger.launch", monitor -> handleLaunch(tool, program, args, monitor)));
    }
    if (ACTION_SET_STATIC_BREAKPOINT.equals(action)) {
      return getProgram(args, tool).map(program -> handleSetStaticBreakpoint(tool, program, args));
    }
    if (ACTION_LAUNCH_EMULATOR.equals(action)) {
      return getProgram(args, tool)
          .flatMap(
              program ->
                  withTaskMonitor(
                      "debugger.launch_emulator",
                      monitor -> handleLaunchEmulator(tool, program, args, monitor)));
    }
    if (ACTION_EMULATE.equals(action)) {
      return withTaskMonitor("debugger.emulate", monitor -> handleEmulate(tool, args, monitor));
    }
    if (ACTION_RUN_EMULATION.equals(action)) {
      return withTaskMonitor(
          "debugger.run_emulation", monitor -> handleRunEmulation(tool, args, monitor));
    }
    if (ACTION_OPEN_MAPPED_PROGRAMS.equals(action)) {
      return withTaskMonitor(
          "debugger.open_mapped_programs",
          monitor -> handleOpenMappedPrograms(tool, args, monitor));
    }
    if (ACTION_PROPOSE_MAPPING.equals(action)) {
      return getProgram(args, tool).map(program -> handleProposeMapping(tool, program, args));
    }
    if (ACTION_APPLY_MAPPING.equals(action)) {
      return getProgram(args, tool)
          .flatMap(
              program ->
                  withTaskMonitor(
                      "debugger.apply_mapping",
                      monitor -> handleApplyMapping(tool, program, args, monitor)));
    }
    if (ACTION_ADD_IDENTITY_MAPPING.equals(action)) {
      return getProgram(args, tool).map(program -> handleAddIdentityMapping(tool, program, args));
    }
    if (ACTION_MAP_STATIC_TO_DYNAMIC.equals(action)) {
      return getProgram(args, tool).map(program -> handleMapStaticToDynamic(tool, program, args));
    }

    return Mono.fromCallable(() -> handleSynchronousAction(action, tool, args));
  }

  private Object handleSynchronousAction(String action, PluginTool tool, Map<String, Object> args)
      throws GhidraMcpException {
    return switch (action) {
      case ACTION_STATUS -> handleStatus(tool);
      case ACTION_EXECUTE -> handleExecute(tool, args);
      case ACTION_RESUME, "go", "continue" ->
          handleTargetAction(tool, args, ACTION_RESUME, ActionName.RESUME);
      case ACTION_INTERRUPT, "pause", "break" ->
          handleTargetAction(tool, args, ACTION_INTERRUPT, ActionName.INTERRUPT);
      case ACTION_STEP_INTO -> handleTargetAction(tool, args, action, ActionName.STEP_INTO);
      case ACTION_STEP_OVER -> handleTargetAction(tool, args, action, ActionName.STEP_OVER);
      case ACTION_STEP_OUT -> handleTargetAction(tool, args, action, ActionName.STEP_OUT);
      case ACTION_STEP_SKIP -> handleTargetAction(tool, args, action, ActionName.STEP_SKIP);
      case ACTION_STEP_BACK -> handleTargetAction(tool, args, action, ActionName.STEP_BACK);
      case ACTION_ATTACH -> handleRemoteAction(tool, args, action, ActionName.ATTACH);
      case ACTION_DETACH -> handleTargetAction(tool, args, action, ActionName.DETACH);
      case ACTION_KILL -> handleKillTarget(tool, args);
      case ACTION_DISCONNECT -> handleDisconnectTarget(tool, args);
      case ACTION_CLOSE_CONNECTION -> handleCloseConnection(tool, args);
      case ACTION_CLOSE_TRACE -> handleCloseTrace(tool, args, false);
      case ACTION_SAVE_TRACE -> handleSaveTrace(tool, args);
      case ACTION_CLOSE_DEAD_TRACES -> handleCloseDeadTraces(tool);
      case ACTION_GET_CONTROL_MODE -> handleGetControlMode(tool, args);
      case ACTION_SET_CONTROL_MODE -> handleSetControlMode(tool, args);
      case ACTION_SET_BREAKPOINT -> handleSetBreakpoint(tool, args);
      case ACTION_SET_WATCHPOINT -> handleSetWatchpoint(tool, args);
      case ACTION_LIST_SUPPORTED_BREAKPOINT_KINDS -> handleListSupportedBreakpointKinds(tool);
      case ACTION_LIST_BREAKPOINTS -> handleListBreakpoints(tool);
      case ACTION_ENABLE_BREAKPOINT ->
          handleBreakpointMutation(tool, args, ACTION_ENABLE_BREAKPOINT);
      case ACTION_DISABLE_BREAKPOINT ->
          handleBreakpointMutation(tool, args, ACTION_DISABLE_BREAKPOINT);
      case ACTION_DELETE_BREAKPOINT ->
          handleBreakpointMutation(tool, args, ACTION_DELETE_BREAKPOINT);
      case ACTION_GO_TO_ADDRESS -> handleGoToAddress(tool, args);
      case ACTION_READ_MEMORY -> handleReadMemory(tool, args, true);
      case ACTION_REFRESH_MEMORY -> handleRefreshMemory(tool, args);
      case ACTION_WRITE_MEMORY -> handleWriteMemory(tool, args);
      case ACTION_INVALIDATE_MEMORY_CACHE -> handleInvalidateMemoryCache(tool, args);
      case ACTION_READ_TRACE_BYTES -> handleReadMemory(tool, args, false);
      case ACTION_WRITE_TRACE_BYTES -> handleWriteTraceBytes(tool, args);
      case ACTION_GET_MEMORY_STATE -> handleGetMemoryState(tool, args);
      case ACTION_SET_MEMORY_STATE -> handleSetMemoryState(tool, args);
      case ACTION_LIST_MEMORY_REGIONS -> handleListMemoryRegions(tool, args);
      case ACTION_SELECT_RANGE -> handleSelectRange(tool, args);
      case ACTION_LIST_TRACKING_SPECS -> handleListTrackingSpecs(tool, args);
      case ACTION_SET_TRACKING_SPEC -> handleSetTrackingSpec(tool, args);
      case ACTION_LIST_REGISTERS -> handleListRegisters(tool, args, false);
      case ACTION_READ_REGISTERS -> handleListRegisters(tool, args, true);
      case ACTION_WRITE_REGISTER -> handleWriteRegister(tool, args);
      case ACTION_LIST_WATCHES -> handleListWatches(tool, args);
      case ACTION_ADD_WATCH -> handleAddWatch(tool, args);
      case ACTION_UPDATE_WATCH -> handleUpdateWatch(tool, args);
      case ACTION_REMOVE_WATCH -> handleRemoveWatch(tool, args);
      case ACTION_START_SERVER -> handleStartServer(tool, args);
      case ACTION_STOP_SERVER -> handleStopServer(tool);
      case ACTION_CONNECT -> handleConnect(tool, args);
      case ACTION_ACCEPT -> handleAccept(tool, args);
      case ACTION_LIST_CONNECTIONS -> handleListConnections(tool, args);
      case ACTION_LIST_TRACES -> handleListTraces(tool, args);
      case ACTION_LIST_TARGETS -> handleListTargets(tool, args);
      case ACTION_ACTIVATE_TRACE -> handleActivateTrace(tool, args);
      case ACTION_ACTIVATE_TARGET -> handleActivateTarget(tool, args);
      case ACTION_ACTIVATE_THREAD -> handleActivateThread(tool, args);
      case ACTION_ACTIVATE_OBJECT -> handleActivateObject(tool, args);
      case ACTION_ACTIVATE_TIME -> handleActivateTime(tool, args);
      case ACTION_ACTIVATE_PLATFORM -> handleActivatePlatform(tool, args);
      case ACTION_ACTIVATE_SNAP -> handleActivateSnap(tool, args);
      case ACTION_ACTIVATE_FRAME -> handleActivateFrame(tool, args);
      case ACTION_LIST_THREADS -> handleListThreads(tool, args);
      case ACTION_LIST_STACK -> handleListStack(tool, args);
      case ACTION_LIST_SNAPSHOTS -> handleListSnapshots(tool, args);
      case ACTION_LIST_OBJECTS -> handleListObjects(tool, args);
      case ACTION_GET_OBJECT -> handleGetObject(tool, args);
      case ACTION_LIST_MODULES -> handleListModules(tool, args);
      case ACTION_LIST_SECTIONS -> handleListSections(tool, args);
      case ACTION_MAP_DYNAMIC_TO_STATIC -> handleMapDynamicToStatic(tool, args);
      case ACTION_FIND_BEST_MODULE_PROGRAM -> handleFindBestModuleProgram(tool, args);
      case ACTION_LIST_MAPPED_VIEWS -> handleListMappedViews(tool, args);
      case ACTION_LIST_PLATFORMS -> handleListPlatforms(tool, args);
      case ACTION_GET_PLATFORM_MAPPER -> handleGetPlatformMapper(tool, args);
      case ACTION_SET_PLATFORM_MAPPER -> handleSetPlatformMapper(tool, args);
      case ACTION_LIST_REMOTE_METHODS -> handleListRemoteMethods(tool, args);
      case ACTION_INVOKE_REMOTE_METHOD -> handleInvokeRemoteMethod(tool, args);
      case ACTION_LIST_EMULATOR_FACTORIES -> handleListEmulatorFactories(tool, args);
      case ACTION_SET_EMULATOR_FACTORY -> handleSetEmulatorFactory(tool, args);
      case ACTION_LIST_BUSY_EMULATORS -> handleListBusyEmulators(tool);
      case ACTION_INVALIDATE_EMULATOR_CACHE -> handleInvalidateEmulatorCache(tool);
      default -> {
        Map<String, String> aliases =
            Map.of("go", ACTION_RESUME, "continue", ACTION_RESUME, "pause", ACTION_INTERRUPT);
        GhidraMcpError error =
            GhidraMcpErrorUtils.invalidAction(
                action,
                List.of(
                    ACTION_STATUS,
                    ACTION_EXECUTE,
                    ACTION_RESUME,
                    ACTION_INTERRUPT,
                    ACTION_STEP_INTO,
                    ACTION_STEP_OVER,
                    ACTION_STEP_OUT,
                    ACTION_STEP_SKIP,
                    ACTION_STEP_BACK,
                    ACTION_ATTACH,
                    ACTION_DETACH,
                    ACTION_KILL,
                    ACTION_DISCONNECT,
                    ACTION_CLOSE_CONNECTION,
                    ACTION_CLOSE_TRACE,
                    ACTION_SAVE_TRACE,
                    ACTION_CLOSE_DEAD_TRACES,
                    ACTION_GET_CONTROL_MODE,
                    ACTION_SET_CONTROL_MODE,
                    ACTION_SET_BREAKPOINT,
                    ACTION_SET_STATIC_BREAKPOINT,
                    ACTION_SET_WATCHPOINT,
                    ACTION_LIST_SUPPORTED_BREAKPOINT_KINDS,
                    ACTION_LIST_BREAKPOINTS,
                    ACTION_ENABLE_BREAKPOINT,
                    ACTION_DISABLE_BREAKPOINT,
                    ACTION_DELETE_BREAKPOINT,
                    ACTION_GO_TO_ADDRESS,
                    ACTION_READ_MEMORY,
                    ACTION_REFRESH_MEMORY,
                    ACTION_WRITE_MEMORY,
                    ACTION_INVALIDATE_MEMORY_CACHE,
                    ACTION_READ_TRACE_BYTES,
                    ACTION_WRITE_TRACE_BYTES,
                    ACTION_GET_MEMORY_STATE,
                    ACTION_SET_MEMORY_STATE,
                    ACTION_LIST_MEMORY_REGIONS,
                    ACTION_SELECT_RANGE,
                    ACTION_LIST_TRACKING_SPECS,
                    ACTION_SET_TRACKING_SPEC,
                    ACTION_MAP_DATA_TYPE,
                    ACTION_LIST_REGISTERS,
                    ACTION_READ_REGISTERS,
                    ACTION_WRITE_REGISTER,
                    ACTION_LIST_WATCHES,
                    ACTION_ADD_WATCH,
                    ACTION_UPDATE_WATCH,
                    ACTION_REMOVE_WATCH,
                    ACTION_START_SERVER,
                    ACTION_STOP_SERVER,
                    ACTION_CONNECT,
                    ACTION_ACCEPT,
                    ACTION_LIST_CONNECTIONS,
                    ACTION_LIST_LAUNCHERS,
                    ACTION_LAUNCH,
                    ACTION_LIST_TRACES,
                    ACTION_LIST_TARGETS,
                    ACTION_ACTIVATE_TRACE,
                    ACTION_ACTIVATE_TARGET,
                    ACTION_ACTIVATE_THREAD,
                    ACTION_ACTIVATE_OBJECT,
                    ACTION_ACTIVATE_TIME,
                    ACTION_ACTIVATE_PLATFORM,
                    ACTION_ACTIVATE_SNAP,
                    ACTION_ACTIVATE_FRAME,
                    ACTION_LIST_THREADS,
                    ACTION_LIST_STACK,
                    ACTION_LIST_SNAPSHOTS,
                    ACTION_LIST_OBJECTS,
                    ACTION_GET_OBJECT,
                    ACTION_LIST_MODULES,
                    ACTION_LIST_SECTIONS,
                    ACTION_PROPOSE_MAPPING,
                    ACTION_APPLY_MAPPING,
                    ACTION_ADD_IDENTITY_MAPPING,
                    ACTION_MAP_DYNAMIC_TO_STATIC,
                    ACTION_MAP_STATIC_TO_DYNAMIC,
                    ACTION_FIND_BEST_MODULE_PROGRAM,
                    ACTION_OPEN_MAPPED_PROGRAMS,
                    ACTION_LIST_MAPPED_VIEWS,
                    ACTION_LIST_PLATFORMS,
                    ACTION_GET_PLATFORM_MAPPER,
                    ACTION_SET_PLATFORM_MAPPER,
                    ACTION_LIST_REMOTE_METHODS,
                    ACTION_INVOKE_REMOTE_METHOD,
                    ACTION_LIST_EMULATOR_FACTORIES,
                    ACTION_SET_EMULATOR_FACTORY,
                    ACTION_LAUNCH_EMULATOR,
                    ACTION_EMULATE,
                    ACTION_RUN_EMULATION,
                    ACTION_LIST_BUSY_EMULATORS,
                    ACTION_INVALIDATE_EMULATOR_CACHE),
                aliases);
        throw new GhidraMcpException(error);
      }
    };
  }

  private Map<String, Object> handleStatus(PluginTool tool) throws GhidraMcpException {
    DebuggerTraceManagerService traceService =
        requireService(tool, DebuggerTraceManagerService.class);
    DebuggerCoordinates coordinates = traceService.getCurrent();
    Trace trace = coordinates != null ? coordinates.getTrace() : null;
    Target target = coordinates != null ? coordinates.getTarget() : null;
    TraceThread thread = coordinates != null ? coordinates.getThread() : null;

    Map<String, Object> status = new LinkedHashMap<>();
    status.put("open_trace_count", traceService.getOpenTraces().size());
    status.put(
        "open_traces",
        traceService.getOpenTraces().stream().map(Trace::getName).collect(Collectors.toList()));
    putIfNotNull(status, "trace", trace != null ? trace.getName() : null);
    putIfNotNull(status, "target", target != null ? target.describe() : null);
    putIfNotNull(status, "target_valid", target != null ? target.isValid() : null);
    putIfNotNull(status, "target_busy", target != null ? target.isBusy() : null);
    putIfNotNull(status, "snap", coordinates != null ? coordinates.getSnap() : null);
    putIfNotNull(status, "frame", coordinates != null ? coordinates.getFrame() : null);
    if (thread != null) {
      Map<String, Object> threadInfo = new LinkedHashMap<>();
      threadInfo.put("key", thread.getKey());
      threadInfo.put("path", thread.getPath());
      putIfNotNull(threadInfo, "name", thread.getName(coordinates.getSnap()));
      status.put("thread", threadInfo);
    }

    DebuggerControlService controlService =
        tool != null ? tool.getService(DebuggerControlService.class) : null;
    if (controlService != null && trace != null) {
      putIfNotNull(status, "control_mode", controlService.getCurrentMode(trace).name());
    }

    if (target != null && thread != null) {
      TraceExecutionState state = target.getThreadExecutionState(thread);
      putIfNotNull(status, "execution_state", state != null ? state.name() : null);
    }

    return status;
  }

  private Map<String, Object> handleStartServer(PluginTool tool, Map<String, Object> args)
      throws GhidraMcpException {
    TraceRmiService rmiService = requireService(tool, TraceRmiService.class);
    SocketAddress address = resolveSocketAddress(args, rmiService.getServerAddress(), false);
    if (address != null) {
      rmiService.setServerAddress(address);
    }
    try {
      if (!rmiService.isServerStarted()) {
        rmiService.startServer();
      }
    } catch (IOException e) {
      throw new GhidraMcpException(
          GhidraMcpError.failed("start Trace RMI server", describeFailure(e)), e);
    }

    Map<String, Object> result = new LinkedHashMap<>();
    result.put("started", rmiService.isServerStarted());
    result.put("server_address", describeSocketAddress(rmiService.getServerAddress()));
    return result;
  }

  private OperationResult handleStopServer(PluginTool tool) throws GhidraMcpException {
    TraceRmiService rmiService = requireService(tool, TraceRmiService.class);
    rmiService.stopServer();
    return OperationResult.success(ACTION_STOP_SERVER, "trace-rmi", "Trace RMI server stopped.");
  }

  private Map<String, Object> handleConnect(PluginTool tool, Map<String, Object> args)
      throws GhidraMcpException {
    TraceRmiService rmiService = requireService(tool, TraceRmiService.class);
    SocketAddress address = resolveSocketAddress(args, rmiService.getServerAddress(), true);
    try {
      TraceRmiConnection connection = rmiService.connect(address);
      return createConnectionInfo(indexOfConnection(rmiService, connection), connection);
    } catch (IOException e) {
      throw new GhidraMcpException(
          GhidraMcpError.failed("connect Trace RMI", describeFailure(e)), e);
    }
  }

  private Map<String, Object> handleAccept(PluginTool tool, Map<String, Object> args)
      throws GhidraMcpException {
    TraceRmiService rmiService = requireService(tool, TraceRmiService.class);
    SocketAddress address = resolveSocketAddress(args, rmiService.getServerAddress(), false);
    boolean wait = getOptionalBooleanArgument(args, ARG_WAIT).orElse(false);
    int timeoutMs = getOptionalIntArgument(args, ARG_TIMEOUT_MS).orElse(DEFAULT_TIMEOUT_MS);
    try {
      TraceRmiAcceptor acceptor = rmiService.acceptOne(address);
      if (!wait) {
        Map<String, Object> info =
            createAcceptorInfo(indexOfAcceptor(rmiService, acceptor), acceptor);
        info.put("waiting", false);
        return info;
      }
      acceptor.setTimeout(timeoutMs);
      TraceRmiConnection connection = acceptor.accept();
      Map<String, Object> info =
          createConnectionInfo(indexOfConnection(rmiService, connection), connection);
      info.put("accepted_from", describeSocketAddress(acceptor.getAddress()));
      return info;
    } catch (SocketException e) {
      throw new GhidraMcpException(
          GhidraMcpError.failed("configure Trace RMI acceptor", describeFailure(e)), e);
    } catch (Exception e) {
      throw new GhidraMcpException(
          GhidraMcpError.failed("accept Trace RMI connection", describeFailure(e)), e);
    }
  }

  private Map<String, Object> handleListConnections(PluginTool tool, Map<String, Object> args)
      throws GhidraMcpException {
    TraceRmiService rmiService = requireService(tool, TraceRmiService.class);
    List<TraceRmiConnection> connections = new ArrayList<>(rmiService.getAllConnections());
    List<TraceRmiAcceptor> acceptors = new ArrayList<>(rmiService.getAllAcceptors());

    Map<String, Object> result = new LinkedHashMap<>();
    result.put("server_started", rmiService.isServerStarted());
    result.put("server_address", describeSocketAddress(rmiService.getServerAddress()));
    result.put("connection_count", connections.size());
    result.put("acceptor_count", acceptors.size());
    result.put("connections", indexedRows(connections, this::createConnectionInfo));
    result.put("acceptors", indexedRows(acceptors, this::createAcceptorInfo));
    return result;
  }

  private CursorDataResult<List<Map<String, Object>>> handleListTraces(
      PluginTool tool, Map<String, Object> args) throws GhidraMcpException {
    DebuggerTraceManagerService traceService =
        requireService(tool, DebuggerTraceManagerService.class);
    List<Trace> traces = new ArrayList<>(traceService.getOpenTraces());
    List<Map<String, Object>> rows = indexedRows(traces, this::createTraceInfo);
    return pageRows(rows, args, "v1:<base64url_trace_offset>");
  }

  private CursorDataResult<List<Map<String, Object>>> handleListTargets(
      PluginTool tool, Map<String, Object> args) throws GhidraMcpException {
    List<Target> targets = allTargets(tool);
    List<Map<String, Object>> rows = indexedRows(targets, this::createTargetInfo);
    return pageRows(rows, args, "v1:<base64url_target_offset>");
  }

  private Map<String, Object> handleActivateTrace(PluginTool tool, Map<String, Object> args)
      throws GhidraMcpException {
    DebuggerTraceManagerService traceService =
        requireService(tool, DebuggerTraceManagerService.class);
    Trace trace = resolveTrace(traceService, args);
    traceService.activateTrace(trace);
    return createTraceInfo(indexOfTrace(traceService, trace), trace);
  }

  private Map<String, Object> handleActivateTarget(PluginTool tool, Map<String, Object> args)
      throws GhidraMcpException {
    DebuggerTraceManagerService traceService =
        requireService(tool, DebuggerTraceManagerService.class);
    Target target = resolveTarget(tool, args);
    traceService.activateTarget(target);
    return createTargetInfo(resolveTargetIndex(tool, target), target);
  }

  private Map<String, Object> handleActivateThread(PluginTool tool, Map<String, Object> args)
      throws GhidraMcpException {
    DebuggerTraceManagerService traceService =
        requireService(tool, DebuggerTraceManagerService.class);
    DebuggerCoordinates coordinates = requireCurrentCoordinates(traceService);
    TraceThread thread = resolveThread(coordinates.getTrace(), coordinates.getSnap(), args);
    traceService.activateThread(thread);
    return createThreadInfo(thread, coordinates.getSnap());
  }

  private Map<String, Object> handleActivateSnap(PluginTool tool, Map<String, Object> args)
      throws GhidraMcpException {
    DebuggerTraceManagerService traceService =
        requireService(tool, DebuggerTraceManagerService.class);
    long snap = getRequiredLongArgument(args, ARG_SNAP);
    traceService.activateSnap(snap);
    return Map.of("snap", snap);
  }

  private Map<String, Object> handleActivateFrame(PluginTool tool, Map<String, Object> args)
      throws GhidraMcpException {
    DebuggerTraceManagerService traceService =
        requireService(tool, DebuggerTraceManagerService.class);
    int frame = getRequiredIntArgument(args, ARG_FRAME);
    traceService.activateFrame(frame);
    return Map.of("frame", frame);
  }

  private Map<String, Object> handleActivateObject(PluginTool tool, Map<String, Object> args)
      throws GhidraMcpException {
    DebuggerTraceManagerService traceService =
        requireService(tool, DebuggerTraceManagerService.class);
    Trace trace = resolveTrace(traceService, args);
    TraceObject object = resolveObject(trace, args);
    traceService.activateObject(object);
    return createObjectInfo(
        -1, object, getOptionalLongArgument(args, ARG_SNAP).orElse(traceService.getCurrentSnap()));
  }

  private Map<String, Object> handleActivateTime(PluginTool tool, Map<String, Object> args)
      throws GhidraMcpException {
    DebuggerTraceManagerService traceService =
        requireService(tool, DebuggerTraceManagerService.class);
    DebuggerCoordinates coordinates = requireCurrentCoordinates(traceService);
    TraceSchedule schedule = resolveSchedule(coordinates, args);
    traceService.activateTime(schedule);
    return createTimeInfo(coordinates.getTrace(), schedule);
  }

  private Map<String, Object> handleActivatePlatform(PluginTool tool, Map<String, Object> args)
      throws GhidraMcpException {
    DebuggerTraceManagerService traceService =
        requireService(tool, DebuggerTraceManagerService.class);
    DebuggerCoordinates coordinates = requireCurrentCoordinates(traceService);
    TracePlatform platform = resolvePlatform(coordinates.getTrace(), args);
    traceService.activatePlatform(platform);
    return createPlatformInfo(resolvePlatformIndex(coordinates.getTrace(), platform), platform);
  }

  private CursorDataResult<List<Map<String, Object>>> handleListThreads(
      PluginTool tool, Map<String, Object> args) throws GhidraMcpException {
    DebuggerTraceManagerService traceService =
        requireService(tool, DebuggerTraceManagerService.class);
    DebuggerCoordinates coordinates = requireCurrentCoordinates(traceService);
    long snap = getOptionalLongArgument(args, ARG_SNAP).orElse(coordinates.getSnap());
    boolean includeAll = getOptionalBooleanArgument(args, ARG_INCLUDE_ALL).orElse(false);
    Collection<? extends TraceThread> source =
        includeAll
            ? coordinates.getTrace().getThreadManager().getAllThreads()
            : coordinates.getTrace().getThreadManager().getLiveThreads(snap);
    List<TraceThread> threads = new ArrayList<>(source);
    threads.sort(Comparator.comparingLong(TraceThread::getKey));
    List<Map<String, Object>> rows = new ArrayList<>(threads.size());
    for (int i = 0; i < threads.size(); i++) {
      rows.add(createThreadInfo(i, threads.get(i), coordinates.getTarget(), snap));
    }
    return pageRows(rows, args, "v1:<base64url_thread_offset>");
  }

  private CursorDataResult<List<Map<String, Object>>> handleListStack(
      PluginTool tool, Map<String, Object> args) throws GhidraMcpException {
    DebuggerTraceManagerService traceService =
        requireService(tool, DebuggerTraceManagerService.class);
    DebuggerCoordinates coordinates = requireCurrentCoordinates(traceService);
    long snap = getOptionalLongArgument(args, ARG_SNAP).orElse(coordinates.getSnap());
    TraceThread thread =
        args.containsKey(ARG_THREAD_KEY) || args.containsKey(ARG_THREAD_PATH)
            ? resolveThread(coordinates.getTrace(), snap, args)
            : coordinates.getThread();
    if (thread == null) {
      thread = resolveThread(coordinates.getTrace(), snap, args);
    }
    TraceStack stack = coordinates.getTrace().getStackManager().getLatestStack(thread, snap);
    List<Map<String, Object>> rows = new ArrayList<>();
    if (stack != null) {
      for (TraceStackFrame frame : stack.getFrames(snap)) {
        rows.add(createStackFrameInfo(frame, snap, coordinates.getFrame()));
      }
    }
    return pageRows(rows, args, "v1:<base64url_stack_frame_offset>");
  }

  private CursorDataResult<List<Map<String, Object>>> handleListSnapshots(
      PluginTool tool, Map<String, Object> args) throws GhidraMcpException {
    DebuggerTraceManagerService traceService =
        requireService(tool, DebuggerTraceManagerService.class);
    Trace trace = resolveTrace(traceService, args);
    List<TraceSnapshot> snapshots = new ArrayList<>(trace.getTimeManager().getAllSnapshots());
    snapshots.sort(Comparator.comparingLong(TraceSnapshot::getKey));
    List<Map<String, Object>> rows = new ArrayList<>(snapshots.size());
    for (int i = 0; i < snapshots.size(); i++) {
      rows.add(createSnapshotInfo(i, snapshots.get(i)));
    }
    return pageRows(rows, args, "v1:<base64url_snapshot_offset>");
  }

  private CursorDataResult<List<Map<String, Object>>> handleListObjects(
      PluginTool tool, Map<String, Object> args) throws GhidraMcpException {
    DebuggerTraceManagerService traceService =
        requireService(tool, DebuggerTraceManagerService.class);
    DebuggerCoordinates coordinates = requireCurrentCoordinates(traceService);
    long snap = getOptionalLongArgument(args, ARG_SNAP).orElse(coordinates.getSnap());
    Optional<Pattern> pattern = compileOptionalPattern(args, ARG_NAME_PATTERN);
    List<TraceObject> objects =
        coordinates
            .getTrace()
            .getObjectManager()
            .getAllObjects()
            .filter(
                object ->
                    pattern
                        .map(p -> p.matcher(object.getCanonicalPath().toString()).find())
                        .orElse(true))
            .sorted(Comparator.comparing(object -> object.getCanonicalPath().toString()))
            .collect(Collectors.toList());
    List<Map<String, Object>> rows = new ArrayList<>(objects.size());
    for (int i = 0; i < objects.size(); i++) {
      rows.add(createObjectInfo(i, objects.get(i), snap));
    }
    return pageRows(rows, args, "v1:<base64url_object_offset>");
  }

  private CursorDataResult<Map<String, Object>> handleGetObject(
      PluginTool tool, Map<String, Object> args) throws GhidraMcpException {
    DebuggerTraceManagerService traceService =
        requireService(tool, DebuggerTraceManagerService.class);
    DebuggerCoordinates coordinates = requireCurrentCoordinates(traceService);
    long snap = getOptionalLongArgument(args, ARG_SNAP).orElse(coordinates.getSnap());
    TraceObject object = resolveObject(coordinates.getTrace(), args);
    int maxValues = getBoundedInt(args, ARG_MAX_VALUES, DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE);
    int offset = getIndexCursorOffset(args, "v1:<base64url_object_value_offset>");

    List<TraceObjectValue> values = new ArrayList<>(object.getValues(Lifespan.at(snap)));
    values.sort(Comparator.comparing(TraceObjectValue::getEntryKey));
    if (offset > values.size()) {
      throw new GhidraMcpException(
          GhidraMcpError.invalid(ARG_CURSOR, args.get(ARG_CURSOR), "cursor is past object values"));
    }
    int endExclusive = Math.min(values.size(), offset + maxValues);

    Map<String, Object> info = createObjectInfo(-1, object, snap);
    List<Map<String, Object>> valueRows = new ArrayList<>();
    for (int i = offset; i < endExclusive; i++) {
      valueRows.add(createObjectValueInfo(i, values.get(i)));
    }
    info.put("values", valueRows);
    info.put("value_count", values.size());
    String nextCursor =
        endExclusive < values.size()
            ? OpaqueCursorCodec.encodeV1(String.valueOf(endExclusive))
            : null;
    return new CursorDataResult<>(info, nextCursor);
  }

  private CursorDataResult<List<Map<String, Object>>> handleListModules(
      PluginTool tool, Map<String, Object> args) throws GhidraMcpException {
    DebuggerTraceManagerService traceService =
        requireService(tool, DebuggerTraceManagerService.class);
    DebuggerCoordinates coordinates = requireCurrentCoordinates(traceService);
    long snap = getOptionalLongArgument(args, ARG_SNAP).orElse(coordinates.getSnap());
    List<TraceModule> modules =
        new ArrayList<>(coordinates.getTrace().getModuleManager().getLoadedModules(snap));
    modules.sort(Comparator.comparing(module -> safeString(module.getName(snap))));
    List<Map<String, Object>> rows = new ArrayList<>(modules.size());
    for (int i = 0; i < modules.size(); i++) {
      rows.add(createModuleInfo(i, modules.get(i), snap));
    }
    return pageRows(rows, args, "v1:<base64url_module_offset>");
  }

  private CursorDataResult<List<Map<String, Object>>> handleListSections(
      PluginTool tool, Map<String, Object> args) throws GhidraMcpException {
    DebuggerTraceManagerService traceService =
        requireService(tool, DebuggerTraceManagerService.class);
    DebuggerCoordinates coordinates = requireCurrentCoordinates(traceService);
    long snap = getOptionalLongArgument(args, ARG_SNAP).orElse(coordinates.getSnap());
    List<TraceSection> sections =
        new ArrayList<>(coordinates.getTrace().getModuleManager().getAllSections());
    sections =
        sections.stream()
            .filter(section -> section.isValid(snap))
            .sorted(
                Comparator.comparing(
                    section -> safeString(section.getName(snap)), String.CASE_INSENSITIVE_ORDER))
            .collect(Collectors.toList());
    List<Map<String, Object>> rows = new ArrayList<>(sections.size());
    for (int i = 0; i < sections.size(); i++) {
      rows.add(createSectionInfo(i, sections.get(i), snap));
    }
    return pageRows(rows, args, "v1:<base64url_section_offset>");
  }

  private CursorDataResult<List<Map<String, Object>>> handleListLaunchers(
      PluginTool tool, Program program, Map<String, Object> args) throws GhidraMcpException {
    TraceRmiLauncherService launcherService = requireService(tool, TraceRmiLauncherService.class);
    List<TraceRmiLaunchOffer> offers = new ArrayList<>(launcherService.getOffers(program));
    offers.sort(
        Comparator.comparing(TraceRmiLaunchOffer::getTitle, String.CASE_INSENSITIVE_ORDER)
            .thenComparing(TraceRmiLaunchOffer::getConfigName, String.CASE_INSENSITIVE_ORDER));
    List<Map<String, Object>> rows = new ArrayList<>(offers.size());
    for (int i = 0; i < offers.size(); i++) {
      rows.add(createLaunchOfferInfo(i, offers.get(i)));
    }
    return pageRows(rows, args, "v1:<base64url_launcher_offset>");
  }

  private Map<String, Object> handleLaunch(
      PluginTool tool, Program program, Map<String, Object> args, TaskMonitor monitor)
      throws GhidraMcpException {
    TraceRmiLauncherService launcherService = requireService(tool, TraceRmiLauncherService.class);
    DebuggerTraceManagerService traceService =
        requireService(tool, DebuggerTraceManagerService.class);
    TraceRmiLaunchOffer offer = resolveLaunchOffer(launcherService, program, args);
    TraceRmiLaunchOffer.LaunchResult result =
        offer.launchProgram(monitor, launchConfigurator(offer, args));
    if (result.exception() != null) {
      throw new GhidraMcpException(
          GhidraMcpError.failed("launch debugger", describeFailure(result.exception())),
          result.exception());
    }
    if (result.trace() != null) {
      traceService.activateTrace(result.trace());
    }

    Map<String, Object> info = new LinkedHashMap<>();
    info.put("launcher", offer.getTitle());
    info.put("config_name", offer.getConfigName());
    info.put("program", program.getName());
    info.put("trace", result.trace() != null ? result.trace().getName() : null);
    info.put(
        "connection", result.connection() != null ? result.connection().getDescription() : null);
    info.put(
        "acceptor",
        result.acceptor() != null ? describeSocketAddress(result.acceptor().getAddress()) : null);
    info.put("terminal_count", result.sessions() != null ? result.sessions().size() : 0);
    return info;
  }

  private Map<String, Object> handleProposeMapping(
      PluginTool tool, Program program, Map<String, Object> args) throws GhidraMcpException {
    DebuggerStaticMappingService mappingService =
        requireService(tool, DebuggerStaticMappingService.class);
    DebuggerTraceManagerService traceService =
        requireService(tool, DebuggerTraceManagerService.class);
    DebuggerCoordinates coordinates = requireCurrentCoordinates(traceService);
    String kind = getOptionalStringArgument(args, ARG_MAPPING_KIND).orElse("module");
    if ("identity".equalsIgnoreCase(kind)) {
      return Map.of(
          "mapping_kind",
          "identity",
          "trace",
          coordinates.getTrace().getName(),
          "program",
          program.getName(),
          "lifespan",
          mappingLifespan(args, coordinates.getSnap()).toString());
    }
    if ("address".equalsIgnoreCase(kind)) {
      return Map.of(
          "mapping_kind",
          "address",
          "dynamic_address",
          parseCurrentTraceAddress(traceService, args).toString(),
          "static_address",
          parseAddressValue(
                  program, getRequiredStringArgument(args, ARG_STATIC_ADDRESS), ARG_STATIC_ADDRESS)
              .toString(),
          "length",
          getRequiredLongArgument(args, ARG_LENGTH));
    }

    long snap = getOptionalLongArgument(args, ARG_SNAP).orElse(coordinates.getSnap());
    if ("section".equalsIgnoreCase(kind)) {
      TraceModule module = resolveModule(coordinates.getTrace(), snap, args);
      SectionMapProposal proposal = mappingService.proposeSectionMap(module, snap, program);
      return createSectionProposalInfo(proposal, snap);
    }
    if ("region".equalsIgnoreCase(kind)) {
      Collection<TraceMemoryRegion> regions = resolveRegions(coordinates.getTrace(), snap, args);
      RegionMapProposal proposal = mappingService.proposeRegionMap(regions, snap, program);
      return createRegionProposalInfo(proposal, snap);
    }

    TraceModule module = resolveModule(coordinates.getTrace(), snap, args);
    ModuleMapProposal proposal = mappingService.proposeModuleMap(module, snap, program);
    return createModuleProposalInfo(proposal, snap);
  }

  private Object handleApplyMapping(
      PluginTool tool, Program program, Map<String, Object> args, TaskMonitor monitor)
      throws GhidraMcpException {
    DebuggerStaticMappingService mappingService =
        requireService(tool, DebuggerStaticMappingService.class);
    DebuggerTraceManagerService traceService =
        requireService(tool, DebuggerTraceManagerService.class);
    DebuggerCoordinates coordinates = requireCurrentCoordinates(traceService);
    boolean truncate = getOptionalBooleanArgument(args, ARG_TRUNCATE_EXISTING).orElse(false);
    String kind = getOptionalStringArgument(args, ARG_MAPPING_KIND).orElse("module");

    if ("identity".equalsIgnoreCase(kind)) {
      return handleAddIdentityMapping(tool, program, args);
    }
    if ("address".equalsIgnoreCase(kind)) {
      Address dynamicAddress = parseCurrentTraceAddress(traceService, args);
      Address staticAddress =
          parseAddressValue(
              program, getRequiredStringArgument(args, ARG_STATIC_ADDRESS), ARG_STATIC_ADDRESS);
      long length = getRequiredLongArgument(args, ARG_LENGTH);
      TraceLocation traceLocation =
          new DefaultTraceLocation(
              coordinates.getTrace(),
              null,
              mappingLifespan(args, coordinates.getSnap()),
              dynamicAddress);
      ProgramLocation programLocation = new ProgramLocation(program, staticAddress);
      try {
        mappingService.addMapping(traceLocation, programLocation, length, truncate);
      } catch (Exception e) {
        throw new GhidraMcpException(
            GhidraMcpError.failed("apply address mapping", describeFailure(e)), e);
      }
      Map<String, Object> info = new LinkedHashMap<>();
      info.put("mapping_kind", "address");
      info.put("trace", coordinates.getTrace().getName());
      info.put("program", program.getName());
      info.put("dynamic_address", dynamicAddress.toString());
      info.put("static_address", staticAddress.toString());
      info.put("length", length);
      return ToolOutcome.of(info, NavigateToAddressEffect.listing(program, staticAddress));
    }

    long snap = getOptionalLongArgument(args, ARG_SNAP).orElse(coordinates.getSnap());
    if ("section".equalsIgnoreCase(kind)) {
      TraceModule module = resolveModule(coordinates.getTrace(), snap, args);
      SectionMapProposal proposal = mappingService.proposeSectionMap(module, snap, program);
      Collection<SectionMapProposal.SectionMapEntry> entries = proposal.computeMap().values();
      try {
        mappingService.addSectionMappings(entries, monitor, truncate);
      } catch (Exception e) {
        throw new GhidraMcpException(
            GhidraMcpError.failed("apply section mapping", describeFailure(e)), e);
      }
      Map<String, Object> info = createSectionProposalInfo(proposal, snap);
      info.put("applied", true);
      info.put("truncate_existing", truncate);
      return info;
    }
    if ("region".equalsIgnoreCase(kind)) {
      Collection<TraceMemoryRegion> regions = resolveRegions(coordinates.getTrace(), snap, args);
      RegionMapProposal proposal = mappingService.proposeRegionMap(regions, snap, program);
      Collection<RegionMapProposal.RegionMapEntry> entries = proposal.computeMap().values();
      try {
        mappingService.addRegionMappings(entries, monitor, truncate);
      } catch (Exception e) {
        throw new GhidraMcpException(
            GhidraMcpError.failed("apply region mapping", describeFailure(e)), e);
      }
      Map<String, Object> info = createRegionProposalInfo(proposal, snap);
      info.put("applied", true);
      info.put("truncate_existing", truncate);
      return info;
    }

    TraceModule module = resolveModule(coordinates.getTrace(), snap, args);
    ModuleMapProposal proposal = mappingService.proposeModuleMap(module, snap, program);
    Collection<ModuleMapProposal.ModuleMapEntry> entries = proposal.computeMap().values();
    boolean memorize = getOptionalBooleanArgument(args, ARG_MEMORIZE).orElse(false);
    entries.forEach(entry -> entry.setMemorize(memorize));
    try {
      mappingService.addModuleMappings(entries, monitor, truncate);
    } catch (Exception e) {
      throw new GhidraMcpException(
          GhidraMcpError.failed("apply module mapping", describeFailure(e)), e);
    }
    Map<String, Object> info = createModuleProposalInfo(proposal, snap);
    info.put("applied", true);
    info.put("truncate_existing", truncate);
    info.put("memorize", memorize);
    return info;
  }

  private Map<String, Object> handleAddIdentityMapping(
      PluginTool tool, Program program, Map<String, Object> args) throws GhidraMcpException {
    DebuggerStaticMappingService mappingService =
        requireService(tool, DebuggerStaticMappingService.class);
    DebuggerTraceManagerService traceService =
        requireService(tool, DebuggerTraceManagerService.class);
    DebuggerCoordinates coordinates = requireCurrentCoordinates(traceService);
    boolean truncate = getOptionalBooleanArgument(args, ARG_TRUNCATE_EXISTING).orElse(false);
    Lifespan lifespan = mappingLifespan(args, coordinates.getSnap());
    mappingService.addIdentityMapping(coordinates.getTrace(), program, lifespan, truncate);
    Map<String, Object> info = new LinkedHashMap<>();
    info.put("mapping_kind", "identity");
    info.put("trace", coordinates.getTrace().getName());
    info.put("program", program.getName());
    info.put("lifespan", lifespan.toString());
    info.put("truncate_existing", truncate);
    return info;
  }

  private Object handleMapDynamicToStatic(PluginTool tool, Map<String, Object> args)
      throws GhidraMcpException {
    DebuggerStaticMappingService mappingService =
        requireService(tool, DebuggerStaticMappingService.class);
    DebuggerTraceManagerService traceService =
        requireService(tool, DebuggerTraceManagerService.class);
    DebuggerCoordinates coordinates = requireCurrentCoordinates(traceService);
    Address dynamicAddress = parseCurrentTraceAddress(traceService, args);
    TraceLocation traceLocation =
        new DefaultTraceLocation(
            coordinates.getTrace(),
            coordinates.getThread(),
            Lifespan.at(coordinates.getSnap()),
            dynamicAddress);
    ProgramLocation staticLocation = mappingService.getOpenMappedLocation(traceLocation);
    Map<String, Object> info = new LinkedHashMap<>();
    info.put("dynamic_address", dynamicAddress.toString());
    info.put("trace", coordinates.getTrace().getName());
    if (staticLocation == null) {
      info.put("mapped", false);
      return info;
    }
    info.put("mapped", true);
    info.put("program", staticLocation.getProgram().getName());
    info.put("static_address", staticLocation.getAddress().toString());
    return ToolOutcome.of(
        info,
        NavigateToAddressEffect.listing(staticLocation.getProgram(), staticLocation.getAddress()));
  }

  private Object handleMapStaticToDynamic(
      PluginTool tool, Program program, Map<String, Object> args) throws GhidraMcpException {
    DebuggerStaticMappingService mappingService =
        requireService(tool, DebuggerStaticMappingService.class);
    DebuggerTraceManagerService traceService =
        requireService(tool, DebuggerTraceManagerService.class);
    TraceProgramView view = requireCurrentView(traceService);
    Address staticAddress =
        parseAddressValue(
            program, getRequiredStringArgument(args, ARG_STATIC_ADDRESS), ARG_STATIC_ADDRESS);
    ProgramLocation dynamicLocation =
        mappingService.getDynamicLocationFromStatic(
            view, new ProgramLocation(program, staticAddress));
    Map<String, Object> info = new LinkedHashMap<>();
    info.put("program", program.getName());
    info.put("static_address", staticAddress.toString());
    if (dynamicLocation == null) {
      info.put("mapped", false);
      return info;
    }
    info.put("mapped", true);
    info.put("trace", view.getTrace().getName());
    info.put("snap", view.getSnap());
    info.put("dynamic_address", dynamicLocation.getAddress().toString());
    return ToolOutcome.of(
        info, NavigateDebuggerAddressEffect.listing(dynamicLocation.getAddress()));
  }

  private Map<String, Object> handleFindBestModuleProgram(PluginTool tool, Map<String, Object> args)
      throws GhidraMcpException {
    DebuggerStaticMappingService mappingService =
        requireService(tool, DebuggerStaticMappingService.class);
    DebuggerTraceManagerService traceService =
        requireService(tool, DebuggerTraceManagerService.class);
    DebuggerCoordinates coordinates = requireCurrentCoordinates(traceService);
    long snap = getOptionalLongArgument(args, ARG_SNAP).orElse(coordinates.getSnap());
    TraceModule module = resolveModule(coordinates.getTrace(), snap, args);
    Address base = module.getBase(snap);
    if (base == null) {
      throw new GhidraMcpException(
          GhidraMcpError.failed("find best module program", "module has no base at snap " + snap));
    }
    DomainFile domainFile =
        mappingService.findBestModuleProgram(base.getAddressSpace(), module, snap);
    Map<String, Object> info = new LinkedHashMap<>();
    info.put("trace", coordinates.getTrace().getName());
    info.put("module", createModuleInfo(-1, module, snap));
    info.put("found", domainFile != null);
    putIfNotNull(info, "file_name", domainFile != null ? domainFile.getName() : null);
    putIfNotNull(info, "path", domainFile != null ? domainFile.getPathname() : null);
    return info;
  }

  private Map<String, Object> handleOpenMappedPrograms(
      PluginTool tool, Map<String, Object> args, TaskMonitor monitor) throws GhidraMcpException {
    DebuggerStaticMappingService mappingService =
        requireService(tool, DebuggerStaticMappingService.class);
    DebuggerTraceManagerService traceService =
        requireService(tool, DebuggerTraceManagerService.class);
    DebuggerCoordinates coordinates = requireCurrentCoordinates(traceService);
    long snap = getOptionalLongArgument(args, ARG_SNAP).orElse(coordinates.getSnap());
    AddressSet addressSet = resolveTraceAddressSet(coordinates, args);
    Set<Exception> failures = new LinkedHashSet<>();
    Set<Program> programs =
        mappingService.openMappedProgramsInView(coordinates.getTrace(), addressSet, snap, failures);
    Map<String, Object> info = new LinkedHashMap<>();
    info.put("trace", coordinates.getTrace().getName());
    info.put("snap", snap);
    info.put("address_set", addressSet.toString());
    info.put("programs", programs.stream().map(Program::getName).collect(Collectors.toList()));
    info.put("program_count", programs.size());
    info.put("failures", failures.stream().map(this::describeFailure).collect(Collectors.toList()));
    return info;
  }

  private CursorDataResult<List<Map<String, Object>>> handleListMappedViews(
      PluginTool tool, Map<String, Object> args) throws GhidraMcpException {
    DebuggerStaticMappingService mappingService =
        requireService(tool, DebuggerStaticMappingService.class);
    DebuggerTraceManagerService traceService =
        requireService(tool, DebuggerTraceManagerService.class);
    DebuggerCoordinates coordinates = requireCurrentCoordinates(traceService);
    long snap = getOptionalLongArgument(args, ARG_SNAP).orElse(coordinates.getSnap());
    AddressSet addressSet = resolveTraceAddressSet(coordinates, args);
    Map<Program, Collection<DebuggerStaticMappingService.MappedAddressRange>> views =
        mappingService.getOpenMappedViews(coordinates.getTrace(), addressSet, snap);
    List<Map<String, Object>> rows = new ArrayList<>();
    int index = 0;
    for (Map.Entry<Program, Collection<DebuggerStaticMappingService.MappedAddressRange>> entry :
        views.entrySet()) {
      for (DebuggerStaticMappingService.MappedAddressRange range : entry.getValue()) {
        Map<String, Object> info = new LinkedHashMap<>();
        info.put("mapped_view_index", index++);
        info.put("program", entry.getKey().getName());
        info.put("dynamic_range", range.getSourceAddressRange().toString());
        info.put("static_range", range.getDestinationAddressRange().toString());
        info.put("shift", range.getShift());
        rows.add(info);
      }
    }
    rows.sort(Comparator.comparing(row -> String.valueOf(row.get("program"))));
    return pageRows(rows, args, "v1:<base64url_mapped_view_offset>");
  }

  private CursorDataResult<List<Map<String, Object>>> handleListPlatforms(
      PluginTool tool, Map<String, Object> args) throws GhidraMcpException {
    DebuggerTraceManagerService traceService =
        requireService(tool, DebuggerTraceManagerService.class);
    Trace trace = resolveTrace(traceService, args);
    List<TracePlatform> platforms = listPlatforms(trace);
    List<Map<String, Object>> rows = new ArrayList<>(platforms.size());
    for (int i = 0; i < platforms.size(); i++) {
      rows.add(createPlatformInfo(i, platforms.get(i)));
    }
    return pageRows(rows, args, "v1:<base64url_platform_offset>");
  }

  private Map<String, Object> handleGetPlatformMapper(PluginTool tool, Map<String, Object> args)
      throws GhidraMcpException {
    DebuggerTraceManagerService traceService =
        requireService(tool, DebuggerTraceManagerService.class);
    DebuggerPlatformService platformService = requireService(tool, DebuggerPlatformService.class);
    DebuggerCoordinates coordinates = requireCurrentCoordinates(traceService);
    TraceObject object = resolveOptionalObject(coordinates, args).orElse(coordinates.getObject());
    long snap = getOptionalLongArgument(args, ARG_SNAP).orElse(coordinates.getSnap());
    DebuggerPlatformMapper current = platformService.getCurrentMapperFor(coordinates.getTrace());
    DebuggerPlatformMapper fresh =
        object != null ? platformService.getNewMapper(coordinates.getTrace(), object, snap) : null;
    Map<String, Object> info = new LinkedHashMap<>();
    info.put("trace", coordinates.getTrace().getName());
    info.put("snap", snap);
    putIfNotNull(info, "object_path", object != null ? object.getCanonicalPath().toString() : null);
    info.put("current_mapper", createMapperInfo(current, object, snap));
    putIfNotNull(info, "new_mapper", fresh != null ? createMapperInfo(fresh, object, snap) : null);
    return info;
  }

  private Map<String, Object> handleSetPlatformMapper(PluginTool tool, Map<String, Object> args)
      throws GhidraMcpException {
    DebuggerTraceManagerService traceService =
        requireService(tool, DebuggerTraceManagerService.class);
    DebuggerPlatformService platformService = requireService(tool, DebuggerPlatformService.class);
    DebuggerCoordinates coordinates = requireCurrentCoordinates(traceService);
    TraceObject object = resolveOptionalObject(coordinates, args).orElse(coordinates.getObject());
    if (object == null) {
      throw new GhidraMcpException(
          GhidraMcpError.validation()
              .message("Provide object_path or activate a current debugger object.")
              .build());
    }
    long snap = getOptionalLongArgument(args, ARG_SNAP).orElse(coordinates.getSnap());
    DebuggerPlatformMapper mapper =
        platformService.getNewMapper(coordinates.getTrace(), object, snap);
    if (mapper == null) {
      throw new GhidraMcpException(
          GhidraMcpError.failed("set platform mapper", "no mapper is available for object"));
    }
    platformService.setCurrentMapperFor(coordinates.getTrace(), object, mapper, snap);
    Map<String, Object> info = new LinkedHashMap<>();
    info.put("trace", coordinates.getTrace().getName());
    info.put("snap", snap);
    info.put("object_path", object.getCanonicalPath().toString());
    info.put("mapper", createMapperInfo(mapper, object, snap));
    return info;
  }

  private CursorDataResult<List<Map<String, Object>>> handleListRemoteMethods(
      PluginTool tool, Map<String, Object> args) throws GhidraMcpException {
    TraceRmiConnection connection = resolveConnection(tool, args);
    Optional<Pattern> pattern = compileOptionalPattern(args, ARG_NAME_PATTERN);
    List<RemoteMethod> methods =
        connection.getMethods().all().values().stream()
            .filter(
                method ->
                    pattern
                        .map(
                            p ->
                                p.matcher(method.name()).find()
                                    || p.matcher(method.display()).find()
                                    || p.matcher(method.action().name()).find())
                        .orElse(true))
            .sorted(Comparator.comparing(RemoteMethod::name, String.CASE_INSENSITIVE_ORDER))
            .collect(Collectors.toList());
    List<Map<String, Object>> rows = new ArrayList<>();
    for (int i = 0; i < methods.size(); i++) {
      rows.add(createRemoteMethodInfo(i, methods.get(i)));
    }
    return pageRows(rows, args, "v1:<base64url_remote_method_offset>");
  }

  private Map<String, Object> handleInvokeRemoteMethod(PluginTool tool, Map<String, Object> args)
      throws GhidraMcpException {
    TraceRmiConnection connection = resolveConnection(tool, args);
    RemoteMethod method = resolveRemoteMethod(connection, args);
    Map<String, Object> decodedArgs = decodeRemoteMethodArguments(tool, method, args);
    int timeoutMs = getOptionalIntArgument(args, ARG_TIMEOUT_MS).orElse(DEFAULT_TIMEOUT_MS);
    Object value =
        awaitFuture(
            method.invokeAsync(decodedArgs).toCompletableFuture(),
            "invoke remote method " + method.name(),
            timeoutMs);
    Map<String, Object> info = new LinkedHashMap<>();
    info.put("connection", connection.getDescription());
    info.put("method_name", method.name());
    info.put("action", method.action().name());
    info.put("return_type", method.retType().name());
    info.put("result", describeRemoteValue(value));
    return info;
  }

  private Map<String, Object> handleRemoteAction(
      PluginTool tool, Map<String, Object> args, String action, ActionName actionName)
      throws GhidraMcpException {
    TraceRmiConnection connection = resolveConnection(tool, args);
    RemoteMethod method = resolveRemoteActionMethod(connection, args, actionName);
    Map<String, Object> decodedArgs = decodeRemoteMethodArguments(tool, method, args);
    int timeoutMs = getOptionalIntArgument(args, ARG_TIMEOUT_MS).orElse(DEFAULT_TIMEOUT_MS);
    Object value =
        awaitFuture(
            method.invokeAsync(decodedArgs).toCompletableFuture(),
            "invoke remote action " + action,
            timeoutMs);
    Map<String, Object> info = new LinkedHashMap<>();
    info.put("connection", connection.getDescription());
    info.put("action", action);
    info.put("method_name", method.name());
    info.put("method_action", method.action().name());
    info.put("return_type", method.retType().name());
    info.put("result", describeRemoteValue(value));
    return info;
  }

  private CursorDataResult<List<Map<String, Object>>> handleListEmulatorFactories(
      PluginTool tool, Map<String, Object> args) throws GhidraMcpException {
    DebuggerEmulationService emulationService =
        requireService(tool, DebuggerEmulationService.class);
    EmulatorFactory current = emulationService.getEmulatorFactory();
    List<EmulatorFactory> factories = new ArrayList<>(emulationService.getEmulatorFactories());
    factories.sort(Comparator.comparing(EmulatorFactory::getTitle, String.CASE_INSENSITIVE_ORDER));
    List<Map<String, Object>> rows = new ArrayList<>();
    for (int i = 0; i < factories.size(); i++) {
      rows.add(createEmulatorFactoryInfo(i, factories.get(i), current));
    }
    return pageRows(rows, args, "v1:<base64url_emulator_factory_offset>");
  }

  private Map<String, Object> handleSetEmulatorFactory(PluginTool tool, Map<String, Object> args)
      throws GhidraMcpException {
    DebuggerEmulationService emulationService =
        requireService(tool, DebuggerEmulationService.class);
    EmulatorFactory factory = resolveEmulatorFactory(emulationService, args);
    emulationService.setEmulatorFactory(factory);
    return createEmulatorFactoryInfo(-1, factory, emulationService.getEmulatorFactory());
  }

  private Map<String, Object> handleLaunchEmulator(
      PluginTool tool, Program program, Map<String, Object> args, TaskMonitor monitor)
      throws GhidraMcpException {
    DebuggerEmulationService emulationService =
        requireService(tool, DebuggerEmulationService.class);
    DebuggerTraceManagerService traceService =
        requireService(tool, DebuggerTraceManagerService.class);
    Address address =
        getOptionalStringArgument(args, ARG_STATIC_ADDRESS)
            .map(value -> parseAddressValue(program, value, ARG_STATIC_ADDRESS))
            .orElseGet(program::getMinAddress);
    try {
      Trace trace = emulationService.launchProgram(program, address);
      traceService.activateTrace(trace);
      Map<String, Object> info = new LinkedHashMap<>();
      info.put("program", program.getName());
      info.put("address", address.toString());
      info.put("trace", trace.getName());
      return info;
    } catch (IOException e) {
      throw new GhidraMcpException(GhidraMcpError.failed("launch emulator", describeFailure(e)), e);
    }
  }

  private Map<String, Object> handleEmulate(
      PluginTool tool, Map<String, Object> args, TaskMonitor monitor) throws GhidraMcpException {
    DebuggerEmulationService emulationService =
        requireService(tool, DebuggerEmulationService.class);
    DebuggerTraceManagerService traceService =
        requireService(tool, DebuggerTraceManagerService.class);
    DebuggerCoordinates coordinates = requireCurrentCoordinates(traceService);
    TraceSchedule schedule = resolveSchedule(coordinates, args);
    try {
      long snapshot =
          emulationService.emulate(resolveCurrentPlatform(coordinates), schedule, monitor);
      Map<String, Object> info = createTimeInfo(coordinates.getTrace(), schedule);
      info.put("result_snap", snapshot);
      return info;
    } catch (Exception e) {
      throw new GhidraMcpException(GhidraMcpError.failed("emulate", describeFailure(e)), e);
    }
  }

  private Map<String, Object> handleRunEmulation(
      PluginTool tool, Map<String, Object> args, TaskMonitor monitor) throws GhidraMcpException {
    DebuggerEmulationService emulationService =
        requireService(tool, DebuggerEmulationService.class);
    DebuggerTraceManagerService traceService =
        requireService(tool, DebuggerTraceManagerService.class);
    DebuggerCoordinates coordinates = requireCurrentCoordinates(traceService);
    TraceThread thread = coordinates.getThread();
    if (thread == null) {
      throw new GhidraMcpException(
          GhidraMcpError.failed("run emulation", "no current thread is selected"));
    }
    TraceSchedule schedule = resolveSchedule(coordinates, args);
    try {
      DebuggerEmulationService.EmulationResult result =
          emulationService.run(
              resolveCurrentPlatform(coordinates), schedule, monitor, Scheduler.oneThread(thread));
      Map<String, Object> info = createTimeInfo(coordinates.getTrace(), schedule);
      info.put("result_snap", result.snapshot());
      info.put("result", result.toString());
      return info;
    } catch (Exception e) {
      throw new GhidraMcpException(GhidraMcpError.failed("run emulation", describeFailure(e)), e);
    }
  }

  private List<Map<String, Object>> handleListBusyEmulators(PluginTool tool)
      throws GhidraMcpException {
    DebuggerEmulationService emulationService =
        requireService(tool, DebuggerEmulationService.class);
    List<Map<String, Object>> rows = new ArrayList<>();
    int index = 0;
    for (DebuggerEmulationService.CachedEmulator cached : emulationService.getBusyEmulators()) {
      Map<String, Object> info = new LinkedHashMap<>();
      info.put("busy_emulator_index", index++);
      info.put("trace", cached.trace().getName());
      info.put("version", cached.version());
      info.put("valid", cached.isValid());
      info.put("emulator", cached.emulator().getClass().getName());
      rows.add(info);
    }
    return rows;
  }

  private OperationResult handleInvalidateEmulatorCache(PluginTool tool) throws GhidraMcpException {
    DebuggerEmulationService emulationService =
        requireService(tool, DebuggerEmulationService.class);
    emulationService.invalidateCache();
    return OperationResult.success(
        ACTION_INVALIDATE_EMULATOR_CACHE, "emulator_cache", "Emulator cache invalidated.");
  }

  private Map<String, Object> handleExecute(PluginTool tool, Map<String, Object> args)
      throws GhidraMcpException {
    Target target = requireCurrentTarget(tool);
    String command = getRequiredStringArgument(args, ARG_COMMAND);
    boolean capture = getOptionalBooleanArgument(args, ARG_CAPTURE).orElse(true);
    int timeoutMs = getOptionalIntArgument(args, ARG_TIMEOUT_MS).orElse(DEFAULT_TIMEOUT_MS);

    String output =
        awaitFuture(target.executeAsync(command, capture), "execute debugger command", timeoutMs);

    Map<String, Object> result = new LinkedHashMap<>();
    result.put("action", ACTION_EXECUTE);
    result.put("target", target.describe());
    result.put("command", command);
    result.put("capture", capture);
    putIfNotNull(result, "output", output);
    return result;
  }

  private Map<String, Object> handleTargetAction(
      PluginTool tool, Map<String, Object> args, String action, ActionName actionName)
      throws GhidraMcpException {
    Target target = requireCurrentTarget(tool);
    Target.ActionEntry entry = selectTargetAction(target, actionName);
    int timeoutMs = getOptionalIntArgument(args, ARG_TIMEOUT_MS).orElse(DEFAULT_TIMEOUT_MS);

    Object value =
        awaitFuture(entry.invokeAsyncWithoutTimeout(false), "debugger action " + action, timeoutMs);

    Map<String, Object> result = new LinkedHashMap<>();
    result.put("action", action);
    result.put("target", target.describe());
    result.put("action_display", entry.display());
    result.put("details", entry.details());
    putIfNotNull(result, "result", value);
    return result;
  }

  private OperationResult handleKillTarget(PluginTool tool, Map<String, Object> args)
      throws GhidraMcpException {
    Target target = resolveTarget(tool, args);
    int timeoutMs = getOptionalIntArgument(args, ARG_TIMEOUT_MS).orElse(DEFAULT_TIMEOUT_MS);
    awaitFuture(target.forceTerminateAsync(), "kill target", timeoutMs);
    return OperationResult.success(ACTION_KILL, target.describe(), "Target terminated.");
  }

  private OperationResult handleDisconnectTarget(PluginTool tool, Map<String, Object> args)
      throws GhidraMcpException {
    Target target = resolveTarget(tool, args);
    int timeoutMs = getOptionalIntArgument(args, ARG_TIMEOUT_MS).orElse(DEFAULT_TIMEOUT_MS);
    awaitFuture(target.disconnectAsync(), "disconnect target", timeoutMs);
    return OperationResult.success(ACTION_DISCONNECT, target.describe(), "Target disconnected.");
  }

  private OperationResult handleCloseConnection(PluginTool tool, Map<String, Object> args)
      throws GhidraMcpException {
    TraceRmiConnection connection = resolveConnection(tool, args);
    String description = connection.getDescription();
    try {
      connection.close();
    } catch (IOException e) {
      throw new GhidraMcpException(
          GhidraMcpError.failed("close Trace RMI connection", describeFailure(e)), e);
    }
    return OperationResult.success(
        ACTION_CLOSE_CONNECTION, description, "Trace RMI connection closed.");
  }

  private OperationResult handleCloseTrace(
      PluginTool tool, Map<String, Object> args, boolean saveFirst) throws GhidraMcpException {
    DebuggerTraceManagerService traceService =
        requireService(tool, DebuggerTraceManagerService.class);
    Trace trace = resolveTrace(traceService, args);
    if (saveFirst) {
      int timeoutMs = getOptionalIntArgument(args, ARG_TIMEOUT_MS).orElse(DEFAULT_TIMEOUT_MS);
      awaitFuture(traceService.saveTrace(trace), "save trace", timeoutMs);
    }
    traceService.closeTraceNoConfirm(trace);
    return OperationResult.success(ACTION_CLOSE_TRACE, trace.getName(), "Trace closed.");
  }

  private OperationResult handleSaveTrace(PluginTool tool, Map<String, Object> args)
      throws GhidraMcpException {
    DebuggerTraceManagerService traceService =
        requireService(tool, DebuggerTraceManagerService.class);
    Trace trace = resolveTrace(traceService, args);
    int timeoutMs = getOptionalIntArgument(args, ARG_TIMEOUT_MS).orElse(DEFAULT_TIMEOUT_MS);
    awaitFuture(traceService.saveTrace(trace), "save trace", timeoutMs);
    return OperationResult.success(ACTION_SAVE_TRACE, trace.getName(), "Trace saved.");
  }

  private OperationResult handleCloseDeadTraces(PluginTool tool) throws GhidraMcpException {
    DebuggerTraceManagerService traceService =
        requireService(tool, DebuggerTraceManagerService.class);
    traceService.closeDeadTraces();
    return OperationResult.success(
        ACTION_CLOSE_DEAD_TRACES, "dead_traces", "Dead debugger traces closed.");
  }

  private Map<String, Object> handleGetControlMode(PluginTool tool, Map<String, Object> args)
      throws GhidraMcpException {
    DebuggerTraceManagerService traceService =
        requireService(tool, DebuggerTraceManagerService.class);
    DebuggerControlService controlService = requireService(tool, DebuggerControlService.class);
    Trace trace = resolveTrace(traceService, args);
    ControlMode mode = controlService.getCurrentMode(trace);
    Map<String, Object> info = new LinkedHashMap<>();
    info.put("trace", trace.getName());
    info.put("control_mode", mode.name());
    info.put("follows_present", mode.followsPresent());
    info.put("target_mode", mode.isTarget());
    return info;
  }

  private Map<String, Object> handleSetControlMode(PluginTool tool, Map<String, Object> args)
      throws GhidraMcpException {
    DebuggerTraceManagerService traceService =
        requireService(tool, DebuggerTraceManagerService.class);
    DebuggerControlService controlService = requireService(tool, DebuggerControlService.class);
    Trace trace = resolveTrace(traceService, args);
    ControlMode mode = parseControlMode(getRequiredStringArgument(args, ARG_CONTROL_MODE));
    controlService.setCurrentMode(trace, mode);
    Map<String, Object> info = new LinkedHashMap<>();
    info.put("trace", trace.getName());
    info.put("control_mode", mode.name());
    info.put("follows_present", mode.followsPresent());
    info.put("target_mode", mode.isTarget());
    return info;
  }

  private Object handleSetBreakpoint(PluginTool tool, Map<String, Object> args)
      throws GhidraMcpException {
    DebuggerTraceManagerService traceService =
        requireService(tool, DebuggerTraceManagerService.class);
    DebuggerLogicalBreakpointService breakpointService =
        requireService(tool, DebuggerLogicalBreakpointService.class);
    Trace trace = requireCurrentTrace(traceService);
    Address address = parseCurrentTraceAddress(traceService, args);
    long length = getOptionalIntArgument(args, ARG_LENGTH).orElse(1);
    Set<TraceBreakpointKind> kinds = parseBreakpointKinds(args);
    String name = getOptionalStringArgument(args, ARG_NAME).orElse("");
    int timeoutMs = getOptionalIntArgument(args, ARG_TIMEOUT_MS).orElse(DEFAULT_TIMEOUT_MS);

    awaitFuture(
        breakpointService.placeBreakpointAt(trace, address, length, kinds, name),
        "set breakpoint",
        timeoutMs);

    OperationResult result =
        OperationResult.success(
                ACTION_SET_BREAKPOINT, address.toString(), "Breakpoint placed at " + address + ".")
            .setMetadata(
                Map.of(
                    "length", length,
                    "kinds", kinds.stream().map(Enum::name).collect(Collectors.toList()),
                    "trace", trace.getName()));
    return ToolOutcome.of(result, NavigateDebuggerAddressEffect.listing(address));
  }

  private Object handleSetWatchpoint(PluginTool tool, Map<String, Object> args)
      throws GhidraMcpException {
    if (!args.containsKey(ARG_BREAKPOINT_KINDS)) {
      args = new LinkedHashMap<>(args);
      args.put(ARG_BREAKPOINT_KINDS, List.of("read", "write"));
    }
    return handleSetBreakpoint(tool, args);
  }

  private Object handleSetStaticBreakpoint(
      PluginTool tool, Program program, Map<String, Object> args) throws GhidraMcpException {
    DebuggerLogicalBreakpointService breakpointService =
        requireService(tool, DebuggerLogicalBreakpointService.class);
    Address address =
        parseAddressValue(
            program, getRequiredStringArgument(args, ARG_STATIC_ADDRESS), ARG_STATIC_ADDRESS);
    long length = getOptionalIntArgument(args, ARG_LENGTH).orElse(1);
    Set<TraceBreakpointKind> kinds = parseBreakpointKinds(args);
    String name = getOptionalStringArgument(args, ARG_NAME).orElse("");
    int timeoutMs = getOptionalIntArgument(args, ARG_TIMEOUT_MS).orElse(DEFAULT_TIMEOUT_MS);

    awaitFuture(
        breakpointService.placeBreakpointAt(program, address, length, kinds, name),
        "set static breakpoint",
        timeoutMs);

    OperationResult result =
        OperationResult.success(
                ACTION_SET_STATIC_BREAKPOINT,
                address.toString(),
                "Static breakpoint placed at " + address + ".")
            .setMetadata(
                Map.of(
                    "length", length,
                    "kinds", kinds.stream().map(Enum::name).collect(Collectors.toList()),
                    "program", program.getName()));
    return ToolOutcome.of(result, NavigateToAddressEffect.listing(program, address));
  }

  private List<Map<String, Object>> handleListSupportedBreakpointKinds(PluginTool tool)
      throws GhidraMcpException {
    Target target = requireCurrentTarget(tool);
    List<Map<String, Object>> rows = new ArrayList<>();
    int index = 0;
    for (TraceBreakpointKind kind : target.getSupportedBreakpointKinds()) {
      Map<String, Object> info = new LinkedHashMap<>();
      info.put("kind_index", index++);
      info.put("name", kind.name());
      info.put("tool_value", breakpointKindToolValue(kind));
      rows.add(info);
    }
    return rows;
  }

  private List<Map<String, Object>> handleListBreakpoints(PluginTool tool)
      throws GhidraMcpException {
    DebuggerTraceManagerService traceService =
        requireService(tool, DebuggerTraceManagerService.class);
    DebuggerLogicalBreakpointService breakpointService =
        requireService(tool, DebuggerLogicalBreakpointService.class);
    Trace trace = requireCurrentTrace(traceService);

    List<Map<String, Object>> results = new ArrayList<>();
    breakpointService
        .getBreakpoints(trace)
        .forEach(
            (address, breakpoints) -> {
              for (LogicalBreakpoint breakpoint : breakpoints) {
                results.add(createBreakpointInfo(trace, address, breakpoint));
              }
            });
    return results;
  }

  private Object handleBreakpointMutation(PluginTool tool, Map<String, Object> args, String action)
      throws GhidraMcpException {
    DebuggerTraceManagerService traceService =
        requireService(tool, DebuggerTraceManagerService.class);
    DebuggerLogicalBreakpointService breakpointService =
        requireService(tool, DebuggerLogicalBreakpointService.class);
    Trace trace = requireCurrentTrace(traceService);
    Address address = parseCurrentTraceAddress(traceService, args);
    int timeoutMs = getOptionalIntArgument(args, ARG_TIMEOUT_MS).orElse(DEFAULT_TIMEOUT_MS);

    Set<LogicalBreakpoint> breakpoints = breakpointService.getBreakpointsAt(trace, address);
    if (breakpoints.isEmpty()) {
      throw new GhidraMcpException(GhidraMcpError.notFound("breakpoint", address.toString()));
    }

    CompletableFuture<Void> future =
        switch (action) {
          case ACTION_ENABLE_BREAKPOINT -> breakpointService.enableAll(breakpoints, trace);
          case ACTION_DISABLE_BREAKPOINT -> breakpointService.disableAll(breakpoints, trace);
          case ACTION_DELETE_BREAKPOINT -> breakpointService.deleteAll(breakpoints, trace);
          default -> throw new GhidraMcpException(GhidraMcpError.invalid(ARG_ACTION, action));
        };
    awaitFuture(future, action, timeoutMs);

    OperationResult result =
        OperationResult.success(action, address.toString(), action + " completed at " + address)
            .setMetadata(Map.of("count", breakpoints.size(), "trace", trace.getName()));
    return ToolOutcome.of(result, NavigateDebuggerAddressEffect.listing(address));
  }

  private OperationResult handleGoToAddress(PluginTool tool, Map<String, Object> args)
      throws GhidraMcpException {
    DebuggerTraceManagerService traceService =
        requireService(tool, DebuggerTraceManagerService.class);
    Address address = parseCurrentTraceAddress(traceService, args);
    GhidraUiCoordinator.applyRequired(tool, NavigateDebuggerAddressEffect.listing(address));
    return OperationResult.success(
        ACTION_GO_TO_ADDRESS, address.toString(), "Debugger navigation completed successfully.");
  }

  private Object handleReadMemory(PluginTool tool, Map<String, Object> args, boolean allowRefresh)
      throws GhidraMcpException {
    DebuggerTraceManagerService traceService =
        requireService(tool, DebuggerTraceManagerService.class);
    DebuggerCoordinates coordinates = requireCurrentCoordinates(traceService);
    Address address = parseCurrentTraceAddress(traceService, args);
    int length = getMemoryLength(args, true);
    Target target = coordinates.getTarget();
    boolean refresh =
        allowRefresh && getOptionalBooleanArgument(args, ARG_REFRESH).orElse(target != null);
    if (refresh) {
      if (target == null || !target.isValid()) {
        throw new GhidraMcpException(
            GhidraMcpError.failed("refresh memory", "no live target is selected"));
      }
      refreshTargetMemory(target, address, length, args);
    }

    Map<String, Object> result =
        readTraceBytes(coordinates.getTrace(), coordinates.getSnap(), address, length);
    result.put("action", allowRefresh ? ACTION_READ_MEMORY : ACTION_READ_TRACE_BYTES);
    result.put("trace", coordinates.getTrace().getName());
    result.put("snap", coordinates.getSnap());
    result.put("refreshed", refresh);
    return ToolOutcome.of(result, NavigateDebuggerAddressEffect.listing(address));
  }

  private Object handleRefreshMemory(PluginTool tool, Map<String, Object> args)
      throws GhidraMcpException {
    Target target = resolveTarget(tool, args);
    DebuggerTraceManagerService traceService =
        requireService(tool, DebuggerTraceManagerService.class);
    Address address = parseCurrentTraceAddress(traceService, args);
    int length = getMemoryLength(args, true);
    refreshTargetMemory(target, address, length, args);
    OperationResult result =
        OperationResult.success(
                ACTION_REFRESH_MEMORY,
                address.toString(),
                "Target memory refreshed into the active trace.")
            .setMetadata(Map.of("length", length, "target", target.describe()));
    return ToolOutcome.of(result, NavigateDebuggerAddressEffect.listing(address));
  }

  private Object handleWriteMemory(PluginTool tool, Map<String, Object> args)
      throws GhidraMcpException {
    Target target = resolveTarget(tool, args);
    DebuggerTraceManagerService traceService =
        requireService(tool, DebuggerTraceManagerService.class);
    Address address = parseCurrentTraceAddress(traceService, args);
    byte[] bytes = parseBytesHex(getRequiredStringArgument(args, ARG_BYTES_HEX), ARG_BYTES_HEX);
    int timeoutMs = getOptionalIntArgument(args, ARG_TIMEOUT_MS).orElse(DEFAULT_TIMEOUT_MS);
    awaitFuture(target.writeMemoryAsync(address, bytes), "write target memory", timeoutMs);
    OperationResult result =
        OperationResult.success(
                ACTION_WRITE_MEMORY, address.toString(), "Target memory write completed.")
            .setMetadata(Map.of("length", bytes.length, "target", target.describe()));
    return ToolOutcome.of(result, NavigateDebuggerAddressEffect.listing(address));
  }

  private OperationResult handleInvalidateMemoryCache(PluginTool tool, Map<String, Object> args)
      throws GhidraMcpException {
    Target target = resolveTarget(tool, args);
    int timeoutMs = getOptionalIntArgument(args, ARG_TIMEOUT_MS).orElse(DEFAULT_TIMEOUT_MS);
    awaitFuture(target.invalidateMemoryCachesAsync(), "invalidate target memory cache", timeoutMs);
    return OperationResult.success(
        ACTION_INVALIDATE_MEMORY_CACHE, target.describe(), "Target memory caches invalidated.");
  }

  private Object handleWriteTraceBytes(PluginTool tool, Map<String, Object> args)
      throws GhidraMcpException {
    DebuggerTraceManagerService traceService =
        requireService(tool, DebuggerTraceManagerService.class);
    DebuggerCoordinates coordinates = requireCurrentCoordinates(traceService);
    Address address = parseCurrentTraceAddress(traceService, args);
    byte[] bytes = parseBytesHex(getRequiredStringArgument(args, ARG_BYTES_HEX), ARG_BYTES_HEX);
    try (db.Transaction tx = coordinates.getTrace().openTransaction("MCP - Write trace bytes")) {
      coordinates
          .getTrace()
          .getMemoryManager()
          .putBytes(coordinates.getSnap(), address, ByteBuffer.wrap(bytes));
      coordinates
          .getTrace()
          .getMemoryManager()
          .setState(
              coordinates.getSnap(),
              new AddressSet(address, address.add(bytes.length - 1)),
              TraceMemoryState.KNOWN);
      tx.commit();
    } catch (Exception e) {
      throw new GhidraMcpException(
          GhidraMcpError.failed("write trace bytes", describeFailure(e)), e);
    }
    OperationResult result =
        OperationResult.success(
                ACTION_WRITE_TRACE_BYTES, address.toString(), "Trace bytes updated.")
            .setMetadata(Map.of("length", bytes.length, "trace", coordinates.getTrace().getName()));
    return ToolOutcome.of(result, NavigateDebuggerAddressEffect.listing(address));
  }

  private Object handleGetMemoryState(PluginTool tool, Map<String, Object> args)
      throws GhidraMcpException {
    DebuggerTraceManagerService traceService =
        requireService(tool, DebuggerTraceManagerService.class);
    DebuggerCoordinates coordinates = requireCurrentCoordinates(traceService);
    Address address = parseCurrentTraceAddress(traceService, args);
    int length = getMemoryLength(args, false);
    Map<String, Object> info = new LinkedHashMap<>();
    info.put("trace", coordinates.getTrace().getName());
    info.put("snap", coordinates.getSnap());
    info.put("address", address.toString());
    info.put("length", length);
    info.put(
        "state",
        coordinates
            .getTrace()
            .getMemoryManager()
            .getViewState(coordinates.getSnap(), address)
            .getValue()
            .name());
    if (length > 1) {
      Address end = addBytes(address, length - 1, ARG_LENGTH);
      info.put("end_address", end.toString());
      info.put(
          "end_state",
          coordinates
              .getTrace()
              .getMemoryManager()
              .getViewState(coordinates.getSnap(), end)
              .getValue()
              .name());
    }
    return ToolOutcome.of(info, NavigateDebuggerAddressEffect.listing(address));
  }

  private Object handleSetMemoryState(PluginTool tool, Map<String, Object> args)
      throws GhidraMcpException {
    DebuggerTraceManagerService traceService =
        requireService(tool, DebuggerTraceManagerService.class);
    DebuggerCoordinates coordinates = requireCurrentCoordinates(traceService);
    Address address = parseCurrentTraceAddress(traceService, args);
    int length = getMemoryLength(args, true);
    TraceMemoryState state = parseMemoryState(getRequiredStringArgument(args, ARG_MEMORY_STATE));
    try (db.Transaction tx =
        coordinates.getTrace().openTransaction("MCP - Set trace memory state")) {
      coordinates
          .getTrace()
          .getMemoryManager()
          .setState(coordinates.getSnap(), new AddressSet(address, address.add(length - 1)), state);
      tx.commit();
    } catch (Exception e) {
      throw new GhidraMcpException(
          GhidraMcpError.failed("set trace memory state", describeFailure(e)), e);
    }
    OperationResult result =
        OperationResult.success(
                ACTION_SET_MEMORY_STATE, address.toString(), "Trace memory state updated.")
            .setMetadata(
                Map.of(
                    "length", length,
                    "state", state.name(),
                    "trace", coordinates.getTrace().getName()));
    return ToolOutcome.of(result, NavigateDebuggerAddressEffect.listing(address));
  }

  private CursorDataResult<List<Map<String, Object>>> handleListMemoryRegions(
      PluginTool tool, Map<String, Object> args) throws GhidraMcpException {
    DebuggerTraceManagerService traceService =
        requireService(tool, DebuggerTraceManagerService.class);
    DebuggerCoordinates coordinates = requireCurrentCoordinates(traceService);
    long snap = getOptionalLongArgument(args, ARG_SNAP).orElse(coordinates.getSnap());
    List<TraceMemoryRegion> regions =
        new ArrayList<>(coordinates.getTrace().getMemoryManager().getRegionsAtSnap(snap));
    regions.sort(Comparator.comparing(region -> region.getMinAddress(snap)));
    List<Map<String, Object>> rows = new ArrayList<>(regions.size());
    for (int i = 0; i < regions.size(); i++) {
      rows.add(createMemoryRegionInfo(i, regions.get(i), snap));
    }
    return pageRows(rows, args, "v1:<base64url_memory_region_offset>");
  }

  private OperationResult handleSelectRange(PluginTool tool, Map<String, Object> args)
      throws GhidraMcpException {
    DebuggerTraceManagerService traceService =
        requireService(tool, DebuggerTraceManagerService.class);
    DebuggerListingService listingService = requireService(tool, DebuggerListingService.class);
    Address address = parseCurrentTraceAddress(traceService, args);
    int length = getMemoryLength(args, true);
    try {
      listingService.setCurrentSelection(
          new ProgramSelection(new AddressSet(address, address.add(length - 1))));
    } catch (Exception e) {
      throw new GhidraMcpException(
          GhidraMcpError.failed("select debugger range", describeFailure(e)), e);
    }
    return OperationResult.success(
            ACTION_SELECT_RANGE, address.toString(), "Debugger listing range selected.")
        .setMetadata(Map.of("length", length));
  }

  private CursorDataResult<List<Map<String, Object>>> handleListTrackingSpecs(
      PluginTool tool, Map<String, Object> args) throws GhidraMcpException {
    DebuggerListingService listingService = requireService(tool, DebuggerListingService.class);
    Map<String, LocationTrackingSpec> specs = LocationTrackingSpecFactory.allSuggested(tool);
    LocationTrackingSpec current = listingService.getTrackingSpec();
    List<LocationTrackingSpec> ordered = new ArrayList<>(specs.values());
    ordered.sort(
        Comparator.comparing(LocationTrackingSpec::getConfigName, String.CASE_INSENSITIVE_ORDER));
    List<Map<String, Object>> rows = new ArrayList<>();
    for (int i = 0; i < ordered.size(); i++) {
      LocationTrackingSpec spec = ordered.get(i);
      Map<String, Object> info = new LinkedHashMap<>();
      info.put("tracking_spec_index", i);
      info.put("config_name", spec.getConfigName());
      info.put("menu_name", spec.getMenuName());
      info.put("location_label", spec.getLocationLabel());
      info.put("current", current != null && current.getConfigName().equals(spec.getConfigName()));
      rows.add(info);
    }
    return pageRows(rows, args, "v1:<base64url_tracking_spec_offset>");
  }

  private Map<String, Object> handleSetTrackingSpec(PluginTool tool, Map<String, Object> args)
      throws GhidraMcpException {
    DebuggerListingService listingService = requireService(tool, DebuggerListingService.class);
    String configName = getRequiredStringArgument(args, ARG_TRACKING_SPEC);
    LocationTrackingSpec spec = LocationTrackingSpecFactory.fromConfigName(configName);
    if (spec == null) {
      throw new GhidraMcpException(GhidraMcpError.notFound("tracking spec", configName));
    }
    listingService.setTrackingSpec(spec);
    Map<String, Object> info = new LinkedHashMap<>();
    info.put("config_name", spec.getConfigName());
    info.put("menu_name", spec.getMenuName());
    info.put("location_label", spec.getLocationLabel());
    return info;
  }

  private Mono<? extends Object> handleMapDataType(PluginTool tool, Map<String, Object> args) {
    try {
      DebuggerTraceManagerService traceService =
          requireService(tool, DebuggerTraceManagerService.class);
      TraceProgramView view = requireCurrentView(traceService);
      Address address = parseCurrentTraceAddress(traceService, args);

      return executeInTransaction(
          view,
          "MCP - Map debugger data type at " + address,
          () -> {
            DataType dataType = resolveRequestedDataType(view.getDataTypeManager(), args, true);
            int maxFields =
                getBoundedInt(args, ARG_MAX_FIELDS, DEFAULT_MAX_FIELDS, MAX_FIELDS_LIMIT);
            int fieldOffset = getIndexCursorOffset(args, "v1:<base64url_typed_field_offset>");

            CursorDataResult<?> result =
                TypedMemoryMapper.applyAndMap(view, address, dataType, maxFields, fieldOffset);
            return ToolOutcome.of(result, NavigateDebuggerAddressEffect.listing(address));
          });
    } catch (GhidraMcpException e) {
      return Mono.error(e);
    }
  }

  private CursorDataResult<List<Map<String, Object>>> handleListRegisters(
      PluginTool tool, Map<String, Object> args, boolean includeValues) throws GhidraMcpException {
    DebuggerTraceManagerService traceService =
        requireService(tool, DebuggerTraceManagerService.class);
    DebuggerCoordinates coordinates = requireCurrentCoordinates(traceService);
    List<Register> registers = selectRegisters(coordinates, args);
    int maxRegisters =
        getBoundedInt(args, ARG_MAX_REGISTERS, DEFAULT_MAX_REGISTERS, MAX_REGISTERS_LIMIT);
    int registerOffset = getIndexCursorOffset(args, "v1:<base64url_register_offset>");
    if (registerOffset > registers.size()) {
      throw new GhidraMcpException(
          GhidraMcpError.invalid(ARG_CURSOR, args.get(ARG_CURSOR), "cursor is past register list"));
    }

    int endExclusive = Math.min(registers.size(), registerOffset + maxRegisters);
    List<Register> page = registers.subList(registerOffset, endExclusive);

    if (includeValues) {
      refreshRegistersIfRequested(coordinates, page, args);
    }

    List<Map<String, Object>> rows =
        page.stream()
            .map(register -> createRegisterInfo(coordinates, register, includeValues))
            .collect(Collectors.toList());
    String nextCursor =
        endExclusive < registers.size()
            ? OpaqueCursorCodec.encodeV1(String.valueOf(endExclusive))
            : null;
    return new CursorDataResult<>(rows, nextCursor);
  }

  private OperationResult handleWriteRegister(PluginTool tool, Map<String, Object> args)
      throws GhidraMcpException {
    DebuggerTraceManagerService traceService =
        requireService(tool, DebuggerTraceManagerService.class);
    DebuggerControlService controlService = requireService(tool, DebuggerControlService.class);
    DebuggerCoordinates coordinates = requireCurrentCoordinates(traceService);
    Register register =
        resolveRegister(coordinates, getRequiredStringArgument(args, ARG_REGISTER_NAME));
    String valueString = getRequiredStringArgument(args, ARG_VALUE);
    int timeoutMs = getOptionalIntArgument(args, ARG_TIMEOUT_MS).orElse(DEFAULT_TIMEOUT_MS);

    DebuggerControlService.StateEditor editor = controlService.createStateEditor(coordinates);
    if (!editor.isRegisterEditable(register)) {
      throw new GhidraMcpException(
          GhidraMcpError.failed("write register", register.getName() + " is not editable"));
    }

    RegisterValue value = new RegisterValue(register, parseIntegerValue(valueString));
    awaitFuture(editor.setRegister(value), "write register", timeoutMs);

    return OperationResult.success(
            ACTION_WRITE_REGISTER,
            register.getName(),
            "Register " + register.getName() + " updated.")
        .setMetadata(Map.of("value", valueString));
  }

  private CursorDataResult<List<Map<String, Object>>> handleListWatches(
      PluginTool tool, Map<String, Object> args) throws GhidraMcpException {
    DebuggerWatchesService watchesService = requireService(tool, DebuggerWatchesService.class);
    List<WatchRow> rows = watchRows(watchesService);
    int maxWatches = getBoundedInt(args, ARG_MAX_WATCHES, DEFAULT_MAX_WATCHES, MAX_WATCHES_LIMIT);
    int watchOffset = getIndexCursorOffset(args, "v1:<base64url_watch_offset>");
    if (watchOffset > rows.size()) {
      throw new GhidraMcpException(
          GhidraMcpError.invalid(ARG_CURSOR, args.get(ARG_CURSOR), "cursor is past watch list"));
    }

    int endExclusive = Math.min(rows.size(), watchOffset + maxWatches);
    List<Map<String, Object>> results = new ArrayList<>(endExclusive - watchOffset);
    for (int i = watchOffset; i < endExclusive; i++) {
      results.add(createWatchInfo(i, rows.get(i)));
    }
    String nextCursor =
        endExclusive < rows.size()
            ? OpaqueCursorCodec.encodeV1(String.valueOf(endExclusive))
            : null;
    return new CursorDataResult<>(results, nextCursor);
  }

  private Object handleAddWatch(PluginTool tool, Map<String, Object> args)
      throws GhidraMcpException {
    DebuggerWatchesService watchesService = requireService(tool, DebuggerWatchesService.class);
    String expression = getRequiredStringArgument(args, ARG_EXPRESSION);
    WatchRow row = watchesService.addWatch(expression);
    applyWatchOptions(tool, row, args, false);
    Map<String, Object> info = createWatchInfo(watchRows(watchesService).indexOf(row), row);
    return watchOutcome(row, info);
  }

  private Object handleUpdateWatch(PluginTool tool, Map<String, Object> args)
      throws GhidraMcpException {
    DebuggerWatchesService watchesService = requireService(tool, DebuggerWatchesService.class);
    WatchRow row = requireWatch(watchesService, getRequiredIntArgument(args, ARG_WATCH_INDEX));
    Optional<String> expression = getOptionalStringArgument(args, ARG_EXPRESSION);
    expression.ifPresent(row::setExpression);
    applyWatchOptions(tool, row, args, true);
    Map<String, Object> info = createWatchInfo(watchRows(watchesService).indexOf(row), row);
    return watchOutcome(row, info);
  }

  private OperationResult handleRemoveWatch(PluginTool tool, Map<String, Object> args)
      throws GhidraMcpException {
    DebuggerWatchesService watchesService = requireService(tool, DebuggerWatchesService.class);
    int index = getRequiredIntArgument(args, ARG_WATCH_INDEX);
    WatchRow row = requireWatch(watchesService, index);
    String expression = row.getExpression();
    watchesService.removeWatch(row);
    return OperationResult.success(
        ACTION_REMOVE_WATCH, String.valueOf(index), "Removed watch '" + expression + "'.");
  }

  private void applyWatchOptions(
      PluginTool tool, WatchRow row, Map<String, Object> args, boolean allowValueUpdate)
      throws GhidraMcpException {
    if (args.containsKey(ARG_DATA_TYPE_PATH) || args.containsKey(ARG_DATA_TYPE_ID)) {
      DataType dataType = resolveRequestedDataType(currentDataTypeManager(tool), args, true);
      row.setDataType(dataType);
    }
    getOptionalStringArgument(args, ARG_COMMENT).ifPresent(row::setComment);
    Optional<String> valueOpt = getOptionalStringArgument(args, ARG_VALUE);
    if (allowValueUpdate && valueOpt.isPresent()) {
      if (row.isValueEditable()) {
        row.setValueString(valueOpt.get());
      } else if (row.isRawValueEditable()) {
        row.setRawValueString(valueOpt.get());
      } else {
        throw new GhidraMcpException(
            GhidraMcpError.failed("update watch", "watch value is not editable"));
      }
    }
    row.settingsChanged();
  }

  private Target.ActionEntry selectTargetAction(Target target, ActionName actionName)
      throws GhidraMcpException {
    Collection<Target.ActionEntry> entries =
        target
            .collectActions(actionName, null, Target.ObjectArgumentPolicy.CURRENT_AND_RELATED)
            .values();

    Target.ActionEntry entry =
        entries.stream()
            .filter(Target.ActionEntry::isEnabled)
            .filter(candidate -> !candidate.requiresPrompt())
            .max(Comparator.comparingLong(Target.ActionEntry::specificity))
            .orElse(null);
    if (entry == null) {
      throw new GhidraMcpException(
          GhidraMcpError.failed(
              "find debugger action " + actionName.name(),
              "no enabled non-interactive action is available for the current target"));
    }
    return entry;
  }

  private Map<String, Object> createBreakpointInfo(
      Trace trace, Address address, LogicalBreakpoint breakpoint) {
    Map<String, Object> info = new LinkedHashMap<>();
    info.put("address", address.toString());
    info.put("name", breakpoint.getName());
    info.put("length", breakpoint.getLength());
    info.put("kinds", breakpoint.getKinds().stream().map(Enum::name).collect(Collectors.toList()));
    LogicalBreakpoint.State state = breakpoint.computeStateForTrace(trace);
    info.put("state", state.name());
    info.put("enabled", state.isEnabled());
    info.put("effective", state.isEffective());
    return info;
  }

  private SocketAddress resolveSocketAddress(
      Map<String, Object> args, SocketAddress defaultAddress, boolean requirePort)
      throws GhidraMcpException {
    Optional<String> hostOpt = getOptionalStringArgument(args, ARG_HOST);
    Optional<Integer> portOpt = getOptionalIntArgument(args, ARG_PORT);
    if (hostOpt.isEmpty() && portOpt.isEmpty()) {
      if (defaultAddress != null) {
        return defaultAddress;
      }
      if (!requirePort) {
        return null;
      }
    }

    String host =
        hostOpt.orElseGet(
            () ->
                defaultAddress instanceof InetSocketAddress inet
                    ? inet.getHostString()
                    : "127.0.0.1");
    int port =
        portOpt.orElseGet(
            () -> defaultAddress instanceof InetSocketAddress inet ? inet.getPort() : -1);
    if (port < 0 || port > 65535 || (requirePort && port == 0)) {
      throw new GhidraMcpException(
          GhidraMcpError.invalid(ARG_PORT, port, "must be between 1 and 65535"));
    }
    return new InetSocketAddress(host, port);
  }

  private String describeSocketAddress(SocketAddress address) {
    if (address == null) {
      return null;
    }
    if (address instanceof InetSocketAddress inet) {
      return inet.getHostString() + ":" + inet.getPort();
    }
    return address.toString();
  }

  private Map<String, Object> createConnectionInfo(int index, TraceRmiConnection connection) {
    Map<String, Object> info = new LinkedHashMap<>();
    info.put("connection_index", index);
    info.put("description", connection.getDescription());
    info.put("remote_address", describeSocketAddress(connection.getRemoteAddress()));
    info.put("closed", connection.isClosed());
    info.put("busy", connection.isBusy());
    List<Target> targets = new ArrayList<>(connection.getTargets());
    info.put("target_count", targets.size());
    info.put("targets", indexedRows(targets, this::createTargetInfo));
    return info;
  }

  private int indexOfConnection(TraceRmiService service, TraceRmiConnection connection) {
    List<TraceRmiConnection> connections = new ArrayList<>(service.getAllConnections());
    return connections.indexOf(connection);
  }

  private Map<String, Object> createAcceptorInfo(int index, TraceRmiAcceptor acceptor) {
    Map<String, Object> info = new LinkedHashMap<>();
    info.put("acceptor_index", index);
    info.put("address", describeSocketAddress(acceptor.getAddress()));
    info.put("closed", acceptor.isClosed());
    return info;
  }

  private int indexOfAcceptor(TraceRmiService service, TraceRmiAcceptor acceptor) {
    List<TraceRmiAcceptor> acceptors = new ArrayList<>(service.getAllAcceptors());
    return acceptors.indexOf(acceptor);
  }

  private <T> List<Map<String, Object>> indexedRows(List<T> values, IndexedInfo<T> infoFactory) {
    List<Map<String, Object>> rows = new ArrayList<>(values.size());
    for (int i = 0; i < values.size(); i++) {
      rows.add(infoFactory.create(i, values.get(i)));
    }
    return rows;
  }

  private CursorDataResult<List<Map<String, Object>>> pageRows(
      List<Map<String, Object>> rows, Map<String, Object> args, String expectedFormat)
      throws GhidraMcpException {
    int pageSize = getBoundedInt(args, ARG_PAGE_SIZE, DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE);
    int offset = getIndexCursorOffset(args, expectedFormat);
    if (offset > rows.size()) {
      throw new GhidraMcpException(
          GhidraMcpError.invalid(ARG_CURSOR, args.get(ARG_CURSOR), "cursor is past result list"));
    }
    int endExclusive = Math.min(rows.size(), offset + pageSize);
    String nextCursor =
        endExclusive < rows.size()
            ? OpaqueCursorCodec.encodeV1(String.valueOf(endExclusive))
            : null;
    return new CursorDataResult<>(new ArrayList<>(rows.subList(offset, endExclusive)), nextCursor);
  }

  private Map<String, Object> createTraceInfo(int index, Trace trace) {
    Map<String, Object> info = new LinkedHashMap<>();
    info.put("trace_index", index);
    info.put("name", trace.getName());
    info.put("language", trace.getBaseLanguage().getLanguageID().getIdAsString());
    info.put("compiler_spec", trace.getBaseCompilerSpec().getCompilerSpecID().getIdAsString());
    return info;
  }

  private int indexOfTrace(DebuggerTraceManagerService traceService, Trace trace) {
    return new ArrayList<>(traceService.getOpenTraces()).indexOf(trace);
  }

  private Trace resolveTrace(DebuggerTraceManagerService traceService, Map<String, Object> args)
      throws GhidraMcpException {
    List<Trace> traces = new ArrayList<>(traceService.getOpenTraces());
    Optional<Integer> indexOpt = getOptionalIntArgument(args, ARG_TRACE_INDEX);
    if (indexOpt.isPresent()) {
      int index = indexOpt.get();
      if (index < 0 || index >= traces.size()) {
        throw new GhidraMcpException(GhidraMcpError.notFound("trace", "index=" + index));
      }
      return traces.get(index);
    }
    Optional<String> nameOpt = getOptionalStringArgument(args, ARG_TRACE_NAME);
    if (nameOpt.isPresent()) {
      String name = nameOpt.get();
      return traces.stream()
          .filter(trace -> trace.getName().equals(name))
          .findFirst()
          .orElseThrow(() -> new GhidraMcpException(GhidraMcpError.notFound("trace", name)));
    }
    Trace current = traceService.getCurrentTrace();
    if (current != null) {
      return current;
    }
    if (traces.size() == 1) {
      return traces.get(0);
    }
    throw new GhidraMcpException(
        GhidraMcpError.validation()
            .message("Provide trace_index or trace_name; no unique current trace is selected.")
            .build());
  }

  private List<Target> allTargets(PluginTool tool) throws GhidraMcpException {
    TraceRmiService rmiService = requireService(tool, TraceRmiService.class);
    LinkedHashSet<Target> targets = new LinkedHashSet<>();
    for (TraceRmiConnection connection : rmiService.getAllConnections()) {
      targets.addAll(connection.getTargets());
    }
    return new ArrayList<>(targets);
  }

  private Map<String, Object> createTargetInfo(int index, Target target) {
    Map<String, Object> info = new LinkedHashMap<>();
    info.put("target_index", index);
    info.put("description", target.describe());
    info.put("valid", target.isValid());
    info.put("busy", target.isBusy());
    return info;
  }

  private Target resolveTarget(PluginTool tool, Map<String, Object> args)
      throws GhidraMcpException {
    List<Target> targets = allTargets(tool);
    Optional<Integer> indexOpt = getOptionalIntArgument(args, ARG_TARGET_INDEX);
    if (indexOpt.isPresent()) {
      int index = indexOpt.get();
      if (index < 0 || index >= targets.size()) {
        throw new GhidraMcpException(GhidraMcpError.notFound("target", "index=" + index));
      }
      return targets.get(index);
    }
    DebuggerTraceManagerService traceService =
        requireService(tool, DebuggerTraceManagerService.class);
    Target current =
        traceService.getCurrent() != null ? traceService.getCurrent().getTarget() : null;
    if (current != null && current.isValid()) {
      return current;
    }
    if (targets.size() == 1) {
      return targets.get(0);
    }
    throw new GhidraMcpException(
        GhidraMcpError.validation()
            .message("Provide target_index; no unique current target is selected.")
            .build());
  }

  private int resolveTargetIndex(PluginTool tool, Target target) throws GhidraMcpException {
    return allTargets(tool).indexOf(target);
  }

  private TraceThread resolveThread(Trace trace, long snap, Map<String, Object> args)
      throws GhidraMcpException {
    Optional<Long> keyOpt = getOptionalLongArgument(args, ARG_THREAD_KEY);
    if (keyOpt.isPresent()) {
      TraceThread thread = trace.getThreadManager().getThread(keyOpt.get());
      if (thread == null) {
        throw new GhidraMcpException(GhidraMcpError.notFound("thread", "key=" + keyOpt.get()));
      }
      return thread;
    }
    Optional<String> pathOpt = getOptionalStringArgument(args, ARG_THREAD_PATH);
    if (pathOpt.isPresent()) {
      TraceThread thread = trace.getThreadManager().getLiveThreadByPath(snap, pathOpt.get());
      if (thread == null) {
        throw new GhidraMcpException(GhidraMcpError.notFound("thread", pathOpt.get()));
      }
      return thread;
    }
    Collection<? extends TraceThread> live = trace.getThreadManager().getLiveThreads(snap);
    if (live.size() == 1) {
      return live.iterator().next();
    }
    throw new GhidraMcpException(
        GhidraMcpError.validation()
            .message("Provide thread_key or thread_path; no unique live thread is selected.")
            .build());
  }

  private Map<String, Object> createThreadInfo(TraceThread thread, long snap) {
    Map<String, Object> info = new LinkedHashMap<>();
    info.put("key", thread.getKey());
    info.put("path", thread.getPath());
    putIfNotNull(info, "name", thread.getName(snap));
    putIfNotNull(info, "comment", thread.getComment(snap));
    return info;
  }

  private Map<String, Object> createModuleInfo(int index, TraceModule module, long snap) {
    Map<String, Object> info = new LinkedHashMap<>();
    info.put("module_index", index);
    info.put("path", module.getPath());
    putIfNotNull(info, "name", module.getName(snap));
    AddressRange range = module.getRange(snap);
    if (range != null) {
      info.put("range", range.toString());
      info.put("base", range.getMinAddress().toString());
      info.put("max_address", range.getMaxAddress().toString());
      info.put("length", range.getLength());
    }
    return info;
  }

  private Map<String, Object> createLaunchOfferInfo(int index, TraceRmiLaunchOffer offer) {
    Map<String, Object> info = new LinkedHashMap<>();
    info.put("launcher_index", index);
    info.put("config_name", offer.getConfigName());
    info.put("title", offer.getTitle());
    info.put("description", offer.getDescription());
    info.put("menu_path", offer.getMenuPath());
    info.put("supports_image", offer.supportsImage());
    info.put("requires_image", offer.requiresImage());
    List<Map<String, Object>> parameters = new ArrayList<>();
    for (Map.Entry<String, LaunchParameter<?>> entry : offer.getParameters().entrySet()) {
      parameters.add(createLaunchParameterInfo(entry.getKey(), entry.getValue()));
    }
    info.put("parameters", parameters);
    return info;
  }

  private Map<String, Object> createLaunchParameterInfo(String key, LaunchParameter<?> parameter) {
    Map<String, Object> info = new LinkedHashMap<>();
    info.put("name", key);
    info.put("display", parameter.display());
    info.put("description", parameter.description());
    info.put("type", parameter.type().getSimpleName());
    info.put("required", parameter.required());
    putIfNotNull(
        info,
        "default",
        parameter.defaultValue() != null ? parameter.defaultValue().normStr() : null);
    if (parameter.choices() != null && !parameter.choices().isEmpty()) {
      info.put("choices", parameter.choices().stream().map(String::valueOf).toList());
    }
    return info;
  }

  private TraceRmiLaunchOffer resolveLaunchOffer(
      TraceRmiLauncherService service, Program program, Map<String, Object> args)
      throws GhidraMcpException {
    List<TraceRmiLaunchOffer> offers = new ArrayList<>(service.getOffers(program));
    offers.sort(
        Comparator.comparing(TraceRmiLaunchOffer::getTitle, String.CASE_INSENSITIVE_ORDER)
            .thenComparing(TraceRmiLaunchOffer::getConfigName, String.CASE_INSENSITIVE_ORDER));
    Optional<Integer> indexOpt = getOptionalIntArgument(args, ARG_LAUNCHER_INDEX);
    if (indexOpt.isPresent()) {
      int index = indexOpt.get();
      if (index < 0 || index >= offers.size()) {
        throw new GhidraMcpException(GhidraMcpError.notFound("launcher", "index=" + index));
      }
      return offers.get(index);
    }
    Optional<String> nameOpt = getOptionalStringArgument(args, ARG_LAUNCHER_NAME);
    if (nameOpt.isPresent()) {
      String name = nameOpt.get();
      return offers.stream()
          .filter(
              offer ->
                  offer.getConfigName().equals(name) || offer.getTitle().equalsIgnoreCase(name))
          .findFirst()
          .orElseThrow(() -> new GhidraMcpException(GhidraMcpError.notFound("launcher", name)));
    }
    if (offers.size() == 1) {
      return offers.get(0);
    }
    throw new GhidraMcpException(
        GhidraMcpError.validation()
            .message("Provide launcher_index or launcher_name; no unique launcher is available.")
            .build());
  }

  private TraceRmiLaunchOffer.LaunchConfigurator launchConfigurator(
      TraceRmiLaunchOffer offer, Map<String, Object> args) throws GhidraMcpException {
    Map<String, ValStr<?>> overrides = decodeLaunchArguments(offer, args);
    return new TraceRmiLaunchOffer.LaunchConfigurator() {
      @Override
      public Map<String, ValStr<?>> configureLauncher(
          TraceRmiLaunchOffer launchOffer,
          Map<String, ValStr<?>> defaults,
          TraceRmiLaunchOffer.RelPrompt relPrompt) {
        Map<String, ValStr<?>> configured = new LinkedHashMap<>(defaults);
        configured.putAll(overrides);
        return LaunchParameter.validateArguments(launchOffer.getParameters(), configured);
      }
    };
  }

  private Map<String, ValStr<?>> decodeLaunchArguments(
      TraceRmiLaunchOffer offer, Map<String, Object> args) throws GhidraMcpException {
    Map<String, Object> rawArguments =
        getOptionalMapArgument(args, ARG_LAUNCH_ARGUMENTS).orElse(Map.of());
    Map<String, ValStr<?>> decoded = new LinkedHashMap<>();
    for (Map.Entry<String, Object> entry : rawArguments.entrySet()) {
      LaunchParameter<?> parameter = offer.getParameters().get(entry.getKey());
      if (parameter == null) {
        throw new GhidraMcpException(
            GhidraMcpError.invalid(
                ARG_LAUNCH_ARGUMENTS, entry.getKey(), "not a parameter for this launcher"));
      }
      try {
        decoded.put(entry.getKey(), parameter.decode(String.valueOf(entry.getValue())));
      } catch (Exception e) {
        throw new GhidraMcpException(
            GhidraMcpError.invalid(
                ARG_LAUNCH_ARGUMENTS,
                entry.getKey(),
                "could not decode value: " + describeFailure(e)),
            e);
      }
    }
    return decoded;
  }

  private Lifespan mappingLifespan(Map<String, Object> args, long currentSnap) {
    long snap = getOptionalLongArgument(args, ARG_SNAP).orElse(currentSnap);
    return Lifespan.since(snap);
  }

  private TraceModule resolveModule(Trace trace, long snap, Map<String, Object> args)
      throws GhidraMcpException {
    Optional<String> pathOpt = getOptionalStringArgument(args, ARG_MODULE_PATH);
    if (pathOpt.isPresent()) {
      TraceModule module = trace.getModuleManager().getLoadedModuleByPath(snap, pathOpt.get());
      if (module == null) {
        throw new GhidraMcpException(GhidraMcpError.notFound("module", pathOpt.get()));
      }
      return module;
    }

    Optional<String> nameOpt = getOptionalStringArgument(args, ARG_MODULE_NAME);
    if (nameOpt.isPresent()) {
      String name = nameOpt.get();
      List<TraceModule> matches =
          trace.getModuleManager().getLoadedModules(snap).stream()
              .filter(module -> name.equalsIgnoreCase(safeString(module.getName(snap))))
              .collect(Collectors.toList());
      if (matches.size() == 1) {
        return matches.get(0);
      }
      if (matches.isEmpty()) {
        throw new GhidraMcpException(GhidraMcpError.notFound("module", name));
      }
      throw new GhidraMcpException(
          GhidraMcpError.invalid(ARG_MODULE_NAME, name, "matches multiple loaded modules"));
    }

    Optional<String> addressOpt = getOptionalStringArgument(args, ARG_ADDRESS);
    if (addressOpt.isPresent()) {
      Address address = parseAddressValue(trace.getProgramView(), addressOpt.get(), ARG_ADDRESS);
      Collection<? extends TraceModule> modules =
          trace.getModuleManager().getModulesAt(snap, address);
      if (modules.size() == 1) {
        return modules.iterator().next();
      }
      if (modules.isEmpty()) {
        throw new GhidraMcpException(
            GhidraMcpError.notFound("module at address", address.toString()));
      }
      throw new GhidraMcpException(
          GhidraMcpError.invalid(ARG_ADDRESS, addressOpt.get(), "address is in multiple modules"));
    }

    Collection<? extends TraceModule> loaded = trace.getModuleManager().getLoadedModules(snap);
    if (loaded.size() == 1) {
      return loaded.iterator().next();
    }
    throw new GhidraMcpException(
        GhidraMcpError.validation()
            .message("Provide module_path, module_name, or address; no unique module is loaded.")
            .build());
  }

  private Map<String, Object> createModuleProposalInfo(ModuleMapProposal proposal, long snap) {
    Collection<ModuleMapProposal.ModuleMapEntry> entries = proposal.computeMap().values();
    Map<String, Object> info = new LinkedHashMap<>();
    info.put("mapping_kind", "module");
    info.put("trace", proposal.getTrace().getName());
    info.put("program", proposal.getProgram().getName());
    info.put("score", proposal.computeScore());
    info.put("module", createModuleInfo(-1, proposal.getModule(), snap));
    info.put(
        "entries", entries.stream().map(this::createMappingEntryInfo).collect(Collectors.toList()));
    info.put("entry_count", entries.size());
    return info;
  }

  private Map<String, Object> createMappingEntryInfo(MapEntry<?, ?> entry) {
    Map<String, Object> info = new LinkedHashMap<>();
    info.put("trace", entry.getFromTrace().getName());
    putIfNotNull(
        info, "from_range", entry.getFromRange() != null ? entry.getFromRange().toString() : null);
    putIfNotNull(
        info,
        "from_lifespan",
        entry.getFromLifespan() != null ? entry.getFromLifespan().toString() : null);
    putIfNotNull(
        info, "program", entry.getToProgram() != null ? entry.getToProgram().getName() : null);
    putIfNotNull(
        info, "to_range", entry.getToRange() != null ? entry.getToRange().toString() : null);
    info.put("length", entry.getMappingLength());
    return info;
  }

  private Map<String, Object> createSectionProposalInfo(SectionMapProposal proposal, long snap) {
    Collection<SectionMapProposal.SectionMapEntry> entries = proposal.computeMap().values();
    Map<String, Object> info = new LinkedHashMap<>();
    info.put("mapping_kind", "section");
    info.put("trace", proposal.getTrace().getName());
    info.put("program", proposal.getProgram().getName());
    info.put("score", proposal.computeScore());
    info.put("module", createModuleInfo(-1, proposal.getModule(), snap));
    info.put(
        "entries", entries.stream().map(this::createMappingEntryInfo).collect(Collectors.toList()));
    info.put("entry_count", entries.size());
    return info;
  }

  private Map<String, Object> createRegionProposalInfo(RegionMapProposal proposal, long snap) {
    Collection<RegionMapProposal.RegionMapEntry> entries = proposal.computeMap().values();
    Map<String, Object> info = new LinkedHashMap<>();
    info.put("mapping_kind", "region");
    info.put("trace", proposal.getTrace().getName());
    info.put("program", proposal.getProgram().getName());
    info.put("score", proposal.computeScore());
    info.put(
        "regions",
        entries.stream()
            .map(RegionMapProposal.RegionMapEntry::getRegion)
            .distinct()
            .map(region -> createMemoryRegionInfo(-1, region, snap))
            .collect(Collectors.toList()));
    info.put(
        "entries", entries.stream().map(this::createMappingEntryInfo).collect(Collectors.toList()));
    info.put("entry_count", entries.size());
    return info;
  }

  private Map<String, Object> createSectionInfo(int index, TraceSection section, long snap) {
    Map<String, Object> info = new LinkedHashMap<>();
    info.put("section_index", index);
    info.put("path", section.getPath());
    putIfNotNull(info, "name", section.getName(snap));
    TraceModule module = section.getModule();
    if (module != null) {
      putIfNotNull(info, "module_path", module.getPath());
      putIfNotNull(info, "module_name", module.getName(snap));
    }
    AddressRange range = section.getRange(snap);
    if (range != null) {
      info.put("range", range.toString());
      info.put("base", range.getMinAddress().toString());
      info.put("max_address", range.getMaxAddress().toString());
      info.put("length", range.getLength());
    }
    return info;
  }

  private Map<String, Object> createMemoryRegionInfo(
      int index, TraceMemoryRegion region, long snap) {
    Map<String, Object> info = new LinkedHashMap<>();
    info.put("region_index", index);
    info.put("path", region.getPath());
    putIfNotNull(info, "name", region.getName(snap));
    AddressRange range = region.getRange(snap);
    if (range != null) {
      info.put("range", range.toString());
      info.put("base", range.getMinAddress().toString());
      info.put("max_address", range.getMaxAddress().toString());
      info.put("length", range.getLength());
    }
    Set<TraceMemoryFlag> flags = region.getFlags(snap);
    info.put("flags", flags.stream().map(Enum::name).collect(Collectors.toList()));
    info.put("readable", flags.contains(TraceMemoryFlag.READ));
    info.put("writable", flags.contains(TraceMemoryFlag.WRITE));
    info.put("executable", flags.contains(TraceMemoryFlag.EXECUTE));
    info.put("volatile", flags.contains(TraceMemoryFlag.VOLATILE));
    return info;
  }

  private Collection<TraceMemoryRegion> resolveRegions(
      Trace trace, long snap, Map<String, Object> args) throws GhidraMcpException {
    Optional<String> pathOpt = getOptionalStringArgument(args, ARG_REGION_PATH);
    if (pathOpt.isPresent()) {
      TraceMemoryRegion region = trace.getMemoryManager().getLiveRegionByPath(snap, pathOpt.get());
      if (region == null) {
        throw new GhidraMcpException(GhidraMcpError.notFound("memory region", pathOpt.get()));
      }
      return List.of(region);
    }

    Optional<String> nameOpt = getOptionalStringArgument(args, ARG_REGION_NAME);
    if (nameOpt.isPresent()) {
      String name = nameOpt.get();
      List<TraceMemoryRegion> matches =
          trace.getMemoryManager().getRegionsAtSnap(snap).stream()
              .filter(region -> name.equalsIgnoreCase(safeString(region.getName(snap))))
              .map(TraceMemoryRegion.class::cast)
              .collect(Collectors.toList());
      if (matches.size() == 1) {
        return matches;
      }
      if (matches.isEmpty()) {
        throw new GhidraMcpException(GhidraMcpError.notFound("memory region", name));
      }
      throw new GhidraMcpException(
          GhidraMcpError.invalid(ARG_REGION_NAME, name, "matches multiple memory regions"));
    }

    Optional<String> addressOpt = getOptionalStringArgument(args, ARG_ADDRESS);
    if (addressOpt.isPresent()) {
      Address address = parseAddressValue(trace.getProgramView(), addressOpt.get(), ARG_ADDRESS);
      TraceMemoryRegion region = trace.getMemoryManager().getRegionContaining(snap, address);
      if (region == null) {
        throw new GhidraMcpException(
            GhidraMcpError.notFound("memory region at address", address.toString()));
      }
      return List.of(region);
    }

    List<TraceMemoryRegion> regions =
        trace.getMemoryManager().getRegionsAtSnap(snap).stream()
            .map(TraceMemoryRegion.class::cast)
            .collect(Collectors.toList());
    if (regions.isEmpty()) {
      throw new GhidraMcpException(GhidraMcpError.notFound("memory regions", "snap=" + snap));
    }
    return regions;
  }

  private AddressSet resolveTraceAddressSet(
      DebuggerCoordinates coordinates, Map<String, Object> args) throws GhidraMcpException {
    long snap = getOptionalLongArgument(args, ARG_SNAP).orElse(coordinates.getSnap());
    Optional<String> addressOpt = getOptionalStringArgument(args, ARG_ADDRESS);
    if (addressOpt.isEmpty()) {
      return new AddressSet(coordinates.getTrace().getMemoryManager().getRegionsAddressSet(snap));
    }
    Address start =
        parseAddressValue(coordinates.getTrace().getProgramView(), addressOpt.get(), ARG_ADDRESS);
    Optional<String> endOpt = getOptionalStringArgument(args, ARG_ADDRESS_END);
    Address end =
        endOpt
            .map(
                value ->
                    parseAddressValue(
                        coordinates.getTrace().getProgramView(), value, ARG_ADDRESS_END))
            .orElseGet(
                () -> {
                  int length = getMemoryLength(args, false);
                  return addBytes(start, Math.max(1, length) - 1, ARG_LENGTH);
                });
    if (start.compareTo(end) > 0) {
      throw new GhidraMcpException(
          GhidraMcpError.invalid(ARG_ADDRESS_END, end.toString(), "end must be >= start"));
    }
    return new AddressSet(start, end);
  }

  private int getMemoryLength(Map<String, Object> args, boolean required)
      throws GhidraMcpException {
    Optional<Integer> lengthOpt = getOptionalIntArgument(args, ARG_LENGTH);
    if (lengthOpt.isEmpty()) {
      if (required) {
        throw new GhidraMcpException(
            GhidraMcpErrorUtils.missingRequiredArgument(getMcpName(), ARG_LENGTH));
      }
      return 1;
    }
    int length = lengthOpt.get();
    if (length < 1 || length > MAX_MEMORY_LENGTH) {
      throw new GhidraMcpException(
          GhidraMcpError.invalid(ARG_LENGTH, length, "must be between 1 and " + MAX_MEMORY_LENGTH));
    }
    return length;
  }

  private Address addBytes(Address address, int byteCount, String argumentName)
      throws GhidraMcpException {
    try {
      return address.add(byteCount);
    } catch (Exception e) {
      throw new GhidraMcpException(
          GhidraMcpError.invalid(argumentName, byteCount, "range overflows address space"), e);
    }
  }

  private void refreshTargetMemory(
      Target target, Address address, int length, Map<String, Object> args)
      throws GhidraMcpException {
    int timeoutMs = getOptionalIntArgument(args, ARG_TIMEOUT_MS).orElse(DEFAULT_TIMEOUT_MS);
    Address end = addBytes(address, length - 1, ARG_LENGTH);
    awaitFuture(
        target.readMemoryAsync(new AddressSet(address, end), TaskMonitor.DUMMY),
        "read target memory",
        timeoutMs);
  }

  private Map<String, Object> readTraceBytes(Trace trace, long snap, Address address, int length)
      throws GhidraMcpException {
    ByteBuffer buffer = ByteBuffer.allocate(length);
    int bytesRead = trace.getMemoryManager().getViewBytes(snap, address, buffer);
    byte[] bytes = Arrays.copyOf(buffer.array(), Math.max(0, bytesRead));
    Map<String, Object> result = new LinkedHashMap<>();
    result.put("address", address.toString());
    result.put("length", length);
    result.put("bytes_read", bytesRead);
    result.put("hex_data", HexFormat.of().formatHex(bytes));
    result.put("ascii", printableBytes(bytes));
    Map.Entry<Long, TraceMemoryState> state = trace.getMemoryManager().getViewState(snap, address);
    result.put("state", state.getValue().name());
    result.put("state_snap", state.getKey());
    return result;
  }

  private String printableBytes(byte[] bytes) {
    StringBuilder builder = new StringBuilder(bytes.length);
    for (byte b : bytes) {
      int value = b & 0xff;
      builder.append(value >= 32 && value <= 126 ? (char) value : '.');
    }
    return builder.toString();
  }

  private byte[] parseBytesHex(String value, String argumentName) throws GhidraMcpException {
    String normalized = value.replaceAll("[^0-9a-fA-F]", "");
    if (normalized.isEmpty() || (normalized.length() & 1) != 0) {
      throw new GhidraMcpException(
          GhidraMcpError.invalid(argumentName, value, "expected an even number of hex digits"));
    }
    try {
      return HexFormat.of().parseHex(normalized);
    } catch (IllegalArgumentException e) {
      throw new GhidraMcpException(
          GhidraMcpError.invalid(argumentName, value, "expected hexadecimal bytes"), e);
    }
  }

  private TraceMemoryState parseMemoryState(String value) throws GhidraMcpException {
    try {
      return TraceMemoryState.valueOf(value.trim().toUpperCase().replace('-', '_'));
    } catch (IllegalArgumentException e) {
      throw new GhidraMcpException(
          GhidraMcpError.invalid(ARG_MEMORY_STATE, value, "expected unknown, known, or error"), e);
    }
  }

  private ControlMode parseControlMode(String value) throws GhidraMcpException {
    try {
      return ControlMode.valueOf(value.trim().toUpperCase().replace('-', '_'));
    } catch (IllegalArgumentException e) {
      throw new GhidraMcpException(
          GhidraMcpError.invalid(
              ARG_CONTROL_MODE,
              value,
              "expected ro_target, rw_target, ro_trace, rw_trace, or rw_emulator"),
          e);
    }
  }

  private String breakpointKindToolValue(TraceBreakpointKind kind) {
    return switch (kind) {
      case SW_EXECUTE -> "sw_execute";
      case HW_EXECUTE -> "hw_execute";
      case READ -> "read";
      case WRITE -> "write";
    };
  }

  private Map<String, Object> createThreadInfo(
      int index, TraceThread thread, Target target, long snap) {
    Map<String, Object> info = createThreadInfo(thread, snap);
    info.put("thread_index", index);
    info.put("alive", thread.isValid(snap));
    if (target != null && target.isValid()) {
      TraceExecutionState state = target.getThreadExecutionState(thread);
      putIfNotNull(info, "execution_state", state != null ? state.name() : null);
    }
    return info;
  }

  private Map<String, Object> createStackFrameInfo(
      TraceStackFrame frame, long snap, int currentFrame) {
    Map<String, Object> info = new LinkedHashMap<>();
    info.put("frame", frame.getLevel());
    info.put("current", frame.getLevel() == currentFrame);
    Address pc = frame.getProgramCounter(snap);
    putIfNotNull(info, "pc", pc != null ? pc.toString() : null);
    putIfNotNull(info, "comment", frame.getComment(snap));
    return info;
  }

  private Map<String, Object> createSnapshotInfo(int index, TraceSnapshot snapshot) {
    Map<String, Object> info = new LinkedHashMap<>();
    info.put("snapshot_index", index);
    info.put("snap", snapshot.getKey());
    putIfNotNull(info, "description", snapshot.getDescription());
    info.put("real_time", snapshot.getRealTime());
    putIfNotNull(
        info,
        "event_thread",
        snapshot.getEventThread() != null ? snapshot.getEventThread().getPath() : null);
    putIfNotNull(info, "schedule", snapshot.getScheduleString());
    info.put("version", snapshot.getVersion());
    return info;
  }

  private Map<String, Object> createObjectInfo(int index, TraceObject object, long snap) {
    Map<String, Object> info = new LinkedHashMap<>();
    info.put("object_index", index);
    info.put("key", object.getKey());
    info.put("path", object.getCanonicalPath().toString());
    info.put("root", object.isRoot());
    info.put("alive", object.isAlive(snap));
    info.put("life", object.getLife().toString());
    info.put("schema", object.getSchema().getName().name());
    info.put(
        "interfaces",
        object.getInterfaces().stream()
            .map(Class::getSimpleName)
            .sorted()
            .collect(Collectors.toList()));
    TraceExecutionState state = object.getExecutionState(snap);
    putIfNotNull(info, "execution_state", state != null ? state.name() : null);
    return info;
  }

  private Map<String, Object> createObjectValueInfo(int index, TraceObjectValue value) {
    Map<String, Object> info = new LinkedHashMap<>();
    info.put("value_index", index);
    info.put("key", value.getEntryKey());
    info.put("path", value.getCanonicalPath().toString());
    info.put("lifespan", value.getLifespan().toString());
    info.put("object", value.isObject());
    info.put("canonical", value.isCanonical());
    info.put("hidden", value.isHidden());
    info.put("value", describeRemoteValue(value.getValue()));
    return info;
  }

  private TraceObject resolveObject(Trace trace, Map<String, Object> args)
      throws GhidraMcpException {
    String path = getRequiredStringArgument(args, ARG_OBJECT_PATH);
    TraceObject object = trace.getObjectManager().getObjectByCanonicalPath(KeyPath.parse(path));
    if (object == null) {
      throw new GhidraMcpException(GhidraMcpError.notFound("trace object", path));
    }
    return object;
  }

  private Optional<TraceObject> resolveOptionalObject(
      DebuggerCoordinates coordinates, Map<String, Object> args) throws GhidraMcpException {
    if (!args.containsKey(ARG_OBJECT_PATH)) {
      return Optional.empty();
    }
    return Optional.of(resolveObject(coordinates.getTrace(), args));
  }

  private Map<String, Object> createTimeInfo(Trace trace, TraceSchedule schedule) {
    Map<String, Object> info = new LinkedHashMap<>();
    info.put("trace", trace.getName());
    info.put("schedule", schedule.toString());
    info.put("snap", schedule.getSnap());
    info.put("snap_only", schedule.isSnapOnly());
    info.put("step_count", schedule.stepCount());
    info.put("tick_count", schedule.tickCount());
    info.put("patch_count", schedule.patchCount());
    return info;
  }

  private TraceSchedule resolveSchedule(DebuggerCoordinates coordinates, Map<String, Object> args)
      throws GhidraMcpException {
    Optional<String> timeOpt = getOptionalStringArgument(args, ARG_TIME);
    if (timeOpt.isEmpty()) {
      TraceSchedule current = coordinates.getTime();
      return current != null ? current : TraceSchedule.snap(coordinates.getSnap());
    }
    try {
      return TraceSchedule.parse(timeOpt.get());
    } catch (Exception e) {
      throw new GhidraMcpException(
          GhidraMcpError.invalid(ARG_TIME, timeOpt.get(), "expected a Ghidra trace schedule"), e);
    }
  }

  private List<TracePlatform> listPlatforms(Trace trace) {
    List<TracePlatform> platforms = new ArrayList<>();
    platforms.add(trace.getPlatformManager().getHostPlatform());
    platforms.addAll(trace.getPlatformManager().getGuestPlatforms());
    return platforms;
  }

  private TracePlatform resolvePlatform(Trace trace, Map<String, Object> args)
      throws GhidraMcpException {
    List<TracePlatform> platforms = listPlatforms(trace);
    int index = getOptionalIntArgument(args, ARG_PLATFORM_INDEX).orElse(0);
    if (index < 0 || index >= platforms.size()) {
      throw new GhidraMcpException(GhidraMcpError.notFound("platform", "index=" + index));
    }
    return platforms.get(index);
  }

  private int resolvePlatformIndex(Trace trace, TracePlatform platform) {
    return listPlatforms(trace).indexOf(platform);
  }

  private TracePlatform resolveCurrentPlatform(DebuggerCoordinates coordinates) {
    TracePlatform platform = coordinates.getPlatform();
    return platform != null
        ? platform
        : coordinates.getTrace().getPlatformManager().getHostPlatform();
  }

  private Map<String, Object> createPlatformInfo(int index, TracePlatform platform) {
    Map<String, Object> info = new LinkedHashMap<>();
    info.put("platform_index", index);
    info.put("guest", platform.isGuest());
    info.put("language", platform.getLanguage().getLanguageID().getIdAsString());
    info.put("compiler_spec", platform.getCompilerSpec().getCompilerSpecID().getIdAsString());
    info.put("host_address_set", platform.getHostAddressSet().toString());
    info.put("guest_address_set", platform.getGuestAddressSet().toString());
    return info;
  }

  private Map<String, Object> createMapperInfo(
      DebuggerPlatformMapper mapper, TraceObject object, long snap) {
    if (mapper == null) {
      return null;
    }
    Map<String, Object> info = new LinkedHashMap<>();
    info.put("class", mapper.getClass().getName());
    info.put("can_interpret", object != null && mapper.canInterpret(object, snap));
    if (object != null) {
      try {
        info.put(
            "compiler_spec",
            mapper.getCompilerSpec(object, snap).getCompilerSpecID().getIdAsString());
      } catch (Exception e) {
        info.put("compiler_spec_error", describeFailure(e));
      }
    }
    return info;
  }

  private TraceRmiConnection resolveConnection(PluginTool tool, Map<String, Object> args)
      throws GhidraMcpException {
    TraceRmiService rmiService = requireService(tool, TraceRmiService.class);
    List<TraceRmiConnection> connections = new ArrayList<>(rmiService.getAllConnections());
    Optional<Integer> indexOpt = getOptionalIntArgument(args, ARG_CONNECTION_INDEX);
    if (indexOpt.isPresent()) {
      int index = indexOpt.get();
      if (index < 0 || index >= connections.size()) {
        throw new GhidraMcpException(GhidraMcpError.notFound("connection", "index=" + index));
      }
      return connections.get(index);
    }

    DebuggerTraceManagerService traceService =
        tool != null ? tool.getService(DebuggerTraceManagerService.class) : null;
    Target current =
        traceService != null && traceService.getCurrent() != null
            ? traceService.getCurrent().getTarget()
            : null;
    if (current != null) {
      for (TraceRmiConnection connection : connections) {
        if (connection.getTargets().contains(current)) {
          return connection;
        }
      }
    }
    if (connections.size() == 1) {
      return connections.get(0);
    }
    throw new GhidraMcpException(
        GhidraMcpError.validation()
            .message("Provide connection_index; no unique Trace RMI connection is selected.")
            .build());
  }

  private Map<String, Object> createRemoteMethodInfo(int index, RemoteMethod method) {
    Map<String, Object> info = new LinkedHashMap<>();
    info.put("method_index", index);
    info.put("name", method.name());
    info.put("action", method.action().name());
    info.put("display", method.display());
    info.put("description", method.description());
    info.put("return_type", method.retType().name());
    List<Map<String, Object>> parameters = new ArrayList<>();
    for (RemoteParameter parameter : method.parameters().values()) {
      Map<String, Object> parameterInfo = new LinkedHashMap<>();
      parameterInfo.put("name", parameter.name());
      parameterInfo.put("type", parameter.type().name());
      parameterInfo.put("required", parameter.required());
      parameterInfo.put("display", parameter.display());
      parameterInfo.put("description", parameter.description());
      putIfNotNull(parameterInfo, "default", describeRemoteValue(parameter.getDefaultValue()));
      parameters.add(parameterInfo);
    }
    info.put("parameters", parameters);
    return info;
  }

  private RemoteMethod resolveRemoteMethod(TraceRmiConnection connection, Map<String, Object> args)
      throws GhidraMcpException {
    String name = getRequiredStringArgument(args, ARG_METHOD_NAME);
    RemoteMethod method = connection.getMethods().get(name);
    if (method == null) {
      throw new GhidraMcpException(GhidraMcpError.notFound("remote method", name));
    }
    return method;
  }

  private RemoteMethod resolveRemoteActionMethod(
      TraceRmiConnection connection, Map<String, Object> args, ActionName actionName)
      throws GhidraMcpException {
    Optional<String> nameOpt = getOptionalStringArgument(args, ARG_METHOD_NAME);
    if (nameOpt.isPresent()) {
      RemoteMethod method = connection.getMethods().get(nameOpt.get());
      if (method == null) {
        throw new GhidraMcpException(GhidraMcpError.notFound("remote method", nameOpt.get()));
      }
      if (!actionName.equals(method.action())) {
        throw new GhidraMcpException(
            GhidraMcpError.invalid(
                ARG_METHOD_NAME,
                nameOpt.get(),
                "method action is " + method.action().name() + ", expected " + actionName.name()));
      }
      return method;
    }

    List<RemoteMethod> methods =
        connection.getMethods().getByAction(actionName).stream()
            .sorted(Comparator.comparing(RemoteMethod::name, String.CASE_INSENSITIVE_ORDER))
            .collect(Collectors.toList());
    if (methods.size() == 1) {
      return methods.get(0);
    }
    if (methods.isEmpty()) {
      throw new GhidraMcpException(
          GhidraMcpError.failed(
              "find remote action " + actionName.name(),
              "the selected Trace RMI connection exposes no matching method"));
    }
    throw new GhidraMcpException(
        GhidraMcpError.validation()
            .message(
                "Provide method_name; multiple remote methods implement action "
                    + actionName.name()
                    + ".")
            .build());
  }

  private Map<String, Object> decodeRemoteMethodArguments(
      PluginTool tool, RemoteMethod method, Map<String, Object> args) throws GhidraMcpException {
    Map<String, Object> raw = getOptionalMapArgument(args, ARG_METHOD_ARGUMENTS).orElse(Map.of());
    DebuggerTraceManagerService traceService =
        requireService(tool, DebuggerTraceManagerService.class);
    DebuggerCoordinates coordinates = requireCurrentCoordinates(traceService);
    Map<String, Object> decoded = new LinkedHashMap<>();
    for (RemoteParameter parameter : method.parameters().values()) {
      Object value = raw.get(parameter.name());
      if (value == null) {
        if (parameter.required() && parameter.getDefaultValue() == null) {
          throw new GhidraMcpException(
              GhidraMcpErrorUtils.missingRequiredArgument(getMcpName(), parameter.name()));
        }
        if (parameter.getDefaultValue() != null) {
          decoded.put(parameter.name(), parameter.getDefaultValue());
        }
        continue;
      }
      decoded.put(parameter.name(), decodeRemoteArgument(coordinates, parameter, value));
    }
    return decoded;
  }

  private Object decodeRemoteArgument(
      DebuggerCoordinates coordinates, RemoteParameter parameter, Object value)
      throws GhidraMcpException {
    String type = parameter.type().name().toUpperCase();
    String text = String.valueOf(value);
    return switch (type) {
      case "BOOL" -> Boolean.parseBoolean(text);
      case "BYTE" -> (byte) parseIntegerValue(text).intValue();
      case "SHORT" -> (short) parseIntegerValue(text).intValue();
      case "INT" -> parseIntegerValue(text).intValue();
      case "LONG" -> parseIntegerValue(text).longValue();
      case "STRING", "CHAR" -> text;
      case "ADDRESS" ->
          parseAddressValue(coordinates.getTrace().getProgramView(), text, parameter.name());
      case "RANGE" -> decodeRemoteRange(coordinates, value, parameter.name());
      case "BYTE_ARR" -> parseBytesHex(text, parameter.name());
      case "OBJECT" ->
          coordinates.getTrace().getObjectManager().getObjectByCanonicalPath(KeyPath.parse(text));
      default -> value;
    };
  }

  private AddressRange decodeRemoteRange(
      DebuggerCoordinates coordinates, Object value, String argumentName)
      throws GhidraMcpException {
    if (value instanceof Map<?, ?> rawMap) {
      Object addressValue = rawMap.get(ARG_ADDRESS);
      Object lengthValue = rawMap.get(ARG_LENGTH);
      if (addressValue != null && lengthValue != null) {
        Address start =
            parseAddressValue(
                coordinates.getTrace().getProgramView(), String.valueOf(addressValue), ARG_ADDRESS);
        int length =
            getOptionalIntArgument(Map.of(ARG_LENGTH, lengthValue), ARG_LENGTH)
                .orElseThrow(
                    () ->
                        new GhidraMcpException(
                            GhidraMcpError.invalid(
                                ARG_LENGTH, lengthValue, "expected integer length")));
        return new AddressSet(start, addBytes(start, length - 1, ARG_LENGTH)).getFirstRange();
      }
    }
    String text = String.valueOf(value);
    String[] parts = text.split("\\.\\.");
    if (parts.length == 2) {
      Address start =
          parseAddressValue(coordinates.getTrace().getProgramView(), parts[0], argumentName);
      Address end =
          parseAddressValue(coordinates.getTrace().getProgramView(), parts[1], argumentName);
      return new AddressSet(start, end).getFirstRange();
    }
    throw new GhidraMcpException(
        GhidraMcpError.invalid(argumentName, value, "expected {address,length} or start..end"));
  }

  private Object describeRemoteValue(Object value) {
    if (value == null) {
      return null;
    }
    if (value instanceof TraceObject object) {
      return object.getCanonicalPath().toString();
    }
    if (value instanceof TraceObjectValue objectValue) {
      return objectValue.getCanonicalPath().toString();
    }
    if (value instanceof Address address) {
      return address.toString();
    }
    if (value instanceof AddressRange range) {
      return range.toString();
    }
    if (value instanceof byte[] bytes) {
      return HexFormat.of().formatHex(bytes);
    }
    if (value instanceof Collection<?> collection) {
      return collection.stream().map(this::describeRemoteValue).collect(Collectors.toList());
    }
    return value;
  }

  private Map<String, Object> createEmulatorFactoryInfo(
      int index, EmulatorFactory factory, EmulatorFactory current) {
    Map<String, Object> info = new LinkedHashMap<>();
    info.put("emulator_index", index);
    info.put("title", factory.getTitle());
    info.put("class", factory.getClass().getName());
    info.put("current", current != null && current.getClass().equals(factory.getClass()));
    return info;
  }

  private EmulatorFactory resolveEmulatorFactory(
      DebuggerEmulationService emulationService, Map<String, Object> args)
      throws GhidraMcpException {
    List<EmulatorFactory> factories = new ArrayList<>(emulationService.getEmulatorFactories());
    factories.sort(Comparator.comparing(EmulatorFactory::getTitle, String.CASE_INSENSITIVE_ORDER));
    Optional<Integer> indexOpt = getOptionalIntArgument(args, ARG_EMULATOR_INDEX);
    if (indexOpt.isPresent()) {
      int index = indexOpt.get();
      if (index < 0 || index >= factories.size()) {
        throw new GhidraMcpException(GhidraMcpError.notFound("emulator factory", "index=" + index));
      }
      return factories.get(index);
    }
    Optional<String> nameOpt = getOptionalStringArgument(args, ARG_EMULATOR_NAME);
    if (nameOpt.isPresent()) {
      String name = nameOpt.get();
      return factories.stream()
          .filter(
              factory ->
                  factory.getTitle().equalsIgnoreCase(name)
                      || factory.getClass().getSimpleName().equalsIgnoreCase(name)
                      || factory.getClass().getName().equals(name))
          .findFirst()
          .orElseThrow(
              () -> new GhidraMcpException(GhidraMcpError.notFound("emulator factory", name)));
    }
    if (factories.size() == 1) {
      return factories.get(0);
    }
    throw new GhidraMcpException(
        GhidraMcpError.validation()
            .message("Provide emulator_index or emulator_name; no unique emulator factory.")
            .build());
  }

  private String safeString(String value) {
    return value != null ? value : "";
  }

  private DebuggerCoordinates requireCurrentCoordinates(DebuggerTraceManagerService traceService)
      throws GhidraMcpException {
    DebuggerCoordinates coordinates = traceService.getCurrent();
    if (coordinates == null || coordinates.getTrace() == null) {
      throw new GhidraMcpException(GhidraMcpError.of("No active debugger trace is selected."));
    }
    return coordinates;
  }

  private TraceProgramView requireCurrentView(DebuggerTraceManagerService traceService)
      throws GhidraMcpException {
    TraceProgramView view = traceService.getCurrentView();
    if (view != null) {
      return view;
    }
    Trace trace = requireCurrentTrace(traceService);
    view = trace.getProgramView();
    if (view == null) {
      throw new GhidraMcpException(
          GhidraMcpError.of("No current trace program view is available."));
    }
    return view;
  }

  private Address parseCurrentTraceAddress(
      DebuggerTraceManagerService traceService, Map<String, Object> args)
      throws GhidraMcpException {
    String addressStr = getRequiredStringArgument(args, ARG_ADDRESS);
    TraceProgramView view = traceService.getCurrentView();
    if (view == null) {
      Trace trace = requireCurrentTrace(traceService);
      view = trace.getProgramView();
    }
    if (view == null) {
      throw new GhidraMcpException(
          GhidraMcpError.of("No current trace program view is available."));
    }
    return parseAddressValue(view, addressStr, ARG_ADDRESS);
  }

  private DataTypeManager currentDataTypeManager(PluginTool tool) throws GhidraMcpException {
    DebuggerTraceManagerService traceService =
        requireService(tool, DebuggerTraceManagerService.class);
    return requireCurrentView(traceService).getDataTypeManager();
  }

  private DataType resolveRequestedDataType(
      DataTypeManager dtm, Map<String, Object> args, boolean required) throws GhidraMcpException {
    String dataTypePath = getOptionalStringArgument(args, ARG_DATA_TYPE_PATH).orElse(null);
    Long dataTypeId = getOptionalLongArgument(args, ARG_DATA_TYPE_ID).orElse(null);
    if (dataTypePath == null && dataTypeId == null) {
      if (required) {
        throw new GhidraMcpException(
            GhidraMcpError.validation()
                .message("Either data_type_path or data_type_id must be provided.")
                .build());
      }
      return null;
    }

    if (dataTypeId != null) {
      DataType dataType = dtm.getDataType(dataTypeId);
      if (dataType == null) {
        throw new GhidraMcpException(GhidraMcpError.notFound("data type", "ID=" + dataTypeId));
      }
      return dataType;
    }

    DataType dataType = resolveDataTypeWithFallback(dtm, dataTypePath);
    if (dataType == null) {
      throw new GhidraMcpException(GhidraMcpError.notFound("data type", dataTypePath));
    }
    return dataType;
  }

  private int getBoundedInt(Map<String, Object> args, String argument, int defaultValue, int max)
      throws GhidraMcpException {
    int value = getOptionalIntArgument(args, argument).orElse(defaultValue);
    if (value < 1 || value > max) {
      throw new GhidraMcpException(
          GhidraMcpError.invalid(argument, value, "must be between 1 and " + max));
    }
    return value;
  }

  private int getIndexCursorOffset(Map<String, Object> args, String expectedFormat)
      throws GhidraMcpException {
    Optional<String> cursorOpt = getOptionalStringArgument(args, ARG_CURSOR);
    if (cursorOpt.isEmpty()) {
      return 0;
    }

    String decoded = decodeOpaqueCursorSingleV1(cursorOpt.get(), ARG_CURSOR, expectedFormat);
    try {
      int offset = Integer.parseInt(decoded);
      if (offset < 0) {
        throw new NumberFormatException("negative");
      }
      return offset;
    } catch (NumberFormatException e) {
      throw new GhidraMcpException(
          GhidraMcpError.invalid(ARG_CURSOR, cursorOpt.get(), "cursor offset is invalid"));
    }
  }

  private List<Register> selectRegisters(DebuggerCoordinates coordinates, Map<String, Object> args)
      throws GhidraMcpException {
    List<String> requestedNames = getOptionalStringList(args, ARG_REGISTER_NAMES);
    if (!requestedNames.isEmpty()) {
      return requestedNames.stream()
          .map(name -> resolveRegister(coordinates, name))
          .collect(Collectors.toList());
    }

    boolean includeHidden = getOptionalBooleanArgument(args, ARG_INCLUDE_HIDDEN).orElse(false);
    Optional<Pattern> pattern = compileOptionalPattern(args, ARG_NAME_PATTERN);
    return currentLanguageRegisters(coordinates).stream()
        .filter(Register::isBaseRegister)
        .filter(register -> includeHidden || !register.isHidden())
        .filter(register -> pattern.map(p -> p.matcher(register.getName()).find()).orElse(true))
        .sorted(Comparator.comparing(Register::getName, String.CASE_INSENSITIVE_ORDER))
        .collect(Collectors.toList());
  }

  private List<String> getOptionalStringList(Map<String, Object> args, String argument)
      throws GhidraMcpException {
    Object raw = args.get(argument);
    if (raw == null) {
      return List.of();
    }
    if (!(raw instanceof List<?> list)) {
      throw new GhidraMcpException(
          GhidraMcpError.invalid(argument, raw, "expected array of strings"));
    }
    return list.stream().map(String::valueOf).collect(Collectors.toList());
  }

  private Optional<Pattern> compileOptionalPattern(Map<String, Object> args, String argument)
      throws GhidraMcpException {
    Optional<String> patternOpt =
        getOptionalStringArgument(args, argument).filter(v -> !v.isBlank());
    if (patternOpt.isEmpty()) {
      return Optional.empty();
    }
    try {
      return Optional.of(Pattern.compile(patternOpt.get(), Pattern.CASE_INSENSITIVE));
    } catch (PatternSyntaxException e) {
      throw new GhidraMcpException(
          GhidraMcpError.invalid(argument, patternOpt.get(), e.getMessage()), e);
    }
  }

  private List<Register> currentLanguageRegisters(DebuggerCoordinates coordinates) {
    if (coordinates.getLanguage() != null) {
      return coordinates.getLanguage().getRegisters();
    }
    return coordinates.getTrace().getBaseLanguage().getRegisters();
  }

  private Register resolveRegister(DebuggerCoordinates coordinates, String registerName)
      throws GhidraMcpException {
    Register register = null;
    if (coordinates.getLanguage() != null) {
      register = coordinates.getLanguage().getRegister(registerName);
    }
    if (register == null) {
      register = coordinates.getTrace().getBaseLanguage().getRegister(registerName);
    }
    if (register == null) {
      throw new GhidraMcpException(GhidraMcpError.notFound("register", registerName));
    }
    return register;
  }

  private void refreshRegistersIfRequested(
      DebuggerCoordinates coordinates, List<Register> registers, Map<String, Object> args)
      throws GhidraMcpException {
    if (registers.isEmpty()) {
      return;
    }

    Target target = coordinates.getTarget();
    boolean refresh = getOptionalBooleanArgument(args, ARG_REFRESH).orElse(target != null);
    if (!refresh || target == null) {
      return;
    }
    if (coordinates.getThread() == null) {
      throw new GhidraMcpException(
          GhidraMcpError.failed("read registers", "no current thread is selected"));
    }
    int timeoutMs = getOptionalIntArgument(args, ARG_TIMEOUT_MS).orElse(DEFAULT_TIMEOUT_MS);
    var platform = coordinates.getPlatform();
    if (platform == null) {
      platform = coordinates.getTrace().getPlatformManager().getHostPlatform();
    }
    awaitFuture(
        target.readRegistersAsync(
            platform,
            coordinates.getThread(),
            coordinates.getFrame(),
            new java.util.LinkedHashSet<>(registers)),
        "read registers",
        timeoutMs);
  }

  private Map<String, Object> createRegisterInfo(
      DebuggerCoordinates coordinates, Register register, boolean includeValue) {
    Map<String, Object> info = new LinkedHashMap<>();
    info.put("name", register.getName());
    putIfNotNull(info, "group", register.getGroup());
    info.put("bit_length", register.getBitLength());
    info.put("byte_length", register.getNumBytes());
    info.put("address", register.getAddress().toString());
    info.put("hidden", register.isHidden());
    info.put("program_counter", register.isProgramCounter());
    if (includeValue) {
      putRegisterValue(info, coordinates, register);
    }
    return info;
  }

  private void putRegisterValue(
      Map<String, Object> info, DebuggerCoordinates coordinates, Register register) {
    TraceThread thread = coordinates.getThread();
    if (thread == null) {
      info.put("known", false);
      return;
    }
    TraceMemorySpace space =
        coordinates
            .getTrace()
            .getMemoryManager()
            .getMemoryRegisterSpace(thread, coordinates.getFrame(), false);
    if (space == null) {
      info.put("known", false);
      return;
    }

    RegisterValue value = space.getViewValue(coordinates.getSnap(), register);
    if (value == null || !value.hasAnyValue()) {
      info.put("known", false);
      return;
    }

    info.put("known", true);
    if (value.hasValue()) {
      BigInteger unsigned = value.getUnsignedValueIgnoreMask();
      putIfNotNull(info, "unsigned", unsigned != null ? unsigned.toString() : null);
      putIfNotNull(info, "hex", unsigned != null ? "0x" + unsigned.toString(16) : null);
      BigInteger signed = value.getSignedValueIgnoreMask();
      putIfNotNull(info, "signed", signed != null ? signed.toString() : null);
    }
    try {
      info.put("bytes", HexFormat.of().formatHex(value.toBytes()));
    } catch (Exception ignored) {
      // Some partially-known values cannot be represented cleanly as bytes.
    }
  }

  private BigInteger parseIntegerValue(String value) throws GhidraMcpException {
    String normalized = value.trim().replace("_", "");
    try {
      boolean negative = normalized.startsWith("-");
      if (negative) {
        normalized = normalized.substring(1);
      }
      if (normalized.startsWith("0x") || normalized.startsWith("0X")) {
        BigInteger parsed = new BigInteger(normalized.substring(2), 16);
        return negative ? parsed.negate() : parsed;
      }
      BigInteger parsed = new BigInteger(normalized, 10);
      return negative ? parsed.negate() : parsed;
    } catch (NumberFormatException e) {
      throw new GhidraMcpException(
          GhidraMcpError.invalid(ARG_VALUE, value, "expected decimal or 0x-prefixed hex integer"),
          e);
    }
  }

  private List<WatchRow> watchRows(DebuggerWatchesService watchesService) {
    return new ArrayList<>(watchesService.getWatches());
  }

  private WatchRow requireWatch(DebuggerWatchesService watchesService, int index)
      throws GhidraMcpException {
    List<WatchRow> rows = watchRows(watchesService);
    if (index < 0 || index >= rows.size()) {
      throw new GhidraMcpException(GhidraMcpError.notFound("watch", "index=" + index));
    }
    return rows.get(index);
  }

  private Map<String, Object> createWatchInfo(int index, WatchRow row) {
    Map<String, Object> info = new LinkedHashMap<>();
    info.put("watch_index", index);
    info.put("expression", row.getExpression());
    DataType dataType = row.getDataType();
    putIfNotNull(info, "data_type", dataType != null ? dataType.getDisplayName() : null);
    putIfNotNull(info, "data_type_path", dataType != null ? dataType.getPathName() : null);
    putIfNotNull(info, "address", row.getAddress() != null ? row.getAddress().toString() : null);
    putIfNotNull(info, "range", row.getRange() != null ? row.getRange().toString() : null);
    putIfNotNull(info, "reads", row.getReads() != null ? row.getReads().toString() : null);
    putIfNotNull(info, "symbol", row.getSymbol() != null ? row.getSymbol().getName(true) : null);
    putIfNotNull(info, "raw_value", row.getRawValueString());
    putIfNotNull(info, "value", row.getValueString());
    putIfNotNull(
        info,
        "value_object",
        row.getValueObject() != null ? String.valueOf(row.getValueObject()) : null);
    byte[] bytes = row.getValue();
    putIfNotNull(info, "hex_data", bytes != null ? HexFormat.of().formatHex(bytes) : null);
    info.put("value_length", row.getValueLength());
    info.put("known", row.isKnown());
    info.put("changed", row.isChanged());
    info.put("value_editable", row.isValueEditable());
    info.put("raw_value_editable", row.isRawValueEditable());
    putIfNotNull(info, "comment", row.getComment());
    putIfNotNull(info, "error", row.getErrorMessage());
    return info;
  }

  private Object watchOutcome(WatchRow row, Map<String, Object> info) {
    Address address = row.getAddress();
    if (address == null) {
      return info;
    }
    return ToolOutcome.of(info, NavigateDebuggerAddressEffect.listing(address));
  }

  private Set<TraceBreakpointKind> parseBreakpointKinds(Map<String, Object> args)
      throws GhidraMcpException {
    Object raw = args.get(ARG_BREAKPOINT_KINDS);
    if (raw == null) {
      return Set.of(TraceBreakpointKind.SW_EXECUTE);
    }
    if (!(raw instanceof List<?> values)) {
      throw new GhidraMcpException(
          GhidraMcpError.invalid(ARG_BREAKPOINT_KINDS, raw, "expected array of strings"));
    }
    if (values.isEmpty()) {
      return Set.of(TraceBreakpointKind.SW_EXECUTE);
    }

    Set<TraceBreakpointKind> kinds = new java.util.LinkedHashSet<>();
    for (Object value : values) {
      String normalized = String.valueOf(value).trim().toLowerCase().replace("-", "_");
      if ("access".equals(normalized) || "break_access".equals(normalized)) {
        kinds.add(TraceBreakpointKind.READ);
        kinds.add(TraceBreakpointKind.WRITE);
      } else {
        kinds.add(parseBreakpointKind(String.valueOf(value)));
      }
    }
    return Set.copyOf(kinds);
  }

  private TraceBreakpointKind parseBreakpointKind(String value) throws GhidraMcpException {
    String normalized = value.trim().toLowerCase().replace("-", "_");
    return switch (normalized) {
      case "execute", "sw_execute", "software_execute" -> TraceBreakpointKind.SW_EXECUTE;
      case "hw_execute", "hardware_execute" -> TraceBreakpointKind.HW_EXECUTE;
      case "read" -> TraceBreakpointKind.READ;
      case "write" -> TraceBreakpointKind.WRITE;
      default ->
          throw new GhidraMcpException(
              GhidraMcpError.invalid(
                  ARG_BREAKPOINT_KINDS,
                  value,
                  "expected one of: sw_execute, hw_execute, read, write, access"));
    };
  }

  private Trace requireCurrentTrace(DebuggerTraceManagerService traceService)
      throws GhidraMcpException {
    Trace trace = traceService.getCurrentTrace();
    if (trace == null) {
      DebuggerCoordinates coordinates = traceService.getCurrent();
      trace = coordinates != null ? coordinates.getTrace() : null;
    }
    if (trace == null) {
      throw new GhidraMcpException(GhidraMcpError.of("No active debugger trace is selected."));
    }
    return trace;
  }

  private Target requireCurrentTarget(PluginTool tool) throws GhidraMcpException {
    DebuggerTraceManagerService traceService =
        requireService(tool, DebuggerTraceManagerService.class);
    DebuggerCoordinates coordinates = traceService.getCurrent();
    Target target = coordinates != null ? coordinates.getTarget() : null;
    if (target == null || !target.isValid()) {
      throw new GhidraMcpException(
          GhidraMcpError.of("No active live debugger target is selected."));
    }
    return target;
  }

  private <T> T requireService(PluginTool tool, Class<T> serviceClass) throws GhidraMcpException {
    T service = tool != null ? tool.getService(serviceClass) : null;
    if (service == null) {
      throw new GhidraMcpException(
          GhidraMcpError.of(serviceClass.getSimpleName() + " is not available."));
    }
    return service;
  }

  private <T> T awaitFuture(CompletableFuture<T> future, String operation, int timeoutMs)
      throws GhidraMcpException {
    try {
      return future.get(timeoutMs, TimeUnit.MILLISECONDS);
    } catch (TimeoutException e) {
      throw new GhidraMcpException(
          GhidraMcpError.failed(operation, "timed out after " + timeoutMs + " ms"), e);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new GhidraMcpException(GhidraMcpError.failed(operation, "interrupted"), e);
    } catch (ExecutionException e) {
      Throwable cause = Optional.ofNullable(e.getCause()).orElse(e);
      throw new GhidraMcpException(GhidraMcpError.failed(operation, describeFailure(cause)), cause);
    }
  }

  private void putIfNotNull(Map<String, Object> map, String key, Object value) {
    if (value != null) {
      map.put(key, value);
    }
  }

  private String describeFailure(Throwable throwable) {
    if (throwable == null) {
      return "unknown error";
    }
    String message = throwable.getMessage();
    if (message == null || message.isBlank()) {
      return throwable.getClass().getSimpleName();
    }
    return throwable.getClass().getSimpleName() + ": " + message;
  }

  @FunctionalInterface
  private interface IndexedInfo<T> {
    Map<String, Object> create(int index, T value);
  }
}
