package com.themixednuts;

import com.themixednuts.services.IGhidraMcpToolProvider;

import ghidra.framework.options.OptionType;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.Swing;
import ghidra.framework.options.OptionsChangeListener;
import javax.swing.Timer;

@PluginInfo(status = PluginStatus.RELEASED, packageName = ghidra.app.DeveloperPluginPackage.NAME, category = PluginCategoryNames.ANALYSIS, shortDescription = "MCP Server Plugin", description = "Starts an embedded HTTP MCP server to expose program data. Port configurable via Tool Options.", servicesRequired = {}, servicesProvided = {
        IGhidraMcpToolProvider.class })
public class GhidraMcpPlugin extends Plugin {
    /**
     * The category name used for registering Ghidra Tool Options for this plugin
     * suite.
     */
    public static final String MCP_TOOL_OPTIONS_CATEGORY = "GhidraMCP HTTP Server";

    // Option Constants
    private static final String PORT_OPTION_NAME = "Server Port";
    private static final String PORT_OPTION_DESC = "Port number for the embedded HTTP MCP server.";
    private static final int DEFAULT_PORT = 8080;

    private static final String ENABLE_SSE_KEEP_ALIVE_OPTION_NAME = "Enable SSE Keep-Alive";
    private static final String ENABLE_SSE_KEEP_ALIVE_OPTION_DESC = "Enable periodic SSE keep-alive pings to prevent connection timeouts.";
    private static final boolean DEFAULT_ENABLE_SSE_KEEP_ALIVE = true;

    private static final String SSE_MAX_KEEP_ALIVE_OPTION_NAME = "SSE Max Keep-Alive (s)";
    private static final String SSE_MAX_KEEP_ALIVE_OPTION_DESC = "Maximum duration in seconds for SSE keep-alive pings (if enabled). 0 for indefinite.";
    private static final long DEFAULT_SSE_MAX_KEEP_ALIVE_SECONDS = 7200L; // 2 hours

    private int currentPort = DEFAULT_PORT;
    private boolean currentEnableSseKeepAlive = DEFAULT_ENABLE_SSE_KEEP_ALIVE;
    private long currentSseMaxKeepAlive = DEFAULT_SSE_MAX_KEEP_ALIVE_SECONDS;

    private final OptionsChangeListener mcpOptionsListener;
    private Timer restartDebounceTimer;
    private Timer notifyToolsDebounceTimer;

    public GhidraMcpPlugin(PluginTool tool) {
        super(tool);

        Msg.info(this, "GhidraMCPPlugin loading for tool: " + tool.getToolName());

        this.mcpOptionsListener = setupOptions();

        GhidraMcpTools localToolsProvider = new GhidraMcpTools(this.tool);

        registerServiceProvided(IGhidraMcpToolProvider.class, localToolsProvider);

        Swing.runLater(
                () -> GhidraMcpServer.start(currentPort, this.tool, currentEnableSseKeepAlive, currentSseMaxKeepAlive));

        Msg.info(this, "GhidraMCPPlugin loaded!");

    }

    private OptionsChangeListener setupOptions() {
        // Use a local variable for options within this method
        ToolOptions options = tool.getOptions(MCP_TOOL_OPTIONS_CATEGORY);

        options.registerOption(PORT_OPTION_NAME, OptionType.INT_TYPE, DEFAULT_PORT,
                new HelpLocation("GhidraMCP", "ServerPortOption"),
                PORT_OPTION_DESC);
        options.registerOption(ENABLE_SSE_KEEP_ALIVE_OPTION_NAME, OptionType.BOOLEAN_TYPE,
                DEFAULT_ENABLE_SSE_KEEP_ALIVE,
                new HelpLocation("GhidraMCP", "EnableSseKeepAliveOption"),
                ENABLE_SSE_KEEP_ALIVE_OPTION_DESC);
        options.registerOption(SSE_MAX_KEEP_ALIVE_OPTION_NAME, OptionType.LONG_TYPE, DEFAULT_SSE_MAX_KEEP_ALIVE_SECONDS,
                new HelpLocation("GhidraMCP", "SseMaxKeepAliveOption"),
                SSE_MAX_KEEP_ALIVE_OPTION_DESC);

        // Get initial values from options
        currentPort = options.getInt(PORT_OPTION_NAME, DEFAULT_PORT);
        currentEnableSseKeepAlive = options.getBoolean(ENABLE_SSE_KEEP_ALIVE_OPTION_NAME,
                DEFAULT_ENABLE_SSE_KEEP_ALIVE);
        currentSseMaxKeepAlive = options.getLong(SSE_MAX_KEEP_ALIVE_OPTION_NAME, DEFAULT_SSE_MAX_KEEP_ALIVE_SECONDS);

        if (mcpOptionsListener != null) {
            options.removeOptionsChangeListener(mcpOptionsListener);
        }

        if (restartDebounceTimer != null) {
            restartDebounceTimer.stop();
        }
        restartDebounceTimer = new Timer(50, e -> {
            Msg.info(this, "MCP tool options changed. Restarting MCP server with new settings.");
            GhidraMcpServer.restartMcpServer(this.currentPort, this.currentEnableSseKeepAlive,
                    this.currentSseMaxKeepAlive);
        });
        restartDebounceTimer.setRepeats(false);

        if (notifyToolsDebounceTimer != null) {
            notifyToolsDebounceTimer.stop();
        }
        notifyToolsDebounceTimer = new Timer(50, e -> {
            GhidraMcpServer.notifyToolsListChanged()
                    .subscribe(
                            null, // onNext is not relevant for Mono<Void>
                            error -> Msg.error(GhidraMcpPlugin.this,
                                    "Asynchronous tool list notification chain failed: " + error.getMessage(), error),
                            () -> Msg.info(GhidraMcpPlugin.this,
                                    "Asynchronous tool list notification chain completed successfully."));
        });
        notifyToolsDebounceTimer.setRepeats(false);

        OptionsChangeListener listener = (toolOptions, optionName, oldValue, newValue) -> {
            boolean restartServer = false;
            boolean notifyTools = false;
            if (optionName.equals(PORT_OPTION_NAME)) {
                int newPort = (Integer) newValue;
                if (newPort != this.currentPort) {
                    Msg.info(this, "MCP Server port changing from " + this.currentPort + " to " + newPort);
                    this.currentPort = newPort;
                    restartServer = true;
                }
            } else if (optionName.equals(ENABLE_SSE_KEEP_ALIVE_OPTION_NAME)) {
                boolean newEnable = (Boolean) newValue;
                if (newEnable != this.currentEnableSseKeepAlive) {
                    Msg.info(this,
                            "SSE Keep-Alive changing from " + this.currentEnableSseKeepAlive + " to " + newEnable);
                    this.currentEnableSseKeepAlive = newEnable;
                    restartServer = true;
                }
            } else if (optionName.equals(SSE_MAX_KEEP_ALIVE_OPTION_NAME)) {
                long newKeepAlive = (Long) newValue;
                if (newKeepAlive != this.currentSseMaxKeepAlive) {
                    Msg.info(this, "SSE Max Keep-Alive changing from " + this.currentSseMaxKeepAlive + "s to "
                            + newKeepAlive + "s");
                    this.currentSseMaxKeepAlive = newKeepAlive;
                    restartServer = true;
                }
            } else if (oldValue == null || !oldValue.equals(newValue)) {
                Msg.info(this, "MCP Tool option '" + optionName + "' changed from " + oldValue + " to " + newValue
                        + ". Will notify clients.");
                notifyTools = true;
            }

            if (restartServer) {
                restartDebounceTimer.restart();
            }

            if (notifyTools) {
                notifyToolsDebounceTimer.restart();
            }
        };

        options.addOptionsChangeListener(listener);
        GhidraMcpTools.registerOptions(options, "GhidraMCP");

        return listener;

    }

    @Override
    protected void dispose() {
        Msg.info(this, "Disposing GhidraMCPPlugin for tool: " + tool.getToolName());

        GhidraMcpServer.dispose(); // Dispose server
        // Service deregistration is automatic

        if (restartDebounceTimer != null && restartDebounceTimer.isRunning()) {
            restartDebounceTimer.stop();
            Msg.info(this, "Stopped server restart debounce timer.");
        }
        if (notifyToolsDebounceTimer != null && notifyToolsDebounceTimer.isRunning()) {
            notifyToolsDebounceTimer.stop();
            Msg.info(this, "Stopped client notification debounce timer.");
        }

        // Remove listener if options object is still valid
        ToolOptions options = tool.getOptions(MCP_TOOL_OPTIONS_CATEGORY);
        if (options != null && this.mcpOptionsListener != null) {
            options.removeOptionsChangeListener(this.mcpOptionsListener);
            Msg.info(this, "OptionsChangeListener removed for category: " + MCP_TOOL_OPTIONS_CATEGORY);
        }

        super.dispose();
        Msg.info(this, "GhidraMCPPlugin disposed.");
    }
}
// End of GhidraMCPPlugin class
