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

    private static final String JETTY_IDLE_TIMEOUT_OPTION_NAME = "Jetty Idle Timeout (ms)";
    private static final String JETTY_IDLE_TIMEOUT_OPTION_DESC = "Jetty server idle connection timeout in milliseconds. 0 for infinite.";
    private static final long DEFAULT_JETTY_IDLE_TIMEOUT = 3600000L; // 1 hour

    private static final String SSE_MAX_KEEP_ALIVE_OPTION_NAME = "SSE Max Keep-Alive (s)";
    private static final String SSE_MAX_KEEP_ALIVE_OPTION_DESC = "Maximum duration in seconds for SSE keep-alive pings. 0 for indefinite (uses a very long duration).";
    private static final long DEFAULT_SSE_MAX_KEEP_ALIVE_SECONDS = 7200L; // 2 hours

    private int currentPort = DEFAULT_PORT;
    private long currentJettyIdleTimeout = DEFAULT_JETTY_IDLE_TIMEOUT;
    private long currentSseMaxKeepAlive = DEFAULT_SSE_MAX_KEEP_ALIVE_SECONDS;

    private final OptionsChangeListener mcpOptionsListener;
    private Timer restartDebounceTimer;

    public GhidraMcpPlugin(PluginTool tool) {
        super(tool);

        Msg.info(this, "GhidraMCPPlugin loading for tool: " + tool.getToolName());

        this.mcpOptionsListener = setupOptions();

        GhidraMcpTools localToolsProvider = new GhidraMcpTools(this.tool);

        registerServiceProvided(IGhidraMcpToolProvider.class, localToolsProvider);

        Swing.runLater(
                () -> GhidraMcpServer.start(currentPort, this.tool, currentJettyIdleTimeout, currentSseMaxKeepAlive));

        Msg.info(this, "GhidraMCPPlugin loaded!");

    }

    private OptionsChangeListener setupOptions() {
        // Use a local variable for options within this method
        ToolOptions options = tool.getOptions(MCP_TOOL_OPTIONS_CATEGORY);

        options.registerOption(PORT_OPTION_NAME, OptionType.INT_TYPE, DEFAULT_PORT,
                new HelpLocation("GhidraMCP", "ServerPortOption"),
                PORT_OPTION_DESC);
        options.registerOption(JETTY_IDLE_TIMEOUT_OPTION_NAME, OptionType.LONG_TYPE, DEFAULT_JETTY_IDLE_TIMEOUT,
                new HelpLocation("GhidraMCP", "JettyIdleTimeoutOption"),
                JETTY_IDLE_TIMEOUT_OPTION_DESC);
        options.registerOption(SSE_MAX_KEEP_ALIVE_OPTION_NAME, OptionType.LONG_TYPE, DEFAULT_SSE_MAX_KEEP_ALIVE_SECONDS,
                new HelpLocation("GhidraMCP", "SseMaxKeepAliveOption"),
                SSE_MAX_KEEP_ALIVE_OPTION_DESC);

        // Get initial values from options
        currentPort = options.getInt(PORT_OPTION_NAME, DEFAULT_PORT);
        currentJettyIdleTimeout = options.getLong(JETTY_IDLE_TIMEOUT_OPTION_NAME, DEFAULT_JETTY_IDLE_TIMEOUT);
        currentSseMaxKeepAlive = options.getLong(SSE_MAX_KEEP_ALIVE_OPTION_NAME, DEFAULT_SSE_MAX_KEEP_ALIVE_SECONDS);

        if (mcpOptionsListener != null) {
            options.removeOptionsChangeListener(mcpOptionsListener);
        }
        if (restartDebounceTimer != null) {
            restartDebounceTimer.stop();
        }

        restartDebounceTimer = new Timer(50, e -> {
            Msg.info(this, "MCP tool options changed. Restarting MCP server with new settings.");
            GhidraMcpServer.restartMcpServer(this.currentPort, this.currentJettyIdleTimeout,
                    this.currentSseMaxKeepAlive);
        });
        restartDebounceTimer.setRepeats(false);

        OptionsChangeListener listener = (toolOptions, optionName, oldValue, newValue) -> {
            boolean changed = false;
            if (optionName.equals(PORT_OPTION_NAME)) {
                int newPort = (Integer) newValue;
                if (newPort != this.currentPort) {
                    Msg.info(this, "MCP Server port changing from " + this.currentPort + " to " + newPort);
                    this.currentPort = newPort;
                    changed = true;
                }
            } else if (optionName.equals(JETTY_IDLE_TIMEOUT_OPTION_NAME)) {
                long newTimeout = (Long) newValue;
                if (newTimeout != this.currentJettyIdleTimeout) {
                    Msg.info(this, "Jetty Idle Timeout changing from " + this.currentJettyIdleTimeout + "ms to "
                            + newTimeout + "ms");
                    this.currentJettyIdleTimeout = newTimeout;
                    changed = true;
                }
            } else if (optionName.equals(SSE_MAX_KEEP_ALIVE_OPTION_NAME)) {
                long newKeepAlive = (Long) newValue;
                if (newKeepAlive != this.currentSseMaxKeepAlive) {
                    Msg.info(this, "SSE Max Keep-Alive changing from " + this.currentSseMaxKeepAlive + "s to "
                            + newKeepAlive + "s");
                    this.currentSseMaxKeepAlive = newKeepAlive;
                    changed = true;
                }
            }

            if (changed) {
                restartDebounceTimer.restart();
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
            Msg.info(this, "Stopped options change debounce timer.");
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
