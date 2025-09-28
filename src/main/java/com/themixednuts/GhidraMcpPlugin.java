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

@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = ghidra.app.DeveloperPluginPackage.NAME,
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "MCP Server Plugin",
    description = "Starts an embedded HTTP MCP server to expose program data using stateless streamable transport. Port configurable via Tool Options.",
    servicesRequired = {},
    servicesProvided = { IGhidraMcpToolProvider.class }
)
public class GhidraMcpPlugin extends Plugin {
    /**
     * The category name used for registering Ghidra Tool Options for this plugin suite.
     */
    public static final String MCP_TOOL_OPTIONS_CATEGORY = "GhidraMCP HTTP Server";

    // Option Constants
    private static final String PORT_OPTION_NAME = "Server Port";
    private static final String PORT_OPTION_DESC = "Port number for the embedded HTTP MCP server.";
    private static final int DEFAULT_PORT = 8080;

    private int currentPort = DEFAULT_PORT;
    private final OptionsChangeListener mcpOptionsListener;
    private Timer restartDebounceTimer;

    public GhidraMcpPlugin(PluginTool tool) {
        super(tool);

        Msg.info(this, "GhidraMCP Plugin loading for tool: " + tool.getToolName());

        this.mcpOptionsListener = setupOptions();

        // Create and register the tool provider service
        GhidraMcpTools localToolsProvider = new GhidraMcpTools(this.tool);
        registerServiceProvided(IGhidraMcpToolProvider.class, localToolsProvider);

        // Start the MCP server
        Swing.runLater(() -> GhidraMcpServer.start(currentPort, this.tool));

        Msg.info(this, "GhidraMCP Plugin loaded with stateless HTTP transport!");
    }

    private OptionsChangeListener setupOptions() {
        ToolOptions options = tool.getOptions(MCP_TOOL_OPTIONS_CATEGORY);

        // Register port option
        options.registerOption(PORT_OPTION_NAME, OptionType.INT_TYPE, DEFAULT_PORT,
                new HelpLocation("GhidraMCP", "ServerPortOption"),
                PORT_OPTION_DESC, (java.util.function.Supplier<java.beans.PropertyEditor>) null);

        // Register MCP tool options
        GhidraMcpTools.registerOptions(options, "GhidraMCP");

        // Read current values
        currentPort = options.getInt(PORT_OPTION_NAME, DEFAULT_PORT);

        OptionsChangeListener listener = (options1, name, oldValue, newValue) -> {
            if (name.equals(PORT_OPTION_NAME)) {
                int newPort = (Integer) newValue;
                if (newPort != this.currentPort) {
                    Msg.info(this, "Server port changing from " + this.currentPort + " to " + newPort);
                    this.currentPort = newPort;
                    scheduleServerRestart();
                }
            } else {
                // Handle tool-specific option changes
                scheduleServerRestart();
            }
        };

        options.addOptionsChangeListener(listener);
        return listener;
    }

    private void scheduleServerRestart() {
        if (restartDebounceTimer != null && restartDebounceTimer.isRunning()) {
            restartDebounceTimer.stop();
        }

        restartDebounceTimer = new Timer(1000, e -> {
            Msg.info(this, "Restarting MCP server due to configuration change...");
            GhidraMcpServer.restart(currentPort, this.tool);
        });
        restartDebounceTimer.setRepeats(false);
        restartDebounceTimer.start();
    }

    @Override
    public void dispose() {
        if (mcpOptionsListener != null) {
            ToolOptions options = tool.getOptions(MCP_TOOL_OPTIONS_CATEGORY);
            options.removeOptionsChangeListener(mcpOptionsListener);
        }

        if (restartDebounceTimer != null) {
            restartDebounceTimer.stop();
        }

        GhidraMcpServer.stop();
        Msg.info(this, "GhidraMCP Plugin disposed");
        super.dispose();
    }
}
