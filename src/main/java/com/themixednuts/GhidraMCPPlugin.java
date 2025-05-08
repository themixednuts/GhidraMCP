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
public class GhidraMCPPlugin extends Plugin {
    /**
     * The category name used for registering Ghidra Tool Options for this plugin
     * suite.
     */
    public static final String MCP_TOOL_OPTIONS_CATEGORY = "GhidraMCP HTTP Server";

    // Option Constants
    private static final String PORT_OPTION_NAME = "Server Port";
    private static final String PORT_OPTION_DESC = "Port number for the embedded HTTP MCP server.";
    private static final int DEFAULT_PORT = 8080;
    private int currentPort = DEFAULT_PORT;
    private final OptionsChangeListener mcpOptionsListener;
    private Timer restartDebounceTimer;

    public GhidraMCPPlugin(PluginTool tool) {
        super(tool);

        Msg.info(this, "GhidraMCPPlugin loading for tool: " + tool.getToolName());

        this.mcpOptionsListener = setupOptions();

        GhidraMcpTools localToolsProvider = new GhidraMcpTools(this.tool);

        registerServiceProvided(IGhidraMcpToolProvider.class, localToolsProvider);

        Swing.runLater(() -> GhidraMcpServer.start(currentPort, this.tool));

        Msg.info(this, "GhidraMCPPlugin loaded!");

    }

    private OptionsChangeListener setupOptions() {
        // Use a local variable for options within this method
        ToolOptions options = tool.getOptions(MCP_TOOL_OPTIONS_CATEGORY);

        options.registerOption(PORT_OPTION_NAME, OptionType.INT_TYPE, DEFAULT_PORT,
                new HelpLocation("GhidraMCP", "ServerPortOption"),
                PORT_OPTION_DESC);

        // Get port from local options
        currentPort = options.getInt(PORT_OPTION_NAME, DEFAULT_PORT);

        if (mcpOptionsListener != null) {
            options.removeOptionsChangeListener(mcpOptionsListener);
        }
        if (restartDebounceTimer != null) {
            restartDebounceTimer.stop();
        }

        restartDebounceTimer = new Timer(200, e -> {
            Msg.info(this, "MCP tool options changed. Restarting MCP server.");
            GhidraMcpServer.restartMcpServer(this.currentPort);
        });
        restartDebounceTimer.setRepeats(false);

        OptionsChangeListener listener = (toolOptions, optionName, oldValue, newValue) -> {
            if (optionName.equals(PORT_OPTION_NAME)) {
                int newPort = (Integer) newValue;
                if (newPort != this.currentPort) {
                    Msg.info(this, "MCP Server port changing from " + this.currentPort + " to " + newPort);
                    this.currentPort = newPort;
                }
            }
            restartDebounceTimer.restart();
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
