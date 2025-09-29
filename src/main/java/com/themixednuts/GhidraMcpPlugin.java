package com.themixednuts;

import com.themixednuts.services.IGhidraMcpToolProvider;

import ghidra.framework.options.OptionType;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.main.ApplicationLevelPlugin;
import ghidra.app.services.ProgramManager;
import ghidra.program.model.listing.Program;
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
    description = "Exposes program data via MCP (Model Context Protocol) HTTP API for AI-assisted reverse engineering. Server runs with middleware support across multiple tools.",
    servicesRequired = {},
    servicesProvided = { IGhidraMcpToolProvider.class }
)
public class GhidraMcpPlugin extends Plugin implements ApplicationLevelPlugin {
    /**
     * Map to track active plugin instances by port, similar to GhydraMCP reference.
     */
    public static final java.util.Map<Integer, GhidraMcpPlugin> activeInstances = new java.util.concurrent.ConcurrentHashMap<>();
    
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
    private GhidraMcpTools toolsProvider;

    public GhidraMcpPlugin(PluginTool tool) {
        super(tool);

        Msg.info(this, "GhidraMCP Plugin loading with ApplicationLevelPlugin support on port " + currentPort);

        // Track this instance
        activeInstances.put(currentPort, this);

        this.mcpOptionsListener = setupOptions();

        // Create and register the tool provider service
        toolsProvider = new GhidraMcpTools(tool);
        registerServiceProvided(IGhidraMcpToolProvider.class, toolsProvider);

        // Start the MCP server
        Swing.runLater(() -> GhidraMcpServer.start(currentPort, tool));

        Msg.info(this, "GhidraMCP Plugin loaded with MCP transport on port " + currentPort);
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

        // Return options change listener
        return (options1, name, oldValue, newValue) -> {
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

        // Stop the MCP server (reference counted - will stop only when last tool closes)
        GhidraMcpServer.stop();
        
        // Remove this instance from tracking
        activeInstances.remove(currentPort);
        
        Msg.info(this, "GhidraMCP Plugin disposed on port " + currentPort);
        super.dispose();
    }

    /**
     * Get the port this plugin instance is running on
     * @return The HTTP server port
     */
    public int getPort() {
        return currentPort;
    }
    
    /**
     * Get the current program from the tool context.
     * @return The current program or null if no program is loaded
     */
    public Program getCurrentProgram() {
        if (tool == null) {
            return null;
        }
        ProgramManager pm = tool.getService(ProgramManager.class);
        if (pm == null) {
            return null;
        }
        return pm.getCurrentProgram();
    }
}