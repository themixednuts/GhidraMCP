package com.themixednuts;

import ghidra.framework.options.OptionType;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;

@PluginInfo(status = PluginStatus.RELEASED, packageName = ghidra.app.DeveloperPluginPackage.NAME, category = PluginCategoryNames.ANALYSIS, shortDescription = "MCP Server Plugin", description = "Starts an embedded HTTP MCP server to expose program data. Port configurable via Tool Options.", servicesRequired = {}, servicesProvided = {})
public class GhidraMCPPlugin extends Plugin {
    // Option Constants
    private static final String OPTION_CATEGORY_NAME = "GhidraMCP HTTP Server";
    private static final String PORT_OPTION_NAME = "Server Port";
    private static final String PORT_OPTION_DESC = "Port number for the embedded HTTP MCP server.";
    private static final int DEFAULT_PORT = 8080;
    private int currentPort = DEFAULT_PORT;

    public GhidraMCPPlugin(PluginTool tool) {
        super(tool);

        Msg.info(this, "GhidraMCPPlugin loading for tool: " + tool.getInstanceName());
        setupOptions(); // Setup configuration options

        GhidraMcpServer.start(currentPort, tool);

        Msg.info(this, "GhidraMCPPlugin loaded!");

    }

    private void setupOptions() {
        ToolOptions options = tool.getOptions(OPTION_CATEGORY_NAME);
        options.registerOption(PORT_OPTION_NAME, OptionType.INT_TYPE, DEFAULT_PORT,
                new HelpLocation("GhidraMCP", "ServerPortOption"), // Optional help location
                PORT_OPTION_DESC);

        GhidraMcpTools.registerOptions(options, "GhidraMCP");

        currentPort = options.getInt(PORT_OPTION_NAME, DEFAULT_PORT);

        // Add a listener for changes
        options.addOptionsChangeListener((toolOptions, optionName, oldValue, newValue) -> {
            if (optionName.equals(PORT_OPTION_NAME)) {
                int newPort = (Integer) newValue; // Cast the new value
                if (newPort != currentPort) {
                    Msg.info(this, "MCP Server port changed to " + newPort);
                    currentPort = newPort;
                    GhidraMcpServer.restartJettyServer(currentPort);
                }
            }
        });
    }

    @Override
    protected void dispose() {
        Msg.info(this, "Disposing GhidraMCPPlugin for tool: " + tool.getInstanceName());

        GhidraMcpServer.dispose();

        super.dispose();
        Msg.info(this, "GhidraMCPPlugin disposed.");
    }
}
// End of GhidraMCPPlugin class
