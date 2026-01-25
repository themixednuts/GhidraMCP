package com.themixednuts;

import com.themixednuts.services.IGhidraMcpCompletionProvider;
import com.themixednuts.services.IGhidraMcpPromptProvider;
import com.themixednuts.services.IGhidraMcpResourceProvider;
import com.themixednuts.services.IGhidraMcpToolProvider;
import ghidra.framework.main.ApplicationLevelOnlyPlugin;
import ghidra.framework.options.OptionType;
import ghidra.framework.options.OptionsChangeListener;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import javax.swing.SwingUtilities;
import javax.swing.Timer;

/**
 * Ghidra plugin that exposes program data via the Model Context Protocol (MCP).
 *
 * <p>This plugin runs at the application level (Project Window) and starts an embedded HTTP server
 * that provides MCP-compliant API access to Ghidra's reverse engineering capabilities for AI
 * assistants.
 */
@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = "GhidraMCP",
    category = "Application",
    shortDescription = "MCP Server Plugin",
    description =
        "Exposes program data via MCP (Model Context Protocol) HTTP API for AI-assisted reverse"
            + " engineering.",
    servicesProvided = {
      IGhidraMcpToolProvider.class,
      IGhidraMcpResourceProvider.class,
      IGhidraMcpPromptProvider.class,
      IGhidraMcpCompletionProvider.class
    })
public class GhidraMcpPlugin extends Plugin implements ApplicationLevelOnlyPlugin {

  public static final String OPTIONS_CATEGORY = "GhidraMCP HTTP Server";

  /**
   * @deprecated Use OPTIONS_CATEGORY instead
   */
  @Deprecated public static final String MCP_TOOL_OPTIONS_CATEGORY = OPTIONS_CATEGORY;

  private static final String PORT_OPTION = "Server Port";
  private static final String PORT_DESCRIPTION = "Port number for the embedded HTTP MCP server.";
  private static final int DEFAULT_PORT = 8080;
  private static final int RESTART_DEBOUNCE_MS = 1000;

  private int currentPort = DEFAULT_PORT;
  private OptionsChangeListener optionsListener;
  private Timer restartTimer;

  public GhidraMcpPlugin(PluginTool tool) {
    super(tool);

    Msg.info(this, "Initializing GhidraMCP plugin");

    initializeOptions();
    registerProviders();
    scheduleServerStart();
  }

  private void initializeOptions() {
    ToolOptions options = tool.getOptions(OPTIONS_CATEGORY);

    // Register port option
    options.registerOption(
        PORT_OPTION,
        OptionType.INT_TYPE,
        DEFAULT_PORT,
        new HelpLocation("GhidraMCP", "ServerPortOption"),
        PORT_DESCRIPTION,
        (java.util.function.Supplier<java.beans.PropertyEditor>) null);

    // Register tool enable/disable options
    GhidraMcpTools.registerOptions(options, "GhidraMCP");

    // Read current port
    currentPort = options.getInt(PORT_OPTION, DEFAULT_PORT);

    // Listen for changes
    optionsListener =
        (opts, name, oldValue, newValue) -> {
          if (PORT_OPTION.equals(name)) {
            int newPort = (Integer) newValue;
            if (newPort != currentPort) {
              Msg.info(this, "Port changing from " + currentPort + " to " + newPort);
              currentPort = newPort;
              scheduleServerRestart();
            }
          } else {
            // Tool option changed - restart to pick up new configuration
            scheduleServerRestart();
          }
        };
    options.addOptionsChangeListener(optionsListener);
  }

  private void registerProviders() {
    registerServiceProvided(IGhidraMcpToolProvider.class, new GhidraMcpTools(tool));
    registerServiceProvided(IGhidraMcpResourceProvider.class, new GhidraMcpResources(tool));
    registerServiceProvided(IGhidraMcpPromptProvider.class, new GhidraMcpPrompts(tool));
    registerServiceProvided(IGhidraMcpCompletionProvider.class, new GhidraMcpCompletions(tool));
  }

  private void scheduleServerStart() {
    SwingUtilities.invokeLater(
        () -> {
          GhidraMcpServer.start(currentPort, tool);
          Msg.info(this, "GhidraMCP server started on port " + currentPort);
        });
  }

  private void scheduleServerRestart() {
    if (restartTimer != null && restartTimer.isRunning()) {
      restartTimer.stop();
    }

    restartTimer =
        new Timer(
            RESTART_DEBOUNCE_MS,
            e -> {
              Msg.info(this, "Restarting MCP server due to configuration change");
              GhidraMcpServer.restart(currentPort, tool);
            });
    restartTimer.setRepeats(false);
    restartTimer.start();
  }

  @Override
  public void dispose() {
    if (optionsListener != null) {
      tool.getOptions(OPTIONS_CATEGORY).removeOptionsChangeListener(optionsListener);
    }

    if (restartTimer != null) {
      restartTimer.stop();
    }

    GhidraMcpServer.stop();
    Msg.info(this, "GhidraMCP plugin disposed");
    super.dispose();
  }

  /** Returns the current server port. */
  public int getPort() {
    return currentPort;
  }
}
