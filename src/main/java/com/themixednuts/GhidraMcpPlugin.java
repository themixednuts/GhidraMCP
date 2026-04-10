package com.themixednuts;

import com.themixednuts.services.IGhidraMcpCompletionProvider;
import com.themixednuts.services.IGhidraMcpPromptProvider;
import com.themixednuts.services.IGhidraMcpResourceProvider;
import com.themixednuts.services.IGhidraMcpToolProvider;
import com.themixednuts.utils.ToolOutputStore;
import ghidra.app.events.ProgramActivatedPluginEvent;
import ghidra.app.events.ProgramClosedPluginEvent;
import ghidra.app.events.ProgramOpenedPluginEvent;
import ghidra.framework.main.ApplicationLevelOnlyPlugin;
import ghidra.framework.options.OptionType;
import ghidra.framework.options.OptionsChangeListener;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginEvent;
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
    eventsConsumed = {
      ProgramOpenedPluginEvent.class,
      ProgramClosedPluginEvent.class,
      ProgramActivatedPluginEvent.class
    },
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
  private static final String TIMEOUT_OPTION = "Request Timeout (seconds)";
  private static final String TIMEOUT_DESCRIPTION =
      "Maximum time in seconds for a single MCP request. Increase for large binaries.";
  private static final int DEFAULT_TIMEOUT_SECONDS = 600;
  private static final String TOOL_OUTPUT_DIR_OPTION = "Tool Output Storage Directory";
  private static final String TOOL_OUTPUT_DIR_DESCRIPTION =
      "Directory where oversized tool outputs are stored for chunked retrieval."
          + " You can safely delete this folder when the server is not running.";
  private static final int DEFAULT_PORT = 8080;
  private static final int RESTART_DEBOUNCE_MS = 1000;

  private int currentPort = DEFAULT_PORT;
  private int currentTimeoutSeconds = DEFAULT_TIMEOUT_SECONDS;
  private OptionsChangeListener optionsListener;
  private Timer restartTimer;
  private boolean pendingFullRestart;
  private final GhidraResourceUpdateTracker resourceUpdateTracker;

  public GhidraMcpPlugin(PluginTool tool) {
    super(tool);

    Msg.info(this, "Initializing GhidraMCP plugin");
    resourceUpdateTracker = new GhidraResourceUpdateTracker();

    initializeOptions();
    registerProviders();
    scheduleServerStart();
  }

  @Override
  protected void init() {
    super.init();
    resourceUpdateTracker.start();
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

    // Register timeout option
    options.registerOption(
        TIMEOUT_OPTION,
        OptionType.INT_TYPE,
        DEFAULT_TIMEOUT_SECONDS,
        new HelpLocation("GhidraMCP", "RequestTimeoutOption"),
        TIMEOUT_DESCRIPTION,
        (java.util.function.Supplier<java.beans.PropertyEditor>) null);

    // Register tool output directory (informational, read-only)
    options.registerOption(
        TOOL_OUTPUT_DIR_OPTION,
        OptionType.STRING_TYPE,
        ToolOutputStore.ROOT_DIRECTORY.toAbsolutePath().toString(),
        new HelpLocation("GhidraMCP", "ToolOutputStorageOption"),
        TOOL_OUTPUT_DIR_DESCRIPTION);

    // Register tool enable/disable options
    GhidraMcpTools.registerOptions(options, "GhidraMCP");
    GhidraMcpResources.registerOptions(options, "GhidraMCP");
    GhidraMcpPrompts.registerOptions(options, "GhidraMCP");
    GhidraMcpCompletions.registerOptions(options, "GhidraMCP");

    // Read current values
    currentPort = options.getInt(PORT_OPTION, DEFAULT_PORT);
    currentTimeoutSeconds = options.getInt(TIMEOUT_OPTION, DEFAULT_TIMEOUT_SECONDS);

    // Listen for changes
    optionsListener =
        (opts, name, oldValue, newValue) -> {
          if (PORT_OPTION.equals(name)) {
            int newPort = (Integer) newValue;
            if (newPort != currentPort) {
              Msg.info(this, "Port changing from " + currentPort + " to " + newPort);
              currentPort = newPort;
              scheduleServerReconfigure(true);
            }
          } else if (TIMEOUT_OPTION.equals(name)) {
            int newTimeout = (Integer) newValue;
            if (newTimeout != currentTimeoutSeconds) {
              Msg.info(
                  this,
                  "Timeout changing from " + currentTimeoutSeconds + "s to " + newTimeout + "s");
              currentTimeoutSeconds = newTimeout;
              scheduleServerReconfigure(true);
            }
          } else if (TOOL_OUTPUT_DIR_OPTION.equals(name)) {
            return;
          } else if (isCompletionOption(name)) {
            scheduleServerReconfigure(true);
          } else {
            scheduleServerReconfigure(false);
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
          GhidraMcpServer.start(currentPort, currentTimeoutSeconds, tool);
          Msg.info(this, "GhidraMCP server started on port " + currentPort);
        });
  }

  private boolean isCompletionOption(String optionName) {
    return optionName != null && optionName.startsWith("Completion: ");
  }

  private void scheduleServerReconfigure(boolean restartRequired) {
    pendingFullRestart |= restartRequired;

    if (restartTimer != null && restartTimer.isRunning()) {
      restartTimer.stop();
    }

    restartTimer =
        new Timer(
            RESTART_DEBOUNCE_MS,
            e -> {
              boolean restart = pendingFullRestart;
              pendingFullRestart = false;

              if (restart) {
                Msg.info(this, "Restarting MCP server due to configuration change");
                GhidraMcpServer.restart(currentPort, currentTimeoutSeconds, tool);
                return;
              }

              Msg.info(this, "Refreshing live MCP features due to configuration change");
              if (!GhidraMcpServer.refreshFeatures(tool)) {
                Msg.info(this, "Falling back to MCP server restart after refresh failure");
                GhidraMcpServer.restart(currentPort, currentTimeoutSeconds, tool);
              }
            });
    restartTimer.setRepeats(false);
    restartTimer.start();
  }

  @Override
  public void processEvent(PluginEvent event) {
    resourceUpdateTracker.processEvent(event);
  }

  @Override
  public void dispose() {
    if (optionsListener != null) {
      tool.getOptions(OPTIONS_CATEGORY).removeOptionsChangeListener(optionsListener);
    }

    if (restartTimer != null) {
      restartTimer.stop();
    }

    resourceUpdateTracker.stop();

    GhidraMcpServer.stop();
    Msg.info(this, "GhidraMCP plugin disposed");
    super.dispose();
  }

  /** Returns the current server port. */
  public int getPort() {
    return currentPort;
  }
}
