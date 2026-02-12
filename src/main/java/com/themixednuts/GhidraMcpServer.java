package com.themixednuts;

import com.themixednuts.services.IGhidraMcpCompletionProvider;
import com.themixednuts.services.IGhidraMcpPromptProvider;
import com.themixednuts.services.IGhidraMcpResourceProvider;
import com.themixednuts.services.IGhidraMcpToolProvider;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpServer;
import io.modelcontextprotocol.server.McpStatelessAsyncServer;
import io.modelcontextprotocol.server.McpStatelessServerFeatures.AsyncCompletionSpecification;
import io.modelcontextprotocol.server.McpStatelessServerFeatures.AsyncPromptSpecification;
import io.modelcontextprotocol.server.McpStatelessServerFeatures.AsyncResourceSpecification;
import io.modelcontextprotocol.server.McpStatelessServerFeatures.AsyncResourceTemplateSpecification;
import io.modelcontextprotocol.server.McpStatelessServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.server.transport.HttpServletStatelessServerTransport;
import io.modelcontextprotocol.spec.McpSchema.ServerCapabilities;
import java.util.Collections;
import java.util.List;
import org.eclipse.jetty.ee10.servlet.ServletContextHandler;
import org.eclipse.jetty.ee10.servlet.ServletHolder;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;

/**
 * Manages the lifecycle of the embedded Jetty server with a stateless MCP server.
 *
 * <p>This server is designed to be used with ApplicationLevelOnlyPlugin which ensures only a single
 * plugin instance exists. Therefore, we don't need reference counting.
 */
public final class GhidraMcpServer {

  private static final String SERVER_NAME = "ghidra-mcp";
  private static final String SERVER_VERSION = "0.5.3";
  private static final String MCP_PATH_SPEC = "/*";

  private static final Object lock = new Object();
  private static Server jettyServer;
  private static McpStatelessAsyncServer mcpServer;
  private static HttpServletStatelessServerTransport transportProvider;

  private GhidraMcpServer() {
    // Prevent instantiation
  }

  /**
   * Starts the MCP server.
   *
   * @param port The port to listen on
   * @param tool The Ghidra PluginTool for accessing services
   * @return true if started successfully
   */
  public static boolean start(int port, PluginTool tool) {
    synchronized (lock) {
      if (isRunning()) {
        Msg.info(GhidraMcpServer.class, "MCP server already running");
        return true;
      }

      try {
        Msg.info(GhidraMcpServer.class, "Starting MCP server on port " + port);

        McpSpecifications specs = loadSpecifications(tool);
        mcpServer = createMcpServer(specs);
        jettyServer = createJettyServer(port);
        jettyServer.start();

        Msg.info(
            GhidraMcpServer.class,
            "MCP server started on port " + port + " with " + specs.tools.size() + " tools");
        return true;
      } catch (Exception e) {
        Msg.error(GhidraMcpServer.class, "Failed to start MCP server", e);
        cleanup();
        return false;
      }
    }
  }

  /**
   * Stops the MCP server.
   *
   * @return true if stopped successfully
   */
  public static boolean stop() {
    synchronized (lock) {
      if (!isRunning()) {
        return true;
      }

      Msg.info(GhidraMcpServer.class, "Stopping MCP server");
      boolean success = cleanup();
      if (success) {
        Msg.info(GhidraMcpServer.class, "MCP server stopped");
      }
      return success;
    }
  }

  /**
   * Restarts the MCP server with a new port.
   *
   * @param port The new port
   * @param tool The Ghidra PluginTool
   * @return true if restart was successful
   */
  public static boolean restart(int port, PluginTool tool) {
    synchronized (lock) {
      Msg.info(GhidraMcpServer.class, "Restarting MCP server on port " + port);
      cleanup();
      return start(port, tool);
    }
  }

  /** Returns whether the server is currently running. */
  public static boolean isRunning() {
    return jettyServer != null && jettyServer.isRunning() && mcpServer != null;
  }

  /** Returns the server version. */
  public static String getVersion() {
    return SERVER_VERSION;
  }

  // =================== Private Implementation ===================

  private static boolean cleanup() {
    boolean success = true;

    if (mcpServer != null) {
      try {
        mcpServer.close();
      } catch (Exception e) {
        Msg.error(GhidraMcpServer.class, "Error closing MCP server", e);
        success = false;
      }
      mcpServer = null;
    }

    if (jettyServer != null) {
      try {
        jettyServer.stop();
        jettyServer.join();
      } catch (Exception e) {
        Msg.error(GhidraMcpServer.class, "Error stopping Jetty server", e);
        success = false;
      }
      jettyServer = null;
    }

    transportProvider = null;
    return success;
  }

  /** Container for all loaded MCP specifications. */
  private static final class McpSpecifications {
    final List<AsyncToolSpecification> tools;
    final List<AsyncResourceSpecification> resources;
    final List<AsyncResourceTemplateSpecification> resourceTemplates;
    final List<AsyncPromptSpecification> prompts;
    final List<AsyncCompletionSpecification> completions;

    McpSpecifications(
        List<AsyncToolSpecification> tools,
        List<AsyncResourceSpecification> resources,
        List<AsyncResourceTemplateSpecification> resourceTemplates,
        List<AsyncPromptSpecification> prompts,
        List<AsyncCompletionSpecification> completions) {
      this.tools = tools;
      this.resources = resources;
      this.resourceTemplates = resourceTemplates;
      this.prompts = prompts;
      this.completions = completions;
    }

    boolean hasResources() {
      return !resources.isEmpty() || !resourceTemplates.isEmpty();
    }

    boolean hasPrompts() {
      return !prompts.isEmpty();
    }

    boolean hasCompletions() {
      return !completions.isEmpty();
    }
  }

  private static McpSpecifications loadSpecifications(PluginTool tool) throws Exception {
    // Tools (required)
    IGhidraMcpToolProvider toolProvider = tool.getService(IGhidraMcpToolProvider.class);
    if (toolProvider == null) {
      throw new IllegalStateException("IGhidraMcpToolProvider service not available");
    }
    List<AsyncToolSpecification> tools = toolProvider.getAvailableToolSpecifications();
    Msg.info(GhidraMcpServer.class, "Loaded " + tools.size() + " tools");

    // Resources (optional)
    IGhidraMcpResourceProvider resourceProvider = tool.getService(IGhidraMcpResourceProvider.class);
    List<AsyncResourceSpecification> resources =
        resourceProvider != null
            ? resourceProvider.getResourceSpecifications()
            : Collections.emptyList();
    List<AsyncResourceTemplateSpecification> resourceTemplates =
        resourceProvider != null
            ? resourceProvider.getResourceTemplateSpecifications()
            : Collections.emptyList();
    if (!resources.isEmpty() || !resourceTemplates.isEmpty()) {
      Msg.info(
          GhidraMcpServer.class,
          "Loaded "
              + resources.size()
              + " resources and "
              + resourceTemplates.size()
              + " resource templates");
    }

    // Prompts (optional)
    IGhidraMcpPromptProvider promptProvider = tool.getService(IGhidraMcpPromptProvider.class);
    List<AsyncPromptSpecification> prompts =
        promptProvider != null ? promptProvider.getPromptSpecifications() : Collections.emptyList();
    if (!prompts.isEmpty()) {
      Msg.info(GhidraMcpServer.class, "Loaded " + prompts.size() + " prompts");
    }

    // Completions (optional)
    IGhidraMcpCompletionProvider completionProvider =
        tool.getService(IGhidraMcpCompletionProvider.class);
    List<AsyncCompletionSpecification> completions =
        completionProvider != null
            ? completionProvider.getCompletionSpecifications()
            : Collections.emptyList();
    if (!completions.isEmpty()) {
      Msg.info(GhidraMcpServer.class, "Loaded " + completions.size() + " completion handlers");
    }

    return new McpSpecifications(tools, resources, resourceTemplates, prompts, completions);
  }

  private static McpStatelessAsyncServer createMcpServer(McpSpecifications specs) {
    transportProvider = HttpServletStatelessServerTransport.builder().build();

    ServerCapabilities.Builder capabilities = ServerCapabilities.builder().tools(true).logging();

    if (specs.hasResources()) {
      capabilities.resources(true, true);
    }
    if (specs.hasPrompts()) {
      capabilities.prompts(true);
    }
    if (specs.hasCompletions()) {
      capabilities.completions();
    }

    var builder =
        McpServer.async(transportProvider)
            .serverInfo(SERVER_NAME, SERVER_VERSION)
            .capabilities(capabilities.build())
            .tools(specs.tools);

    if (!specs.resources.isEmpty()) {
      builder.resources(specs.resources);
    }
    if (!specs.resourceTemplates.isEmpty()) {
      builder.resourceTemplates(specs.resourceTemplates);
    }
    if (!specs.prompts.isEmpty()) {
      builder.prompts(specs.prompts);
    }
    if (!specs.completions.isEmpty()) {
      builder.completions(specs.completions);
    }

    return builder.build();
  }

  private static Server createJettyServer(int port) {
    Server server = new Server();
    ServerConnector connector = new ServerConnector(server);
    connector.setPort(port);
    server.addConnector(connector);

    ServletContextHandler context = new ServletContextHandler(ServletContextHandler.SESSIONS);
    context.setContextPath("/");
    server.setHandler(context);
    context.addServlet(new ServletHolder(transportProvider), MCP_PATH_SPEC);

    return server;
  }
}
