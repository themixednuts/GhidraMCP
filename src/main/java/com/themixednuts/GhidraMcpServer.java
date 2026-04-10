package com.themixednuts;

import com.themixednuts.services.IGhidraMcpCompletionProvider;
import com.themixednuts.services.IGhidraMcpPromptProvider;
import com.themixednuts.services.IGhidraMcpResourceProvider;
import com.themixednuts.services.IGhidraMcpToolProvider;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.Msg;
import io.modelcontextprotocol.common.McpTransportContext;
import io.modelcontextprotocol.server.McpAsyncServer;
import io.modelcontextprotocol.server.McpServer;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncCompletionSpecification;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncPromptSpecification;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncResourceSpecification;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncResourceTemplateSpecification;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.server.transport.HttpServletStreamableServerTransportProvider;
import io.modelcontextprotocol.spec.McpSchema.ResourcesUpdatedNotification;
import io.modelcontextprotocol.spec.McpSchema.ServerCapabilities;
import jakarta.servlet.DispatcherType;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.time.Duration;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import java.util.stream.Collectors;
import org.eclipse.jetty.ee10.servlet.FilterHolder;
import org.eclipse.jetty.ee10.servlet.ServletContextHandler;
import org.eclipse.jetty.ee10.servlet.ServletHolder;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;

/**
 * Manages the lifecycle of the embedded Jetty server with a streamable HTTP MCP server.
 *
 * <p>This server is designed to be used with ApplicationLevelOnlyPlugin which ensures only a single
 * plugin instance exists. Therefore, we don't need reference counting.
 */
public final class GhidraMcpServer {

  private static final String SERVER_NAME = "ghidra-mcp";
  private static final String SERVER_VERSION = "0.7.0-pre7";
  private static final String MCP_PATH_SPEC = "/*";
  private static final String MCP_SESSION_ID_HEADER = "MCP-Session-Id";
  private static final int DEFAULT_TIMEOUT_SECONDS = 600;
  private static Duration requestTimeout = Duration.ofSeconds(DEFAULT_TIMEOUT_SECONDS);
  private static final String SERVER_INSTRUCTIONS =
      "Use the 14 available tools for reverse engineering analysis:\n\n"
          + "Workflow: triage -> inspect -> analyze -> annotate\n"
          + "- Start with `project` (info, list_programs) and resources (strings, imports, memory)"
          + " for triage\n"
          + "- Use `inspect` (decompile, listing, references) to understand code at specific"
          + " locations\n"
          + "- Use `analyze` (demangle, rtti, graph, call_graph) for structural analysis\n"
          + "- Use `functions`, `symbols`, `data_types` to create and modify program entities\n"
          + "- Use `memory` to read/write bytes, define data types at addresses, and search\n"
          + "- Use `annotate` (set_comment, create_bookmark) to document findings\n"
          + "- Use `delete` for destructive removals (isolated for permission control)\n"
          + "- Use `vt_sessions` and `vt_operations` for binary comparison\n\n"
          + "All tools use an `action` parameter to select the operation.\n"
          + "Use `name_pattern` (regex) for filtering in list operations.\n"
          + "Identifiers use direct args: symbol_id, address, name (no target_type/target_value).\n"
          + "Use paginated cursors for large result sets.\n"
          + "Pass file_name explicitly when operating on program data.";

  private static final Object lock = new Object();
  private static final String PROGRAMS_RESOURCE_URI = "ghidra://programs";
  private static Server jettyServer;
  private static McpAsyncServer mcpServer;
  private static HttpServletStreamableServerTransportProvider transportProvider;
  private static McpSpecifications currentSpecifications;
  private static final Map<String, Set<String>> observedProgramResourceUris =
      new ConcurrentHashMap<>();

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
  public static boolean start(int port, int timeoutSeconds, PluginTool tool) {
    requestTimeout =
        Duration.ofSeconds(timeoutSeconds > 0 ? timeoutSeconds : DEFAULT_TIMEOUT_SECONDS);
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
        currentSpecifications = specs;

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
  public static boolean restart(int port, int timeoutSeconds, PluginTool tool) {
    synchronized (lock) {
      Msg.info(GhidraMcpServer.class, "Restarting MCP server on port " + port);
      cleanup();
      return start(port, timeoutSeconds, tool);
    }
  }

  /** Returns whether the server is currently running. */
  public static boolean isRunning() {
    return jettyServer != null && jettyServer.isRunning() && mcpServer != null;
  }

  /** Records a successfully-read concrete resource URI for future update notifications. */
  public static void recordResourceRead(String uri) {
    if (uri == null || uri.isBlank()) {
      return;
    }

    String programName = extractProgramName(uri);
    if (programName == null || programName.isBlank()) {
      return;
    }

    observedProgramResourceUris
        .computeIfAbsent(programName, ignored -> ConcurrentHashMap.newKeySet())
        .add(uri);
  }

  /** Emits a resource-updated notification for the static program list resource. */
  public static void notifyProgramsResourceUpdated() {
    notifyResourceUpdated(PROGRAMS_RESOURCE_URI);
  }

  /** Emits resource-updated notifications for observed concrete resources in a program. */
  public static void notifyProgramResourcesUpdated(String programName) {
    if (programName == null || programName.isBlank()) {
      return;
    }

    Set<String> observedUris = observedProgramResourceUris.get(programName);
    if (observedUris == null || observedUris.isEmpty()) {
      return;
    }

    for (String uri : new HashSet<>(observedUris)) {
      notifyResourceUpdated(uri);
    }
  }

  /** Re-keys observed resource URIs after a program rename. */
  public static void renameTrackedResourceProgram(String oldProgramName, String newProgramName) {
    if (oldProgramName == null
        || oldProgramName.isBlank()
        || newProgramName == null
        || newProgramName.isBlank()
        || oldProgramName.equals(newProgramName)) {
      return;
    }

    Set<String> oldUris = observedProgramResourceUris.remove(oldProgramName);
    if (oldUris == null || oldUris.isEmpty()) {
      return;
    }

    String oldSegment = encodeProgramName(oldProgramName);
    String newSegment = encodeProgramName(newProgramName);
    Set<String> newUris =
        observedProgramResourceUris.computeIfAbsent(
            newProgramName, ignored -> ConcurrentHashMap.newKeySet());
    for (String uri : oldUris) {
      newUris.add(
          uri.replace(
              "ghidra://program/" + oldSegment + "/", "ghidra://program/" + newSegment + "/"));
    }
  }

  /** Refreshes the live tool/resource/prompt set without restarting the server. */
  public static boolean refreshFeatures(PluginTool tool) {
    synchronized (lock) {
      if (!isRunning() || mcpServer == null || currentSpecifications == null) {
        return false;
      }

      try {
        McpSpecifications newSpecifications = loadSpecifications(tool);

        syncTools(currentSpecifications.tools, newSpecifications.tools);
        syncResources(currentSpecifications.resources, newSpecifications.resources);
        syncResourceTemplates(
            currentSpecifications.resourceTemplates, newSpecifications.resourceTemplates);
        syncPrompts(currentSpecifications.prompts, newSpecifications.prompts);

        currentSpecifications = newSpecifications;
        Msg.info(GhidraMcpServer.class, "Refreshed live MCP tools/resources/prompts");
        return true;
      } catch (Exception e) {
        Msg.error(GhidraMcpServer.class, "Failed to refresh live MCP features", e);
        return false;
      }
    }
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
    currentSpecifications = null;
    observedProgramResourceUris.clear();
    return success;
  }

  private static void notifyResourceUpdated(String uri) {
    synchronized (lock) {
      if (!isRunning() || mcpServer == null || uri == null || uri.isBlank()) {
        return;
      }

      try {
        mcpServer.notifyResourcesUpdated(new ResourcesUpdatedNotification(uri)).block();
      } catch (Exception e) {
        Msg.warn(GhidraMcpServer.class, "Failed to notify MCP resource update for " + uri, e);
      }
    }
  }

  private static String extractProgramName(String uri) {
    String prefix = "ghidra://program/";
    if (!uri.startsWith(prefix)) {
      return null;
    }

    int start = prefix.length();
    int end = uri.indexOf('/', start);
    if (end < 0) {
      return null;
    }

    String encodedProgramName = uri.substring(start, end);
    return java.net.URLDecoder.decode(encodedProgramName, java.nio.charset.StandardCharsets.UTF_8);
  }

  private static String encodeProgramName(String programName) {
    return java.net.URLEncoder.encode(programName, java.nio.charset.StandardCharsets.UTF_8)
        .replace("+", "%20");
  }

  private static void syncTools(
      List<AsyncToolSpecification> currentTools, List<AsyncToolSpecification> newTools) {
    Map<String, AsyncToolSpecification> currentByName =
        indexBy(currentTools, spec -> spec.tool().name());
    Map<String, AsyncToolSpecification> newByName = indexBy(newTools, spec -> spec.tool().name());

    removeMissing(
        currentByName.keySet(), newByName.keySet(), name -> mcpServer.removeTool(name).block());
    addMissing(newByName, currentByName.keySet(), spec -> mcpServer.addTool(spec).block());
  }

  private static void syncResources(
      List<AsyncResourceSpecification> currentResources,
      List<AsyncResourceSpecification> newResources) {
    Map<String, AsyncResourceSpecification> currentByUri =
        indexBy(currentResources, spec -> spec.resource().uri());
    Map<String, AsyncResourceSpecification> newByUri =
        indexBy(newResources, spec -> spec.resource().uri());

    removeMissing(
        currentByUri.keySet(), newByUri.keySet(), uri -> mcpServer.removeResource(uri).block());
    addMissing(newByUri, currentByUri.keySet(), spec -> mcpServer.addResource(spec).block());
  }

  private static void syncResourceTemplates(
      List<AsyncResourceTemplateSpecification> currentTemplates,
      List<AsyncResourceTemplateSpecification> newTemplates) {
    Map<String, AsyncResourceTemplateSpecification> currentByUriTemplate =
        indexBy(currentTemplates, spec -> spec.resourceTemplate().uriTemplate());
    Map<String, AsyncResourceTemplateSpecification> newByUriTemplate =
        indexBy(newTemplates, spec -> spec.resourceTemplate().uriTemplate());

    removeMissing(
        currentByUriTemplate.keySet(),
        newByUriTemplate.keySet(),
        uriTemplate -> mcpServer.removeResourceTemplate(uriTemplate).block());
    addMissing(
        newByUriTemplate,
        currentByUriTemplate.keySet(),
        spec -> mcpServer.addResourceTemplate(spec).block());
  }

  private static void syncPrompts(
      List<AsyncPromptSpecification> currentPrompts, List<AsyncPromptSpecification> newPrompts) {
    Map<String, AsyncPromptSpecification> currentByName =
        indexBy(currentPrompts, spec -> spec.prompt().name());
    Map<String, AsyncPromptSpecification> newByName =
        indexBy(newPrompts, spec -> spec.prompt().name());

    removeMissing(
        currentByName.keySet(), newByName.keySet(), name -> mcpServer.removePrompt(name).block());
    addMissing(newByName, currentByName.keySet(), spec -> mcpServer.addPrompt(spec).block());
  }

  private static <T> Map<String, T> indexBy(
      List<T> specifications, Function<T, String> keyFunction) {
    return specifications.stream()
        .collect(Collectors.toMap(keyFunction, Function.identity(), (left, right) -> right));
  }

  private static void removeMissing(
      Set<String> currentKeys, Set<String> newKeys, java.util.function.Consumer<String> remover) {
    currentKeys.stream().filter(key -> !newKeys.contains(key)).forEach(remover);
  }

  private static <T> void addMissing(
      Map<String, T> newSpecifications,
      Set<String> currentKeys,
      java.util.function.Consumer<T> adder) {
    newSpecifications.entrySet().stream()
        .filter(entry -> !currentKeys.contains(entry.getKey()))
        .map(Map.Entry::getValue)
        .forEach(adder);
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

  private static McpAsyncServer createMcpServer(McpSpecifications specs) {
    transportProvider =
        HttpServletStreamableServerTransportProvider.builder()
            .contextExtractor(
                request -> {
                  Map<String, Object> contextValues = new LinkedHashMap<>();
                  contextValues.put("http_method", request.getMethod());
                  contextValues.put("request_uri", request.getRequestURI());

                  String requestId = request.getHeader("X-Request-Id");
                  if (requestId != null && !requestId.isBlank()) {
                    contextValues.put("request_id", requestId);
                  }

                  String mcpSessionId = request.getHeader("MCP-Session-Id");
                  if (mcpSessionId != null && !mcpSessionId.isBlank()) {
                    contextValues.put("mcp_session_id", mcpSessionId);
                  }

                  String userAgent = request.getHeader("User-Agent");
                  if (userAgent != null && !userAgent.isBlank()) {
                    contextValues.put("user_agent", userAgent);
                  }

                  String remoteAddress = request.getRemoteAddr();
                  if (remoteAddress != null && !remoteAddress.isBlank()) {
                    contextValues.put("remote_address", remoteAddress);
                  }

                  contextValues.put(
                      "has_authorization_header",
                      request.getHeader("Authorization") != null
                          && !request.getHeader("Authorization").isBlank());

                  return McpTransportContext.create(contextValues);
                })
            .build();

    ServerCapabilities.Builder capabilities = ServerCapabilities.builder();
    capabilities.logging();

    if (!specs.tools.isEmpty()) {
      capabilities.tools(true);
    }

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
            .instructions(SERVER_INSTRUCTIONS)
            .requestTimeout(requestTimeout)
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
    server.setStopAtShutdown(true);
    server.setStopTimeout(10_000L);

    ServerConnector connector = new ServerConnector(server);
    connector.setPort(port);
    connector.setIdleTimeout(requestTimeout.toMillis());
    server.addConnector(connector);

    ServletContextHandler context = new ServletContextHandler(ServletContextHandler.SESSIONS);
    context.setContextPath("/");
    server.setHandler(context);
    context.addFilter(
        new FilterHolder(new PreSessionStreamableHttpFilter()),
        MCP_PATH_SPEC,
        EnumSet.of(DispatcherType.REQUEST));
    context.addServlet(new ServletHolder(transportProvider), MCP_PATH_SPEC);

    return server;
  }

  /**
   * Enforces spec-friendly behavior for pre-session GET requests.
   *
   * <p>For streamable HTTP, a client may probe the endpoint with GET before any session is
   * established. The underlying Java MCP transport currently returns 400 when the session header is
   * missing, which breaks some clients. Returning 405 here lets clients fall back to POST-only
   * request/response mode until a session-backed SSE stream is available.
   */
  private static final class PreSessionStreamableHttpFilter implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
        throws java.io.IOException, ServletException {
      if (!(request instanceof HttpServletRequest httpRequest)
          || !(response instanceof HttpServletResponse httpResponse)) {
        chain.doFilter(request, response);
        return;
      }

      boolean isGet = "GET".equalsIgnoreCase(httpRequest.getMethod());
      boolean hasSessionId =
          httpRequest.getHeader(MCP_SESSION_ID_HEADER) != null
              && !httpRequest.getHeader(MCP_SESSION_ID_HEADER).isBlank();

      if (isGet && !hasSessionId) {
        httpResponse.setStatus(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
        httpResponse.setHeader("Allow", "POST, DELETE");
        return;
      }

      chain.doFilter(request, response);
    }
  }
}
