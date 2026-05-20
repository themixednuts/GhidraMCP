package com.themixednuts;

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
import jakarta.servlet.http.HttpServlet;
import java.time.Duration;
import java.util.List;

final class McpRuntime {

  private final HttpServletStreamableServerTransportProvider transport;
  private final McpAsyncServer server;

  private McpRuntime(
      HttpServletStreamableServerTransportProvider transport, McpAsyncServer server) {
    this.transport = transport;
    this.server = server;
  }

  static McpRuntime create(
      HttpServletStreamableServerTransportProvider transport,
      String serverName,
      String serverVersion,
      String instructions,
      Duration requestTimeout,
      ServerCapabilities capabilities,
      List<AsyncToolSpecification> tools,
      List<AsyncResourceSpecification> resources,
      List<AsyncResourceTemplateSpecification> resourceTemplates,
      List<AsyncPromptSpecification> prompts,
      List<AsyncCompletionSpecification> completions) {
    var builder =
        McpServer.async(transport)
            .serverInfo(serverName, serverVersion)
            .instructions(instructions)
            .requestTimeout(requestTimeout)
            .capabilities(capabilities);

    if (!tools.isEmpty()) {
      builder.tools(tools);
    }
    if (!resources.isEmpty()) {
      builder.resources(resources);
    }
    if (!resourceTemplates.isEmpty()) {
      builder.resourceTemplates(resourceTemplates);
    }
    if (!prompts.isEmpty()) {
      builder.prompts(prompts);
    }
    if (!completions.isEmpty()) {
      builder.completions(completions);
    }

    return new McpRuntime(transport, builder.build());
  }

  HttpServlet servlet() {
    return transport;
  }

  boolean supportsResourceUpdateNotifications() {
    return true;
  }

  void notifyResourceUpdated(String uri) {
    server.notifyResourcesUpdated(new ResourcesUpdatedNotification(uri)).block();
  }

  void close() {
    server.close();
  }

  void addTool(AsyncToolSpecification spec) {
    server.addTool(spec).block();
  }

  void removeTool(String name) {
    server.removeTool(name).block();
  }

  void addResource(AsyncResourceSpecification spec) {
    server.addResource(spec).block();
  }

  void removeResource(String uri) {
    server.removeResource(uri).block();
  }

  void addResourceTemplate(AsyncResourceTemplateSpecification spec) {
    server.addResourceTemplate(spec).block();
  }

  void removeResourceTemplate(String uriTemplate) {
    server.removeResourceTemplate(uriTemplate).block();
  }

  void addPrompt(AsyncPromptSpecification spec) {
    server.addPrompt(spec).block();
  }

  void removePrompt(String name) {
    server.removePrompt(name).block();
  }
}
