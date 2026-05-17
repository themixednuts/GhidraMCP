package com.themixednuts;

import com.themixednuts.utils.McpTransportContexts;
import io.modelcontextprotocol.server.McpServer;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncCompletionSpecification;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncPromptSpecification;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncResourceSpecification;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncResourceTemplateSpecification;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.server.McpStatelessAsyncServer;
import io.modelcontextprotocol.server.McpStatelessServerFeatures;
import io.modelcontextprotocol.server.transport.HttpServletStatelessServerTransport;
import io.modelcontextprotocol.spec.McpSchema.ServerCapabilities;
import jakarta.servlet.http.HttpServlet;
import java.time.Duration;
import java.util.List;

final class McpStatelessRuntime {

  private final HttpServletStatelessServerTransport transport;
  private final McpStatelessAsyncServer server;

  private McpStatelessRuntime(
      HttpServletStatelessServerTransport transport, McpStatelessAsyncServer server) {
    this.transport = transport;
    this.server = server;
  }

  static McpStatelessRuntime create(
      HttpServletStatelessServerTransport transport,
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
      builder.tools(toStatelessTools(tools));
    }
    if (!resources.isEmpty()) {
      builder.resources(toStatelessResources(resources));
    }
    if (!resourceTemplates.isEmpty()) {
      builder.resourceTemplates(toStatelessResourceTemplates(resourceTemplates));
    }
    if (!prompts.isEmpty()) {
      builder.prompts(toStatelessPrompts(prompts));
    }
    if (!completions.isEmpty()) {
      builder.completions(toStatelessCompletions(completions));
    }

    return new McpStatelessRuntime(transport, builder.build());
  }

  HttpServlet servlet() {
    return transport;
  }

  boolean supportsResourceUpdateNotifications() {
    return false;
  }

  void notifyResourceUpdated(String uri) {
    // Stateless transport supports resource list/read, but has no server-to-client notification
    // channel for resources/updated.
  }

  void close() {
    server.close();
  }

  void addTool(AsyncToolSpecification spec) {
    server.addTool(toStatelessTool(spec)).block();
  }

  void removeTool(String name) {
    server.removeTool(name).block();
  }

  void addResource(AsyncResourceSpecification spec) {
    server.addResource(toStatelessResource(spec)).block();
  }

  void removeResource(String uri) {
    server.removeResource(uri).block();
  }

  void addResourceTemplate(AsyncResourceTemplateSpecification spec) {
    server.addResourceTemplate(toStatelessResourceTemplate(spec)).block();
  }

  void removeResourceTemplate(String uriTemplate) {
    server.removeResourceTemplate(uriTemplate).block();
  }

  void addPrompt(AsyncPromptSpecification spec) {
    server.addPrompt(toStatelessPrompt(spec)).block();
  }

  void removePrompt(String name) {
    server.removePrompt(name).block();
  }

  private static List<McpStatelessServerFeatures.AsyncToolSpecification> toStatelessTools(
      List<AsyncToolSpecification> specs) {
    return specs.stream().map(McpStatelessRuntime::toStatelessTool).toList();
  }

  private static McpStatelessServerFeatures.AsyncToolSpecification toStatelessTool(
      AsyncToolSpecification spec) {
    return new McpStatelessServerFeatures.AsyncToolSpecification(
        spec.tool(),
        (context, request) ->
            spec.callHandler()
                .apply(null, request)
                .contextWrite(ctx -> McpTransportContexts.put(ctx, context)));
  }

  private static List<McpStatelessServerFeatures.AsyncResourceSpecification> toStatelessResources(
      List<AsyncResourceSpecification> specs) {
    return specs.stream().map(McpStatelessRuntime::toStatelessResource).toList();
  }

  private static McpStatelessServerFeatures.AsyncResourceSpecification toStatelessResource(
      AsyncResourceSpecification spec) {
    return new McpStatelessServerFeatures.AsyncResourceSpecification(
        spec.resource(),
        (context, request) ->
            spec.readHandler()
                .apply(null, request)
                .contextWrite(ctx -> McpTransportContexts.put(ctx, context)));
  }

  private static List<McpStatelessServerFeatures.AsyncResourceTemplateSpecification>
      toStatelessResourceTemplates(List<AsyncResourceTemplateSpecification> specs) {
    return specs.stream().map(McpStatelessRuntime::toStatelessResourceTemplate).toList();
  }

  private static McpStatelessServerFeatures.AsyncResourceTemplateSpecification
      toStatelessResourceTemplate(AsyncResourceTemplateSpecification spec) {
    return new McpStatelessServerFeatures.AsyncResourceTemplateSpecification(
        spec.resourceTemplate(),
        (context, request) ->
            spec.readHandler()
                .apply(null, request)
                .contextWrite(ctx -> McpTransportContexts.put(ctx, context)));
  }

  private static List<McpStatelessServerFeatures.AsyncPromptSpecification> toStatelessPrompts(
      List<AsyncPromptSpecification> specs) {
    return specs.stream().map(McpStatelessRuntime::toStatelessPrompt).toList();
  }

  private static McpStatelessServerFeatures.AsyncPromptSpecification toStatelessPrompt(
      AsyncPromptSpecification spec) {
    return new McpStatelessServerFeatures.AsyncPromptSpecification(
        spec.prompt(),
        (context, request) ->
            spec.promptHandler()
                .apply(null, request)
                .contextWrite(ctx -> McpTransportContexts.put(ctx, context)));
  }

  private static List<McpStatelessServerFeatures.AsyncCompletionSpecification>
      toStatelessCompletions(List<AsyncCompletionSpecification> specs) {
    return specs.stream().map(McpStatelessRuntime::toStatelessCompletion).toList();
  }

  private static McpStatelessServerFeatures.AsyncCompletionSpecification toStatelessCompletion(
      AsyncCompletionSpecification spec) {
    return new McpStatelessServerFeatures.AsyncCompletionSpecification(
        spec.referenceKey(),
        (context, request) ->
            spec.completionHandler()
                .apply(null, request)
                .contextWrite(ctx -> McpTransportContexts.put(ctx, context)));
  }
}
