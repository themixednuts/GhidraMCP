package com.themixednuts.tools;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.utils.jsonschema.JsonSchema;
import ghidra.framework.plugintool.PluginTool;
import io.modelcontextprotocol.client.McpAsyncClient;
import io.modelcontextprotocol.client.McpClient;
import io.modelcontextprotocol.client.transport.HttpClientStreamableHttpTransport;
import io.modelcontextprotocol.common.McpTransportContext;
import io.modelcontextprotocol.server.McpAsyncServer;
import io.modelcontextprotocol.server.McpServer;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.server.transport.HttpServletStreamableServerTransportProvider;
import io.modelcontextprotocol.spec.McpSchema;
import java.time.Duration;
import java.util.Map;
import org.eclipse.jetty.ee10.servlet.ServletContextHandler;
import org.eclipse.jetty.ee10.servlet.ServletHolder;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import tools.jackson.databind.node.ObjectNode;

class BaseMcpToolTransportRegressionTest {

  @Test
  void streamableToolsCallWithoutProgressTokenReturnsStructuredError() throws Exception {
    FailingTool tool = new FailingTool();
    AsyncToolSpecification specification = tool.specification(null);

    HttpServletStreamableServerTransportProvider transportProvider =
        HttpServletStreamableServerTransportProvider.builder().build();
    McpAsyncServer server =
        McpServer.async(transportProvider)
            .serverInfo("test-server", "1.0.0")
            .capabilities(McpSchema.ServerCapabilities.builder().tools(true).build())
            .tools(specification)
            .build();

    Server jetty = new Server(0);
    ServletContextHandler context = new ServletContextHandler(ServletContextHandler.SESSIONS);
    context.setContextPath("/");
    context.addServlet(new ServletHolder(transportProvider), "/mcp");
    jetty.setHandler(context);
    jetty.start();

    int port = ((ServerConnector) jetty.getConnectors()[0]).getLocalPort();
    HttpClientStreamableHttpTransport clientTransport =
        HttpClientStreamableHttpTransport.builder("http://127.0.0.1:" + port + "/mcp").build();
    McpAsyncClient client =
        McpClient.async(clientTransport)
            .clientInfo(new McpSchema.Implementation("test-client", "1.0.0"))
            .requestTimeout(Duration.ofSeconds(5))
            .initializationTimeout(Duration.ofSeconds(5))
            .build();

    try {
      McpSchema.InitializeResult initializeResult = client.initialize().block();
      assertNotNull(initializeResult);

      McpSchema.CallToolResult result =
          client.callTool(new McpSchema.CallToolRequest("failing_tool", Map.of())).block();

      assertNotNull(result);
      assertEquals(Boolean.TRUE, result.isError());
      assertNotNull(result.structuredContent());
      assertTrue(result.structuredContent() instanceof Map<?, ?>);

      @SuppressWarnings("unchecked")
      Map<String, Object> structured = (Map<String, Object>) result.structuredContent();
      assertEquals(Boolean.FALSE, structured.get("success"));
      assertTrue(structured.get("error") instanceof Map<?, ?>);

      @SuppressWarnings("unchecked")
      Map<String, Object> error = (Map<String, Object>) structured.get("error");
      assertEquals("internal", error.get("error_type"));
      assertTrue(String.valueOf(error.get("message")).contains("NullPointerException: value"));
      assertFalse(result.content().isEmpty());
    } finally {
      client.closeGracefully().block(Duration.ofSeconds(5));
      server.closeGracefully().block(Duration.ofSeconds(5));
      jetty.stop();
      jetty.join();
    }
  }

  @GhidraMcpTool(
      name = "Failing Tool",
      description = "Test helper tool that fails over transport",
      mcpName = "failing_tool",
      mcpDescription = "Test helper tool that fails over transport")
  private static final class FailingTool extends BaseMcpTool {
    @Override
    public JsonSchema schema() {
      ObjectNode root = mapper.createObjectNode();
      root.put("type", "object");
      root.set("properties", mapper.createObjectNode());
      return new JsonSchema(root);
    }

    @Override
    public Mono<? extends Object> execute(
        McpTransportContext context, Map<String, Object> args, PluginTool tool) {
      return Mono.error(new NullPointerException("value"));
    }
  }
}
