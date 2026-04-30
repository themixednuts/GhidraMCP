package com.themixednuts.tools;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.models.McpResponse;
import com.themixednuts.utils.CursorDataResult;
import com.themixednuts.utils.ToolOutputStore;
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
import io.modelcontextprotocol.spec.McpSchema.TextContent;
import java.time.Duration;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
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
    try (TransportFixture fixture = openTransport(new FailingTool().specification(null))) {
      McpSchema.CallToolResult result = fixture.callTool("failing_tool", Map.of());

      assertNotNull(result);
      assertEquals(Boolean.TRUE, result.isError());
      assertNotNull(result.structuredContent());
      assertTrue(result.structuredContent() instanceof Map<?, ?>);

      Map<String, Object> structured = structured(result);
      // success/duration_ms/error_type/error_code dropped from envelope. CallToolResult.isError
      // is the canonical failure signal; error fields flatten into the structured root via
      // @JsonUnwrapped, so there is no nested "error" wrapper to traverse.
      assertFalse(structured.containsKey("success"));
      assertFalse(structured.containsKey("error"));
      assertFalse(structured.containsKey("error_type"));
      assertFalse(structured.containsKey("error_code"));
      assertTrue(String.valueOf(structured.get("message")).contains("NullPointerException: value"));
      assertFalse(result.content().isEmpty());
    }
  }

  @Test
  void successfulToolsCanReturnTextWhilePreservingStructuredContent() throws Exception {
    try (TransportFixture fixture = openTransport(new TextRenderingTool().specification(null))) {
      McpSchema.CallToolResult result = fixture.callTool("text_rendering_tool", Map.of());

      assertNotNull(result);
      assertEquals(Boolean.FALSE, result.isError());

      Map<String, Object> structured = structured(result);
      assertFalse(structured.containsKey("success"));
      assertFalse(structured.containsKey("duration_ms"));
      assertEquals("structured", dataMap(structured).get("mode"));
      assertEquals("00401000 90 NOP", text(result));
    }
  }

  @Test
  void cursorDataResultsExposeTextInDataWithoutWrappingItInAJsonArray() throws Exception {
    try (TransportFixture fixture = openTransport(new CursorTextTool().specification(null))) {
      McpSchema.CallToolResult result = fixture.callTool("cursor_text_tool", Map.of());

      assertNotNull(result);
      assertEquals(Boolean.FALSE, result.isError());

      Map<String, Object> structured = structured(result);
      assertFalse(structured.containsKey("success"));
      assertEquals("00401000 55 PUSH EBP\n00401001 8b ec MOV EBP,ESP", structured.get("data"));
      assertEquals("cursor-2", structured.get("next_cursor"));
      assertEquals("00401000 55 PUSH EBP\n00401001 8b ec MOV EBP,ESP", text(result));
    }
  }

  @Test
  void oversizedSuccessResponsesKeepRetrievalMetadataAndInlinePreview() throws Exception {
    try (TransportFixture fixture = openTransport(new LargeTextTool().specification(null))) {
      McpSchema.CallToolResult result = fixture.callTool("large_text_tool", Map.of());

      assertNotNull(result);
      assertEquals(Boolean.FALSE, result.isError());

      Map<String, Object> structured = structured(result);
      Map<String, Object> data = dataMap(structured);
      assertEquals(
          "Output exceeded inline size and was stored for chunked retrieval.", data.get("message"));
      assertEquals("read_tool_output", data.get("retrieval_tool"));
      assertEquals(ToolOutputStore.VIEW_TEXT, data.get("preferred_read_view"));
      assertTrue(data.get("view_total_chars") instanceof Map<?, ?>);
      assertEquals(Boolean.TRUE, data.get("inline_preview_available"));
      assertNotNull(data.get("output_id"));

      String preview = text(result);
      assertTrue(preview.contains("LINE 0000"));
      assertTrue(preview.length() < LargeTextTool.LARGE_TEXT.length());
    }
  }

  @Test
  void readToolOutputTrimsEscapedChunksBeforeTheyBecomeOversizedAgain() throws Exception {
    String sessionId = "ses_transport_" + UUID.randomUUID().toString().replace("-", "");
    ToolOutputStore.StoredOutputRef ref =
        ToolOutputStore.store(sessionId, "fixture_tool", "execute", buildEscapedPayload());

    try (TransportFixture fixture = openTransport(new ReadToolOutputTool().specification(null))) {
      McpSchema.CallToolResult result =
          fixture.callTool(
              "read_tool_output",
              Map.of(
                  "action",
                  "read",
                  "session_id",
                  sessionId,
                  "output_id",
                  ref.outputId(),
                  "max_chars",
                  ToolOutputStore.MAX_READ_CHUNK_CHARS));

      assertNotNull(result);
      assertEquals(Boolean.FALSE, result.isError());

      Map<String, Object> structured = structured(result);
      Map<String, Object> data = dataMap(structured);
      assertTrue(data.containsKey("content"), "Expected an inline output chunk");
      assertEquals(ref.outputId(), data.get("outputId"));
      assertEquals(
          ToolOutputStore.MAX_READ_CHUNK_CHARS, ((Number) data.get("requestedChars")).intValue());
      assertEquals(ToolOutputStore.VIEW_JSON, data.get("view"));
      assertEquals(ToolOutputStore.FORMAT_JSON, data.get("contentFormat"));
      assertTrue(((Number) data.get("returnedChars")).intValue() > 0);
      assertTrue(
          ((Number) data.get("returnedChars")).intValue()
              < ((Number) data.get("requestedChars")).intValue());
      assertEquals(Boolean.TRUE, data.get("hasMore"));
      assertTrue(((Number) data.get("remainingChars")).intValue() > 0);
    }
  }

  private static Map<String, Object> structured(McpSchema.CallToolResult result) {
    @SuppressWarnings("unchecked")
    Map<String, Object> structured = (Map<String, Object>) result.structuredContent();
    return structured;
  }

  private static Map<String, Object> dataMap(Map<String, Object> structured) {
    @SuppressWarnings("unchecked")
    Map<String, Object> data = (Map<String, Object>) structured.get("data");
    return data;
  }

  private static String text(McpSchema.CallToolResult result) {
    return result.content().stream()
        .filter(TextContent.class::isInstance)
        .map(TextContent.class::cast)
        .map(TextContent::text)
        .findFirst()
        .orElse("");
  }

  private static String buildEscapedPayload() {
    StringBuilder builder = new StringBuilder();
    for (int i = 0; i < 2500; i++) {
      builder
          .append("{\"line\":")
          .append(i)
          .append(",\"text\":\"quoted \\\"value\\\" \\\\ path\"}\n");
    }
    return builder.toString();
  }

  private static TransportFixture openTransport(AsyncToolSpecification... specifications)
      throws Exception {
    HttpServletStreamableServerTransportProvider transportProvider =
        HttpServletStreamableServerTransportProvider.builder().build();
    McpAsyncServer server =
        McpServer.async(transportProvider)
            .serverInfo("test-server", "1.0.0")
            .capabilities(McpSchema.ServerCapabilities.builder().tools(true).build())
            .tools(specifications)
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
            .requestTimeout(Duration.ofSeconds(10))
            .initializationTimeout(Duration.ofSeconds(10))
            .build();

    McpSchema.InitializeResult initializeResult = client.initialize().block();
    assertNotNull(initializeResult);

    return new TransportFixture(client, server, jetty);
  }

  private record TransportFixture(McpAsyncClient client, McpAsyncServer server, Server jetty)
      implements AutoCloseable {
    private McpSchema.CallToolResult callTool(String name, Map<String, Object> args) {
      return client.callTool(new McpSchema.CallToolRequest(name, args)).block();
    }

    @Override
    public void close() throws Exception {
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

  @GhidraMcpTool(
      name = "Text Rendering Tool",
      description = "Test helper tool that returns text and structured content",
      mcpName = "text_rendering_tool",
      mcpDescription = "Test helper tool that returns text and structured content")
  private static final class TextRenderingTool extends BaseMcpTool {
    @Override
    public JsonSchema schema() {
      ObjectNode root = mapper.createObjectNode();
      root.put("type", "object");
      root.set("properties", mapper.createObjectNode());
      return new JsonSchema(root);
    }

    @Override
    protected Optional<String> createSuccessTextContent(
        McpResponse<?> response, Map<String, Object> args, String toolName, String operation) {
      return Optional.of("00401000 90 NOP");
    }

    @Override
    public Mono<? extends Object> execute(
        McpTransportContext context, Map<String, Object> args, PluginTool tool) {
      return Mono.just(Map.of("mode", "structured", "kind", "listing"));
    }
  }

  @GhidraMcpTool(
      name = "Large Text Tool",
      description = "Test helper tool that forces oversized output storage",
      mcpName = "large_text_tool",
      mcpDescription = "Test helper tool that forces oversized output storage")
  private static final class LargeTextTool extends BaseMcpTool {
    private static final String LARGE_TEXT = buildLargeText();

    @Override
    public JsonSchema schema() {
      ObjectNode root = mapper.createObjectNode();
      root.put("type", "object");
      root.set("properties", mapper.createObjectNode());
      return new JsonSchema(root);
    }

    @Override
    protected Optional<String> createSuccessTextContent(
        McpResponse<?> response, Map<String, Object> args, String toolName, String operation) {
      return Optional.of(LARGE_TEXT);
    }

    @Override
    public Mono<? extends Object> execute(
        McpTransportContext context, Map<String, Object> args, PluginTool tool) {
      return Mono.just(Map.of("kind", "decompile", "decompiled_code", LARGE_TEXT));
    }

    private static String buildLargeText() {
      StringBuilder builder = new StringBuilder();
      for (int i = 0; i < 3000; i++) {
        builder.append(String.format("LINE %04d: int value_%04d = %d;%n", i, i, i));
      }
      return builder.toString();
    }
  }

  @GhidraMcpTool(
      name = "Cursor Text Tool",
      description = "Test helper tool that returns compact paged text",
      mcpName = "cursor_text_tool",
      mcpDescription = "Test helper tool that returns compact paged text")
  private static final class CursorTextTool extends BaseMcpTool {
    @Override
    public JsonSchema schema() {
      ObjectNode root = mapper.createObjectNode();
      root.put("type", "object");
      root.set("properties", mapper.createObjectNode());
      return new JsonSchema(root);
    }

    @Override
    protected Optional<String> createSuccessTextContent(
        McpResponse<?> response, Map<String, Object> args, String toolName, String operation) {
      return Optional.ofNullable(response.getData()).map(Object::toString);
    }

    @Override
    public Mono<? extends Object> execute(
        McpTransportContext context, Map<String, Object> args, PluginTool tool) {
      return Mono.just(
          new CursorDataResult<>("00401000 55 PUSH EBP\n00401001 8b ec MOV EBP,ESP", "cursor-2"));
    }
  }
}
