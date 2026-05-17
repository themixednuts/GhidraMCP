package com.themixednuts.tools;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.themixednuts.annotation.GhidraMcpResource;
import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.models.McpResponse;
import com.themixednuts.resources.BaseMcpResource;
import com.themixednuts.utils.CursorDataResult;
import com.themixednuts.utils.McpTransportContexts;
import com.themixednuts.utils.PaginatedResult;
import com.themixednuts.utils.ToolOutputStore;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.draft7.SchemaBuilder;
import ghidra.framework.plugintool.PluginTool;
import io.modelcontextprotocol.client.McpAsyncClient;
import io.modelcontextprotocol.client.McpClient;
import io.modelcontextprotocol.client.transport.HttpClientStreamableHttpTransport;
import io.modelcontextprotocol.common.McpTransportContext;
import io.modelcontextprotocol.server.McpServer;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncResourceSpecification;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.server.McpStatelessAsyncServer;
import io.modelcontextprotocol.server.McpStatelessServerFeatures;
import io.modelcontextprotocol.server.transport.HttpServletStatelessServerTransport;
import io.modelcontextprotocol.spec.McpSchema;
import io.modelcontextprotocol.spec.McpSchema.TextContent;
import io.modelcontextprotocol.spec.McpSchema.TextResourceContents;
import java.time.Duration;
import java.util.List;
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
  void statelessToolsCallWithoutProgressTokenReturnsStructuredError() throws Exception {
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
  void statelessToolsReceiveTransportContextFromRequest() throws Exception {
    try (TransportFixture fixture = openTransport(new ContextEchoTool().specification(null))) {
      McpSchema.CallToolResult result = fixture.callTool("context_echo_tool", Map.of());

      assertNotNull(result);
      assertEquals(Boolean.FALSE, result.isError());
      assertEquals("stateless-test", structured(result).get("transport"));
    }
  }

  @Test
  void statelessTransportListsAndReadsResources() throws Exception {
    try (TransportFixture fixture =
        openTransport(List.of(), List.of(new StaticTextResource().toResourceSpecification(null)))) {
      McpSchema.ListResourcesResult resources = fixture.listResources();
      assertNotNull(resources);
      assertEquals(1, resources.resources().size());
      assertEquals("test://fixture", resources.resources().get(0).uri());

      McpSchema.ReadResourceResult result = fixture.readResource("test://fixture");
      assertNotNull(result);
      assertEquals(1, result.contents().size());
      assertTrue(result.contents().get(0) instanceof TextResourceContents);

      TextResourceContents content = (TextResourceContents) result.contents().get(0);
      assertEquals("test://fixture", content.uri());
      assertEquals("text/plain", content.mimeType());
      assertEquals("stateless-test:test://fixture", content.text());
    }
  }

  @Test
  void successfulToolsCanReturnTextWhilePreservingStructuredContent() throws Exception {
    try (TransportFixture fixture = openTransport(new TextRenderingTool().specification(null))) {
      McpSchema.CallToolResult result = fixture.callTool("text_rendering_tool", Map.of());

      assertNotNull(result);
      assertEquals(Boolean.FALSE, result.isError());

      Map<String, Object> structured = structured(result);
      // Object-shaped payloads now flatten into the structured root — no "data" wrapper level
      // for the agent to traverse. success/duration_ms remain dropped.
      assertFalse(structured.containsKey("success"));
      assertFalse(structured.containsKey("duration_ms"));
      assertFalse(structured.containsKey("data"));
      assertEquals("structured", structured.get("mode"));
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
      // String payloads stay under "data" — they need a key to coexist with next_cursor.
      assertEquals("00401000 55 PUSH EBP\n00401001 8b ec MOV EBP,ESP", structured.get("data"));
      assertEquals("cursor-2", structured.get("next_cursor"));
      assertEquals("00401000 55 PUSH EBP\n00401001 8b ec MOV EBP,ESP", text(result));
    }
  }

  @Test
  void successfulToolsCanReturnPaginatedRowsWithMissingOptionalFields() throws Exception {
    try (TransportFixture fixture = openTransport(new SymbolLikeListTool().specification(null))) {
      McpSchema.CallToolResult result = fixture.callTool("symbol_like_list_tool", Map.of());

      assertNotNull(result);
      assertEquals(Boolean.FALSE, result.isError());

      Map<String, Object> structured = structured(result);
      assertEquals("cursor-2", structured.get("next_cursor"));
      assertTrue(structured.get("data") instanceof List<?>);
      List<?> rows = (List<?>) structured.get("data");
      assertEquals(1, rows.size());
      assertTrue(rows.get(0) instanceof Map<?, ?>);
      Map<?, ?> row = (Map<?, ?>) rows.get(0);
      assertEquals("Global", row.get("name"));
      assertFalse(row.containsKey("address"));
    }
  }

  @Test
  void constConditionalsDoNotTreatMissingDiscriminantsAsMatchingStructuredOutput()
      throws Exception {
    try (TransportFixture fixture =
        openTransport(new ConditionalSymbolLikeListTool().specification(null))) {
      McpSchema.CallToolResult result =
          fixture.callTool("conditional_symbol_like_list_tool", Map.of());

      assertNotNull(result);
      assertEquals(Boolean.FALSE, result.isError());

      Map<String, Object> structured = structured(result);
      assertTrue(structured.get("data") instanceof List<?>);
      List<?> rows = (List<?>) structured.get("data");
      assertEquals(1, rows.size());
      assertFalse(((Map<?, ?>) rows.get(0)).containsKey("address"));
    }
  }

  @Test
  void oversizedSuccessResponsesKeepRetrievalMetadataAndInlinePreview() throws Exception {
    try (TransportFixture fixture = openTransport(new LargeTextTool().specification(null))) {
      McpSchema.CallToolResult result = fixture.callTool("large_text_tool", Map.of());

      assertNotNull(result);
      assertEquals(Boolean.FALSE, result.isError());

      Map<String, Object> structured = structured(result);
      // Inline notice is an object payload — its fields flatten to the structured root.
      assertTrue(((String) structured.get("message")).startsWith("Output exceeded inline size"));
      assertNotNull(structured.get("session_id"));
      assertNotNull(structured.get("output_id"));
      assertFalse(structured.containsKey("retrieval_tool"));
      assertFalse(structured.containsKey("preferred_read_view"));
      assertFalse(structured.containsKey("view_total_chars"));
      assertFalse(structured.containsKey("inline_preview_available"));
      assertFalse(structured.containsKey("data"));

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
      // Read chunks expose content plus the normal top-level next_cursor continuation.
      assertTrue(structured.containsKey("content"), "Expected an inline output chunk");
      String content = (String) structured.get("content");
      assertTrue(content.length() > 0);
      assertTrue(content.length() < ToolOutputStore.MAX_READ_CHUNK_CHARS);
      assertNotNull(structured.get("next_cursor"));
      assertFalse(structured.containsKey("nextOffset"));
      assertFalse(structured.containsKey("outputId"));
      assertFalse(structured.containsKey("view"));
      assertFalse(structured.containsKey("contentFormat"));
      assertFalse(structured.containsKey("requestedChars"));
      assertFalse(structured.containsKey("returnedChars"));
      assertFalse(structured.containsKey("totalChars"));
      assertFalse(structured.containsKey("remainingChars"));
      assertFalse(structured.containsKey("hasMore"));
      assertFalse(structured.containsKey("data"));
    }
  }

  private static Map<String, Object> structured(McpSchema.CallToolResult result) {
    @SuppressWarnings("unchecked")
    Map<String, Object> structured = (Map<String, Object>) result.structuredContent();
    return structured;
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
    return openTransport(List.of(specifications), List.of());
  }

  private static TransportFixture openTransport(
      List<AsyncToolSpecification> toolSpecifications,
      List<AsyncResourceSpecification> resourceSpecifications)
      throws Exception {
    HttpServletStatelessServerTransport transport =
        HttpServletStatelessServerTransport.builder()
            .messageEndpoint("/mcp")
            .contextExtractor(
                request -> McpTransportContext.create(Map.of("transport", "stateless-test")))
            .build();

    McpSchema.ServerCapabilities.Builder capabilities = McpSchema.ServerCapabilities.builder();
    if (!toolSpecifications.isEmpty()) {
      capabilities.tools(false);
    }
    if (!resourceSpecifications.isEmpty()) {
      capabilities.resources(false, false);
    }

    var serverBuilder =
        McpServer.async(transport)
            .serverInfo("test-server", "1.0.0")
            .capabilities(capabilities.build());
    if (!toolSpecifications.isEmpty()) {
      serverBuilder.tools(toStatelessTools(toolSpecifications));
    }
    if (!resourceSpecifications.isEmpty()) {
      serverBuilder.resources(toStatelessResources(resourceSpecifications));
    }

    McpStatelessAsyncServer server = serverBuilder.build();

    Server jetty = new Server(0);
    ServletContextHandler context = new ServletContextHandler(ServletContextHandler.NO_SESSIONS);
    context.setContextPath("/");
    context.addServlet(new ServletHolder(transport), "/mcp");
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

  private static List<McpStatelessServerFeatures.AsyncToolSpecification> toStatelessTools(
      List<AsyncToolSpecification> specifications) {
    return specifications.stream()
        .map(
            spec ->
                new McpStatelessServerFeatures.AsyncToolSpecification(
                    spec.tool(),
                    (context, request) ->
                        spec.callHandler()
                            .apply(null, request)
                            .contextWrite(ctx -> McpTransportContexts.put(ctx, context))))
        .toList();
  }

  private static List<McpStatelessServerFeatures.AsyncResourceSpecification> toStatelessResources(
      List<AsyncResourceSpecification> specifications) {
    return specifications.stream()
        .map(
            spec ->
                new McpStatelessServerFeatures.AsyncResourceSpecification(
                    spec.resource(),
                    (context, request) ->
                        spec.readHandler()
                            .apply(null, request)
                            .contextWrite(ctx -> McpTransportContexts.put(ctx, context))))
        .toList();
  }

  private record TransportFixture(
      McpAsyncClient client, McpStatelessAsyncServer server, Server jetty)
      implements AutoCloseable {
    private McpSchema.CallToolResult callTool(String name, Map<String, Object> args) {
      return client.callTool(new McpSchema.CallToolRequest(name, args)).block();
    }

    private McpSchema.ListResourcesResult listResources() {
      return client.listResources().block();
    }

    private McpSchema.ReadResourceResult readResource(String uri) {
      return client.readResource(new McpSchema.ReadResourceRequest(uri)).block();
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
      name = "Context Echo Tool",
      description = "Test helper tool that echoes transport context",
      mcpName = "context_echo_tool",
      mcpDescription = "Test helper tool that echoes transport context")
  private static final class ContextEchoTool extends BaseMcpTool {
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
      return Mono.just(Map.of("transport", String.valueOf(context.get("transport"))));
    }
  }

  @GhidraMcpResource(
      uri = "test://fixture",
      name = "Fixture Resource",
      description = "Test helper resource exposed over stateless transport",
      mimeType = "text/plain")
  private static final class StaticTextResource extends BaseMcpResource {
    @Override
    public Mono<String> read(McpTransportContext context, String uri, PluginTool tool) {
      return Mono.just(String.valueOf(context.get("transport")) + ":" + uri);
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

  @GhidraMcpTool(
      name = "Symbol Like List Tool",
      description = "Test helper tool that returns paginated rows with optional fields absent",
      mcpName = "symbol_like_list_tool",
      mcpDescription = "Test helper tool that returns paginated rows with optional fields absent")
  private static final class SymbolLikeListTool extends BaseMcpTool {
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
      return Mono.just(
          new PaginatedResult<>(
              List.of(Map.of("name", "Global", "type", "NAMESPACE")), "cursor-2"));
    }
  }

  @GhidraMcpTool(
      name = "Conditional Symbol Like List Tool",
      description = "Test helper tool with a guarded symbol_type conditional",
      mcpName = "conditional_symbol_like_list_tool",
      mcpDescription = "Test helper tool with a guarded symbol_type conditional")
  private static final class ConditionalSymbolLikeListTool extends BaseMcpTool {
    @Override
    public JsonSchema schema() {
      return SchemaBuilder.objectDraft7(mapper)
          .property("symbol_type", SchemaBuilder.string(mapper))
          .allOf(
              SchemaBuilder.objectDraft7(mapper)
                  .ifThen(
                      SchemaBuilder.objectDraft7(mapper)
                          .property(
                              "symbol_type", SchemaBuilder.string(mapper).constValue("label")),
                      SchemaBuilder.objectDraft7(mapper).requiredProperty("address")))
          .build();
    }

    @Override
    public Mono<? extends Object> execute(
        McpTransportContext context, Map<String, Object> args, PluginTool tool) {
      return Mono.just(
          new PaginatedResult<>(
              List.of(Map.of("name", "Global", "type", "NAMESPACE")), "cursor-2"));
    }
  }
}
