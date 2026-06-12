package com.themixednuts.tools;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.networknt.schema.Error;
import com.networknt.schema.InputFormat;
import com.networknt.schema.Schema;
import com.networknt.schema.SchemaRegistry;
import com.networknt.schema.dialect.Dialects;
import com.themixednuts.annotation.GhidraMcpResource;
import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.models.McpResponse;
import com.themixednuts.resources.BaseMcpResource;
import com.themixednuts.ui.ToolOutcome;
import com.themixednuts.utils.CursorDataResult;
import com.themixednuts.utils.PaginatedResult;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.draft7.SchemaBuilder;
import ghidra.framework.plugintool.PluginTool;
import io.modelcontextprotocol.client.McpAsyncClient;
import io.modelcontextprotocol.client.McpClient;
import io.modelcontextprotocol.client.transport.HttpClientStreamableHttpTransport;
import io.modelcontextprotocol.common.McpTransportContext;
import io.modelcontextprotocol.server.McpAsyncServer;
import io.modelcontextprotocol.server.McpServer;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncResourceSpecification;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.server.transport.HttpServletStreamableServerTransportProvider;
import io.modelcontextprotocol.spec.McpSchema;
import io.modelcontextprotocol.spec.McpSchema.TextContent;
import io.modelcontextprotocol.spec.McpSchema.TextResourceContents;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.eclipse.jetty.ee10.servlet.ServletContextHandler;
import org.eclipse.jetty.ee10.servlet.ServletHolder;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.JsonNode;
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
      assertStructuredContentMatchesOutputSchema(fixture, "failing_tool", result);
    }
  }

  @Test
  void streamableToolsReceiveTransportContextFromRequest() throws Exception {
    try (TransportFixture fixture = openTransport(new ContextEchoTool().specification(null))) {
      McpSchema.CallToolResult result = fixture.callTool("context_echo_tool", Map.of());

      assertNotNull(result);
      assertEquals(Boolean.FALSE, result.isError());
      assertEquals("streamable-test", structured(result).get("transport"));
      assertStructuredContentMatchesOutputSchema(fixture, "context_echo_tool", result);
    }
  }

  @Test
  void streamableTransportListsReadsAndSubscribesResources() throws Exception {
    try (TransportFixture fixture =
        openTransport(List.of(), List.of(new StaticTextResource().toResourceSpecification(null)))) {
      assertEquals(Boolean.TRUE, fixture.client.getServerCapabilities().resources().subscribe());
      assertEquals(Boolean.TRUE, fixture.client.getServerCapabilities().resources().listChanged());

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
      assertEquals("streamable-test:test://fixture", content.text());

      fixture.subscribeResource("test://fixture");
      fixture.unsubscribeResource("test://fixture");
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
      assertStructuredContentMatchesOutputSchema(fixture, "text_rendering_tool", result);
    }
  }

  @Test
  void toolOutcomesUnwrapPayloadBeforeStructuredTransportSerialization() throws Exception {
    try (TransportFixture fixture = openTransport(new UiOutcomeTool().specification(null))) {
      McpSchema.CallToolResult result = fixture.callTool("ui_outcome_tool", Map.of());

      assertNotNull(result);
      assertEquals(Boolean.FALSE, result.isError());

      Map<String, Object> structured = structured(result);
      assertEquals("wrapped", structured.get("mode"));
      assertFalse(structured.containsKey("uiEffects"));
      assertFalse(structured.containsKey("ui_effects"));
      assertFalse(structured.containsKey("data"));
      assertStructuredContentMatchesOutputSchema(fixture, "ui_outcome_tool", result);
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
      assertStructuredContentMatchesOutputSchema(fixture, "cursor_text_tool", result);
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
      assertStructuredContentMatchesOutputSchema(fixture, "symbol_like_list_tool", result);
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
      assertStructuredContentMatchesOutputSchema(
          fixture, "conditional_symbol_like_list_tool", result);
    }
  }

  @Test
  void largeSuccessResponsesKeepStructuredPayloadAndUseBoundedNoticeWhenNoInlineBudgetRemains()
      throws Exception {
    try (TransportFixture fixture = openTransport(new LargeTextTool().specification(null))) {
      McpSchema.CallToolResult result = fixture.callTool("large_text_tool", Map.of());

      assertNotNull(result);
      assertEquals(Boolean.FALSE, result.isError());

      Map<String, Object> structured = structured(result);
      assertEquals("decompile", structured.get("kind"));
      assertTrue(String.valueOf(structured.get("decompiled_code")).contains("LINE 0000"));
      assertFalse(structured.containsKey("message"));
      assertFalse(structured.containsKey("session_id"));
      assertFalse(structured.containsKey("output_id"));

      String text = text(result);
      assertTrue(text.startsWith("Structured response is too large for text fallback"));
      assertTrue(text.length() < 160);
      assertFalse(text.contains("LINE 0000"));
      assertStructuredContentMatchesOutputSchema(fixture, "large_text_tool", result);
    }
  }

  @Test
  void largeOptionalTextFallsBackToCompactStructuredJsonWhenItFits() throws Exception {
    try (TransportFixture fixture = openTransport(new LargeTextPreviewTool().specification(null))) {
      McpSchema.CallToolResult result = fixture.callTool("large_text_preview_tool", Map.of());

      assertNotNull(result);
      assertEquals(Boolean.FALSE, result.isError());

      Map<String, Object> structured = structured(result);
      assertEquals("summary", structured.get("kind"));

      assertEquals("{\"kind\":\"summary\"}", text(result));
      assertStructuredContentMatchesOutputSchema(fixture, "large_text_preview_tool", result);
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

  private static void assertStructuredContentMatchesOutputSchema(
      TransportFixture fixture, String toolName, McpSchema.CallToolResult result) {
    Map<String, Object> outputSchema = fixture.outputSchema(toolName);
    assertNotNull(outputSchema, toolName + " should advertise outputSchema");
    assertEquals("object", outputSchema.get("type"));
    assertNotNull(result.structuredContent(), toolName + " should return structuredContent");

    List<Error> errors = validate(outputSchema, result.structuredContent());
    assertTrue(
        errors.isEmpty(),
        () -> toolName + " structuredContent did not match outputSchema: " + errors);
  }

  private static List<Error> validate(Map<String, Object> outputSchema, Object structuredContent) {
    SchemaRegistry schemaRegistry = SchemaRegistry.withDialect(Dialects.getDraft202012());
    String schemaJson;
    try {
      schemaJson = BaseMcpTool.mapper.writeValueAsString(outputSchema);
    } catch (JacksonException e) {
      throw new AssertionError("Failed to serialize output schema", e);
    }
    Schema schema = schemaRegistry.getSchema(schemaJson, InputFormat.JSON);
    JsonNode structuredNode = BaseMcpTool.mapper.valueToTree(structuredContent);
    return schema.validate(structuredNode);
  }

  private static TransportFixture openTransport(AsyncToolSpecification... specifications)
      throws Exception {
    return openTransport(List.of(specifications), List.of());
  }

  private static TransportFixture openTransport(
      List<AsyncToolSpecification> toolSpecifications,
      List<AsyncResourceSpecification> resourceSpecifications)
      throws Exception {
    HttpServletStreamableServerTransportProvider transport =
        HttpServletStreamableServerTransportProvider.builder()
            .mcpEndpoint("/mcp")
            .contextExtractor(
                request -> McpTransportContext.create(Map.of("transport", "streamable-test")))
            .build();

    McpSchema.ServerCapabilities.Builder capabilities = McpSchema.ServerCapabilities.builder();
    if (!toolSpecifications.isEmpty()) {
      capabilities.tools(true);
    }
    if (!resourceSpecifications.isEmpty()) {
      capabilities.resources(true, true);
    }

    var serverBuilder =
        McpServer.async(transport)
            .serverInfo("test-server", "1.0.0")
            .capabilities(capabilities.build());
    if (!toolSpecifications.isEmpty()) {
      serverBuilder.tools(toolSpecifications);
    }
    if (!resourceSpecifications.isEmpty()) {
      serverBuilder.resources(resourceSpecifications);
    }

    McpAsyncServer server = serverBuilder.build();

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

  private record TransportFixture(McpAsyncClient client, McpAsyncServer server, Server jetty)
      implements AutoCloseable {
    private McpSchema.CallToolResult callTool(String name, Map<String, Object> args) {
      return client.callTool(new McpSchema.CallToolRequest(name, args)).block();
    }

    private Map<String, Object> outputSchema(String name) {
      McpSchema.ListToolsResult tools = client.listTools().block();
      assertNotNull(tools);
      return tools.tools().stream()
          .filter(tool -> name.equals(tool.name()))
          .findFirst()
          .map(McpSchema.Tool::outputSchema)
          .orElse(null);
    }

    private McpSchema.ListResourcesResult listResources() {
      return client.listResources().block();
    }

    private McpSchema.ReadResourceResult readResource(String uri) {
      return client.readResource(new McpSchema.ReadResourceRequest(uri)).block();
    }

    private void subscribeResource(String uri) {
      client.subscribeResource(new McpSchema.SubscribeRequest(uri)).block();
    }

    private void unsubscribeResource(String uri) {
      client.unsubscribeResource(new McpSchema.UnsubscribeRequest(uri)).block();
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
      description = "Test helper resource exposed over streamable transport",
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
      name = "UI Outcome Tool",
      description = "Test helper tool that returns a payload with UI effects",
      mcpName = "ui_outcome_tool",
      mcpDescription = "Test helper tool that returns a payload with UI effects")
  private static final class UiOutcomeTool extends BaseMcpTool {
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
      return Mono.just(ToolOutcome.of(Map.of("mode", "wrapped")));
    }
  }

  @GhidraMcpTool(
      name = "Large Text Tool",
      description = "Test helper tool that returns a large structured payload",
      mcpName = "large_text_tool",
      mcpDescription = "Test helper tool that returns a large structured payload")
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
      name = "Large Text Preview Tool",
      description =
          "Test helper tool that returns large optional text with compact structured data",
      mcpName = "large_text_preview_tool",
      mcpDescription =
          "Test helper tool that returns large optional text with compact structured data")
  private static final class LargeTextPreviewTool extends BaseMcpTool {
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
      return Optional.of(LargeTextTool.LARGE_TEXT);
    }

    @Override
    public Mono<? extends Object> execute(
        McpTransportContext context, Map<String, Object> args, PluginTool tool) {
      return Mono.just(Map.of("kind", "summary"));
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
