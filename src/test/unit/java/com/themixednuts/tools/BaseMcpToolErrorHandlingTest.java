package com.themixednuts.tools;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.models.McpResponse;
import com.themixednuts.utils.jsonschema.JsonSchema;
import ghidra.framework.plugintool.PluginTool;
import io.modelcontextprotocol.common.McpTransportContext;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpLoggableSession;
import io.modelcontextprotocol.spec.McpSchema;
import java.util.Map;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import tools.jackson.databind.node.ObjectNode;

class BaseMcpToolErrorHandlingTest {

  @Test
  void normalizeExceptionTreatsNullPointerAsInternalAndPreservesCause() {
    TestTool tool = new TestTool();
    NullPointerException npe = new NullPointerException("value");

    GhidraMcpException normalized = tool.normalizeForTest(npe, "inspect", "decompile");

    assertEquals(GhidraMcpError.ErrorType.INTERNAL, normalized.getErrorType());
    assertSame(npe, normalized.getCause());
    assertEquals("UNEXPECTED_ERROR", normalized.getErrorCode());
    assertNotNull(normalized.getErr().getContext());
    assertTrue(normalized.getMessage().contains("NullPointerException: value"));
  }

  @Test
  void normalizeExceptionPreservesIllegalArgumentCauseAndClassName() {
    TestTool tool = new TestTool();
    IllegalArgumentException iae = new IllegalArgumentException("bad arg");

    GhidraMcpException normalized = tool.normalizeForTest(iae, "inspect", "decompile");

    assertEquals(GhidraMcpError.ErrorType.VALIDATION, normalized.getErrorType());
    assertSame(iae, normalized.getCause());
    assertTrue(normalized.getMessage().contains("IllegalArgumentException: bad arg"));
  }

  @Test
  void specificationCallHandlerReturnsStructuredErrorForThrownNullPointerException() {
    FailingTool tool = new FailingTool();
    AsyncToolSpecification specification = tool.specification(null);
    McpAsyncServerExchange exchange =
        new McpAsyncServerExchange(
            "session-1",
            mock(McpLoggableSession.class),
            null,
            null,
            mock(McpTransportContext.class));
    McpSchema.CallToolRequest request =
        new McpSchema.CallToolRequest("failing_tool", Map.of("value", "ignored"));

    McpSchema.CallToolResult result = specification.callHandler().apply(exchange, request).block();

    assertNotNull(result);
    assertEquals(Boolean.TRUE, result.isError());
    assertNotNull(result.structuredContent());
    assertTrue(result.structuredContent() instanceof McpResponse<?>);

    McpResponse<?> response = (McpResponse<?>) result.structuredContent();
    assertFalse(response.isSuccess());
    assertNotNull(response.getError());
    assertEquals(GhidraMcpError.ErrorType.INTERNAL, response.getError().getErrorType());
    assertTrue(response.getError().getMessage().contains("NullPointerException: value"));
  }

  @GhidraMcpTool(
      name = "Test Tool",
      description = "Test helper tool",
      mcpName = "test_tool",
      mcpDescription = "Test helper tool")
  private static final class TestTool extends BaseMcpTool {
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
      return Mono.empty();
    }

    GhidraMcpException normalizeForTest(Throwable t, String toolName, String operation) {
      return normalizeException(t, toolName, operation);
    }
  }

  @GhidraMcpTool(
      name = "Failing Tool",
      description = "Test helper tool that fails",
      mcpName = "failing_tool",
      mcpDescription = "Test helper tool that fails")
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
