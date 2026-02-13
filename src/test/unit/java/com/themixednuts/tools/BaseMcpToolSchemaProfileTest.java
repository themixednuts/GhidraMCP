package com.themixednuts.tools;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.utils.JsonMapperHolder;
import com.themixednuts.utils.jsonschema.JsonSchema;
import ghidra.framework.plugintool.PluginTool;
import io.modelcontextprotocol.common.McpTransportContext;
import java.util.Map;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;

class BaseMcpToolSchemaProfileTest {

  @Test
  void specificationBuiltWhenSchemaUsesSupportedTopLevelKeywordsOnly() {
    BaseMcpTool tool = new SupportedTopLevelSchemaTool();

    assertNotNull(tool.specification(null));
  }

  @Test
  void specificationBuiltWhenSchemaUsesUnsupportedTopLevelKeywords() {
    BaseMcpTool tool = new UnsupportedTopLevelSchemaTool();

    assertNotNull(tool.specification(null));
  }

  @GhidraMcpTool(
      name = "Supported Schema Tool",
      description = "Test tool with supported schema keywords.",
      mcpName = "supported_schema_tool",
      mcpDescription = "Test tool")
  private static final class SupportedTopLevelSchemaTool extends BaseMcpTool {
    @Override
    public JsonSchema schema() {
      ObjectNode root = JsonMapperHolder.getMapper().createObjectNode();
      root.put("type", "object");
      root.set("properties", JsonMapperHolder.getMapper().createObjectNode());
      root.putArray("required").add("value");
      root.put("additionalProperties", false);
      return new JsonSchema(root);
    }

    @Override
    public Mono<? extends Object> execute(
        McpTransportContext context, Map<String, Object> args, PluginTool tool) {
      return Mono.just(Map.of("ok", true));
    }
  }

  @GhidraMcpTool(
      name = "Unsupported Schema Tool",
      description = "Test tool with unsupported schema keywords.",
      mcpName = "unsupported_schema_tool",
      mcpDescription = "Test tool")
  private static final class UnsupportedTopLevelSchemaTool extends BaseMcpTool {
    @Override
    public JsonSchema schema() {
      ObjectNode root = JsonMapperHolder.getMapper().createObjectNode();
      root.put("type", "object");
      root.set("properties", JsonMapperHolder.getMapper().createObjectNode());
      root.putArray("allOf").add(JsonMapperHolder.getMapper().createObjectNode());
      return new JsonSchema(root);
    }

    @Override
    public Mono<? extends Object> execute(
        McpTransportContext context, Map<String, Object> args, PluginTool tool) {
      return Mono.just(Map.of("ok", true));
    }
  }
}
