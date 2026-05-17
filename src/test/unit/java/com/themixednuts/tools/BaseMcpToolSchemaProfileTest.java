package com.themixednuts.tools;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.utils.JsonMapperHolder;
import com.themixednuts.utils.jsonschema.JsonSchema;
import ghidra.framework.plugintool.PluginTool;
import io.modelcontextprotocol.common.McpTransportContext;
import java.util.Map;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import tools.jackson.databind.node.ObjectNode;

class BaseMcpToolSchemaProfileTest {

  @Test
  void specificationBuiltWhenSchemaUsesSupportedTopLevelKeywordsOnly() {
    BaseMcpTool tool = new SupportedTopLevelSchemaTool();

    assertNotNull(tool.specification(null));
  }

  @Test
  void specificationBuiltWhenSchemaUsesUnsupportedTopLevelKeywords() {
    BaseMcpTool tool = new UnsupportedTopLevelSchemaTool();
    var specification = tool.specification(null);

    assertNotNull(specification);
    assertTrue(specification.tool().inputSchema().containsKey("allOf"));
  }

  @Test
  void specificationInputSchemaExposesConditionalPropertiesAtRoot() {
    var specification = new FunctionsTool().specification(null);

    assertNotNull(specification);
    Map<String, Object> schema = specification.tool().inputSchema();
    assertTrue(schema.containsKey("allOf"));

    @SuppressWarnings("unchecked")
    Map<String, Object> properties = (Map<String, Object>) schema.get("properties");
    assertTrue(properties.containsKey("file_name"));
    assertTrue(properties.containsKey("action"));
    assertTrue(properties.containsKey("address"));
    assertTrue(properties.containsKey("name"));
    assertTrue(properties.containsKey("page_size"));
    assertTrue(properties.containsKey("variable_symbol_id"));
  }

  @Test
  void specificationOmitsGenericOutputSchemaByDefault() {
    var specification = new SupportedTopLevelSchemaTool().specification(null);

    assertNotNull(specification);
    assertNull(specification.tool().outputSchema());
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
