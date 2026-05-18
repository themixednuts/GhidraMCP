package com.themixednuts.tools;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.utils.JsonMapperHolder;
import com.themixednuts.utils.jsonschema.JsonSchema;
import ghidra.framework.plugintool.PluginTool;
import io.modelcontextprotocol.common.McpTransportContext;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.reflections.Reflections;
import org.reflections.scanners.Scanners;
import reactor.core.publisher.Mono;
import tools.jackson.databind.node.ObjectNode;

class BaseMcpToolSchemaProfileTest {

  private static final List<String> CLAUDE_UNSUPPORTED_ROOT_COMPOSITION_KEYS =
      List.of("allOf", "anyOf", "oneOf");

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
    assertFalse(specification.tool().inputSchema().containsKey("allOf"));
    assertFalse(specification.tool().inputSchema().containsKey("anyOf"));
    assertFalse(specification.tool().inputSchema().containsKey("oneOf"));
  }

  @Test
  void specificationInputSchemaExposesConditionalPropertiesAtRoot() {
    var specification = new FunctionsTool().specification(null);

    assertNotNull(specification);
    Map<String, Object> schema = specification.tool().inputSchema();
    assertFalse(schema.containsKey("allOf"));
    assertFalse(schema.containsKey("anyOf"));
    assertFalse(schema.containsKey("oneOf"));

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
  void allToolInputSchemasAvoidClaudeUnsupportedRootCompositionKeywords() throws Exception {
    Reflections reflections = new Reflections("com.themixednuts.tools", Scanners.SubTypes);
    Set<Class<? extends BaseMcpTool>> toolClasses = reflections.getSubTypesOf(BaseMcpTool.class);

    List<String> failures = new ArrayList<>();
    for (Class<? extends BaseMcpTool> toolClass : toolClasses) {
      if (Modifier.isAbstract(toolClass.getModifiers()) || toolClass.getEnclosingClass() != null) {
        continue;
      }

      GhidraMcpTool annotation = toolClass.getAnnotation(GhidraMcpTool.class);
      if (annotation == null) {
        continue;
      }

      BaseMcpTool tool = toolClass.getDeclaredConstructor().newInstance();
      var specification = tool.specification(null);
      if (specification == null) {
        failures.add(toolClass.getSimpleName() + " did not build a tool specification");
        continue;
      }

      Map<String, Object> inputSchema = specification.tool().inputSchema();
      for (String key : CLAUDE_UNSUPPORTED_ROOT_COMPOSITION_KEYS) {
        if (inputSchema.containsKey(key)) {
          failures.add(annotation.mcpName() + " exposes top-level " + key);
        }
      }
    }

    assertFalse(toolClasses.isEmpty(), "No tool classes discovered for input schema coverage");
    assertTrue(failures.isEmpty(), String.join("\n", failures));
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
