package com.themixednuts.tools;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.themixednuts.annotation.GhidraMcpTool;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.reflections.Reflections;
import org.reflections.scanners.Scanners;

class ToolAnnotationHintsCoverageTest {

  private static final String TOOL_PACKAGE = "com.themixednuts.tools";

  private static final Set<String> READ_ONLY_IDEMPOTENT_TOOL_NAMES =
      Set.of("inspect", "analyze", "script_guidance");

  @Test
  void toolMetadataMatchesConventions() {
    Reflections reflections = new Reflections(TOOL_PACKAGE, Scanners.SubTypes);
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

      String mcpName = annotation.mcpName();

      if (requiresReadOnlyAndIdempotentHints(mcpName)) {
        if (!annotation.readOnlyHint()) {
          failures.add(toolClass.getSimpleName() + " must set readOnlyHint=true");
        }
        if (!annotation.idempotentHint()) {
          failures.add(toolClass.getSimpleName() + " must set idempotentHint=true");
        }
      }

      if (mcpName.equals("delete") && !annotation.destructiveHint()) {
        failures.add(toolClass.getSimpleName() + " must set destructiveHint=true");
      }

      String description = annotation.mcpDescription();
      if (description.isBlank() || description.length() > 800) {
        failures.add(
            toolClass.getSimpleName() + " must have an MCP description of 1-800 characters");
      }
      if (description.contains("<use_case>") || description.contains("<examples>")) {
        failures.add(
            toolClass.getSimpleName() + " must not duplicate guidance in its MCP description");
      }
    }

    assertFalse(
        failures.isEmpty() && toolClasses.isEmpty(),
        "No tool classes discovered for hint coverage");
    assertTrue(failures.isEmpty(), String.join("\n", failures));
  }

  @Test
  void closedWorldAndDebuggerHintsAppearInToolSpecifications() {
    var inspect = new InspectTool().specification(null).tool();
    assertEquals("Inspect", inspect.title());
    assertEquals(Boolean.FALSE, inspect.annotations().openWorldHint());
    assertEquals(
        Boolean.TRUE, new DebuggerTool().specification(null).tool().annotations().openWorldHint());
  }

  private boolean requiresReadOnlyAndIdempotentHints(String mcpName) {
    return mcpName.startsWith("read_")
        || mcpName.startsWith("list_")
        || READ_ONLY_IDEMPOTENT_TOOL_NAMES.contains(mcpName);
  }
}
