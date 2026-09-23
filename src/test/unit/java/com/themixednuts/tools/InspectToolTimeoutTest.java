package com.themixednuts.tools;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;
import tools.jackson.databind.JsonNode;

class InspectToolTimeoutTest {

  @Test
  void decompileSchemaUsesConfiguredRequestTimeout() {
    JsonNode decompile = new InspectTool().schema().getNode().get("allOf").get(0).get("then");
    JsonNode timeout = decompile.get("properties").get("timeout");

    assertEquals(600, timeout.get("default").asInt());
    assertEquals(600, timeout.get("maximum").asInt());
  }
}
