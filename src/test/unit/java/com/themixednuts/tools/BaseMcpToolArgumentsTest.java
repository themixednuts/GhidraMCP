package com.themixednuts.tools;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.themixednuts.exceptions.GhidraMcpException;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class BaseMcpToolArgumentsTest {

  @Test
  void malformedObjectArrayIsRejectedAtTheArgumentBoundary() {
    FunctionsTool tool = new FunctionsTool();

    GhidraMcpException error =
        assertThrows(
            GhidraMcpException.class,
            () -> {
              List<Map<String, Object>> parameters =
                  tool.getOptionalListArgument(
                          Map.of("parameters", List.of("int count")), "parameters")
                      .orElseThrow();
              for (Map<String, Object> parameter : parameters) {
                parameter.get("name");
              }
            });

    assertEquals("Invalid parameters[0]: expected an object", error.getErr().getMessage());
  }
}
