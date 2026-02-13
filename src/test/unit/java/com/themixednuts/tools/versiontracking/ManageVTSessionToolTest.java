package com.themixednuts.tools.versiontracking;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.themixednuts.models.OperationResult;
import org.junit.jupiter.api.Test;

class ManageVTSessionToolTest {

  @Test
  void closeResultReportsSessionStillOpenByAnotherConsumer() {
    OperationResult result = ManageVTSessionTool.closeResult("analysis.vt", true);

    assertEquals("close", result.getOperation());
    assertEquals("analysis.vt", result.getTarget());
    assertTrue(result.getMessage().contains("remains open by another consumer"));
  }

  @Test
  void closeResultReportsClosedWhenNoOtherConsumer() {
    OperationResult result = ManageVTSessionTool.closeResult("analysis.vt", false);

    assertEquals("close", result.getOperation());
    assertEquals("analysis.vt", result.getTarget());
    assertEquals("Session closed successfully", result.getMessage());
  }
}
