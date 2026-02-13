package com.themixednuts.tools.versiontracking;

import static org.junit.jupiter.api.Assertions.assertEquals;

import ghidra.feature.vt.api.main.VTAssociationStatus;
import org.junit.jupiter.api.Test;

class ManageVTMatchesToolTest {

  @Test
  void actionNameMapsAvailableToClear() {
    assertEquals("clear", ManageVTMatchesTool.actionNameForStatus(VTAssociationStatus.AVAILABLE));
  }

  @Test
  void actionNameMapsAcceptedAndRejectedAsExpected() {
    assertEquals("accept", ManageVTMatchesTool.actionNameForStatus(VTAssociationStatus.ACCEPTED));
    assertEquals("reject", ManageVTMatchesTool.actionNameForStatus(VTAssociationStatus.REJECTED));
  }
}
