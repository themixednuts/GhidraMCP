package com.themixednuts.tools.versiontracking;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.themixednuts.exceptions.GhidraMcpException;
import ghidra.feature.vt.api.main.VTAssociationStatus;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class VTOperationsToolTest {

  @Test
  void actionNameMapsAvailableToClear() {
    assertEquals("clear", VTOperationsTool.actionNameForStatus(VTAssociationStatus.AVAILABLE));
  }

  @Test
  void actionNameMapsAcceptedAndRejectedAsExpected() {
    assertEquals("accept", VTOperationsTool.actionNameForStatus(VTAssociationStatus.ACCEPTED));
    assertEquals("reject", VTOperationsTool.actionNameForStatus(VTAssociationStatus.REJECTED));
  }

  @Test
  void rejectsPartialSingleMatchAddressInput() {
    GhidraMcpException ex =
        assertThrows(
            GhidraMcpException.class,
            () ->
                VTOperationsTool.validateSingleMatchAddressArguments(
                    Optional.of("0x1000"), Optional.empty()));

    assertTrue(
        ex.getMessage().contains("source_address and destination_address must both be provided"));
  }

  @Test
  void acceptsBothOrNeitherSingleMatchAddresses() {
    assertDoesNotThrow(
        () ->
            VTOperationsTool.validateSingleMatchAddressArguments(
                Optional.of("0x1000"), Optional.of("0x2000")));

    assertDoesNotThrow(
        () ->
            VTOperationsTool.validateSingleMatchAddressArguments(
                Optional.empty(), Optional.empty()));
  }
}
