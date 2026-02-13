package com.themixednuts.tools.versiontracking;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.themixednuts.exceptions.GhidraMcpException;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class ReadVTMatchesToolTest {

  @Test
  void rejectsPartialSingleMatchAddressInput() {
    GhidraMcpException ex =
        assertThrows(
            GhidraMcpException.class,
            () ->
                ReadVTMatchesTool.validateSingleMatchAddressArguments(
                    Optional.of("0x1000"), Optional.empty()));

    assertTrue(
        ex.getMessage().contains("source_address and destination_address must both be provided"));
  }

  @Test
  void acceptsBothOrNeitherSingleMatchAddresses() {
    assertDoesNotThrow(
        () ->
            ReadVTMatchesTool.validateSingleMatchAddressArguments(
                Optional.of("0x1000"), Optional.of("0x2000")));

    assertDoesNotThrow(
        () -> ReadVTMatchesTool.validateSingleMatchAddressArguments(Optional.empty(), Optional.empty()));
  }
}
