package com.themixednuts.models;

import static org.junit.jupiter.api.Assertions.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Serialization tests for McpResponse using a vanilla ObjectMapper.
 *
 * <p>The MCP SDK uses its own internal ObjectMapper without Jdk8Module. These tests ensure
 * McpResponse serializes cleanly in that environment — not just with our custom mapper.
 */
class McpResponseTest {

  /** Vanilla mapper — no Jdk8Module, same as what the MCP SDK uses internally. */
  private static final ObjectMapper VANILLA_MAPPER = new ObjectMapper();

  @Test
  @DisplayName("Success response should serialize with vanilla ObjectMapper")
  void successResponseShouldSerializeWithVanillaMapper() {
    McpResponse<String> response = McpResponse.success("tool", "op", "hello");

    assertDoesNotThrow(() -> VANILLA_MAPPER.writeValueAsString(response));
  }

  @Test
  @DisplayName("Error response should serialize with vanilla ObjectMapper")
  void errorResponseShouldSerializeWithVanillaMapper() {
    McpResponse<String> response =
        McpResponse.error("tool", "op", GhidraMcpError.error("something broke"));

    assertDoesNotThrow(() -> VANILLA_MAPPER.writeValueAsString(response));
  }

  @Test
  @DisplayName("Paginated response should serialize with vanilla ObjectMapper")
  void paginatedResponseShouldSerializeWithVanillaMapper() {
    McpResponse<?> response =
        McpResponse.paginated("tool", "op", java.util.List.of("a", "b"), "cursor123", 2);

    assertDoesNotThrow(() -> VANILLA_MAPPER.writeValueAsString(response));
  }

  @Test
  @DisplayName("Null data response should serialize with vanilla ObjectMapper")
  void nullDataResponseShouldSerializeWithVanillaMapper() {
    McpResponse<Object> response = McpResponse.success("tool", "op", null);

    assertDoesNotThrow(() -> VANILLA_MAPPER.writeValueAsString(response));
  }
}
