package com.themixednuts;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.modelcontextprotocol.server.transport.ServerTransportSecurityException;
import io.modelcontextprotocol.server.transport.ServerTransportSecurityValidator;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class GhidraMcpServerTransportSecurityTest {

  @Test
  void localNativeClientsCanOmitOrigin() {
    ServerTransportSecurityValidator validator =
        GhidraMcpServer.createLocalTransportSecurityValidator();

    assertDoesNotThrow(() -> validator.validateHeaders(Map.of("Host", List.of("127.0.0.1:8080"))));
  }

  @Test
  void localBrowserOriginsAreAllowed() {
    ServerTransportSecurityValidator validator =
        GhidraMcpServer.createLocalTransportSecurityValidator();

    assertDoesNotThrow(
        () ->
            validator.validateHeaders(
                Map.of(
                    "Host", List.of("localhost:8080"),
                    "Origin", List.of("http://localhost:3000"))));
  }

  @Test
  void remoteOriginsAreRejected() {
    ServerTransportSecurityValidator validator =
        GhidraMcpServer.createLocalTransportSecurityValidator();

    ServerTransportSecurityException error =
        assertThrows(
            ServerTransportSecurityException.class,
            () ->
                validator.validateHeaders(
                    Map.of(
                        "Host", List.of("127.0.0.1:8080"),
                        "Origin", List.of("https://example.test"))));

    assertEquals(403, error.getStatusCode());
  }

  @Test
  void remoteHostsAreRejected() {
    ServerTransportSecurityValidator validator =
        GhidraMcpServer.createLocalTransportSecurityValidator();

    ServerTransportSecurityException error =
        assertThrows(
            ServerTransportSecurityException.class,
            () -> validator.validateHeaders(Map.of("Host", List.of("192.0.2.10:8080"))));

    assertEquals(421, error.getStatusCode());
  }
}
