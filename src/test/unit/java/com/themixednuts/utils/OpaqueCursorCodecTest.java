package com.themixednuts.utils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.themixednuts.exceptions.GhidraMcpException;
import java.util.List;
import org.junit.jupiter.api.Test;

class OpaqueCursorCodecTest {

  @Test
  void encodeDecodeRoundTrip() {
    String cursor = OpaqueCursorCodec.encodeV1("main::symbol", "0x401000");
    List<String> parts =
        OpaqueCursorCodec.decodeV1(cursor, 2, "cursor", "v1:<base64url_a>:<base64url_b>");

    assertEquals(2, parts.size());
    assertEquals("main::symbol", parts.get(0));
    assertEquals("0x401000", parts.get(1));
  }

  @Test
  void rejectsWrongVersionOrShape() {
    GhidraMcpException ex =
        assertThrows(
            GhidraMcpException.class,
            () -> OpaqueCursorCodec.decodeV1("v2:abc:def", 2, "cursor", "v1:<a>:<b>"));

    assertTrue(ex.getMessage().contains("must be in format"));
  }

  @Test
  void rejectsInvalidBase64Segment() {
    GhidraMcpException ex =
        assertThrows(
            GhidraMcpException.class,
            () ->
                OpaqueCursorCodec.decodeV1(
                    "v1:***:ZGVm", 2, "cursor", "v1:<a>:<b>"));

    assertTrue(ex.getMessage().contains("invalid base64url"));
  }

  @Test
  void encodeRejectsBlankSegments() {
    IllegalArgumentException ex =
        assertThrows(IllegalArgumentException.class, () -> OpaqueCursorCodec.encodeV1("", "x"));

    assertTrue(ex.getMessage().contains("cannot be null or blank"));
  }
}
