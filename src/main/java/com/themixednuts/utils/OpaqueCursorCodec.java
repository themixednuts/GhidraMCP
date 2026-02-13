package com.themixednuts.utils;

import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/** Utility for strict opaque v1 cursor encoding/decoding. */
public final class OpaqueCursorCodec {

  private static final String VERSION_PREFIX = "v1";

  private OpaqueCursorCodec() {}

  public static String encodeV1(String... parts) {
    if (parts == null || parts.length == 0) {
      throw new IllegalArgumentException("cursor parts are required");
    }

    List<String> encodedParts = new ArrayList<>();
    for (String part : parts) {
      if (part == null || part.isBlank()) {
        throw new IllegalArgumentException("cursor parts cannot be null or blank");
      }
      encodedParts.add(
          Base64.getUrlEncoder().withoutPadding().encodeToString(part.getBytes(StandardCharsets.UTF_8)));
    }

    return VERSION_PREFIX + ":" + String.join(":", encodedParts);
  }

  public static List<String> decodeV1(
      String cursorValue, int expectedPartCount, String argumentName, String formatDescription) {
    if (cursorValue == null || cursorValue.isBlank()) {
      throw new GhidraMcpException(
          GhidraMcpError.invalid(argumentName, cursorValue, "cursor value cannot be blank"));
    }

    String[] parts = cursorValue.split(":", -1);
    if (parts.length != expectedPartCount + 1 || !VERSION_PREFIX.equals(parts[0])) {
      throw new GhidraMcpException(
          GhidraMcpError.invalid(argumentName, cursorValue, "must be in format '" + formatDescription + "'"));
    }

    List<String> decodedParts = new ArrayList<>();
    for (int i = 1; i < parts.length; i++) {
      String rawPart = parts[i];
      if (rawPart.isBlank()) {
        throw new GhidraMcpException(
            GhidraMcpError.invalid(argumentName, cursorValue, "cursor contains blank encoded segments"));
      }

      try {
        String decoded = new String(Base64.getUrlDecoder().decode(rawPart), StandardCharsets.UTF_8);
        if (decoded.isBlank()) {
          throw new GhidraMcpException(
              GhidraMcpError.invalid(argumentName, cursorValue, "cursor contains empty decoded segments"));
        }
        decodedParts.add(decoded);
      } catch (IllegalArgumentException e) {
        throw new GhidraMcpException(
            GhidraMcpError.invalid(argumentName, cursorValue, "contains invalid base64url encoding"));
      }
    }

    return decodedParts;
  }
}
