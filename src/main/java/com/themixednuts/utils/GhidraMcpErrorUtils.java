package com.themixednuts.utils;

import com.themixednuts.models.GhidraMcpError;

/**
 * Utility class for creating error messages. Most methods just delegate to GhidraMcpError factory
 * methods.
 */
public class GhidraMcpErrorUtils {

  public static GhidraMcpError missingRequiredArgument(String toolName, String arg) {
    return GhidraMcpError.missing(arg);
  }

  public static GhidraMcpError addressParseError(String address, String toolName, Throwable cause) {
    return GhidraMcpError.parse("address", address);
  }

  public static GhidraMcpError unexpectedError(String toolName, String op, Throwable cause) {
    return GhidraMcpError.internal(cause);
  }

  public static GhidraMcpError fileNotFound(
      String fileName, java.util.List<String> available, String toolName) {
    String hint =
        available != null && !available.isEmpty()
            ? "Available: " + String.join(", ", available.subList(0, Math.min(3, available.size())))
            : null;
    return GhidraMcpError.notFound("File", fileName, hint);
  }
}
