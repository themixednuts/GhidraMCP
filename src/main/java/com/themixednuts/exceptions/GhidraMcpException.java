package com.themixednuts.exceptions;

import com.themixednuts.models.GhidraMcpError;

/** Exception carrying a structured error for MCP responses. Unchecked to allow use in lambdas. */
public class GhidraMcpException extends RuntimeException {

  private final GhidraMcpError err;

  public GhidraMcpException(GhidraMcpError err) {
    super(err != null ? err.getMessage() : "Unknown error");
    this.err = err;
  }

  public GhidraMcpException(GhidraMcpError err, Throwable cause) {
    super(err != null ? err.getMessage() : "Unknown error", cause);
    this.err = err;
  }

  public GhidraMcpError getErr() {
    return err;
  }

  public GhidraMcpError.ErrorType getErrorType() {
    return err != null ? err.getErrorType() : GhidraMcpError.ErrorType.INTERNAL;
  }

  public String getErrorCode() {
    return err != null ? err.getErrorCode() : "INTERNAL";
  }

  public boolean isValidationError() {
    return getErrorType() == GhidraMcpError.ErrorType.VALIDATION;
  }

  public boolean isResourceNotFoundError() {
    return getErrorType() == GhidraMcpError.ErrorType.RESOURCE_NOT_FOUND;
  }

  public boolean isDataTypeParsingError() {
    return getErrorType() == GhidraMcpError.ErrorType.DATA_TYPE_PARSING;
  }

  public boolean isExecutionError() {
    return getErrorType() == GhidraMcpError.ErrorType.EXECUTION;
  }

  public boolean isInternalError() {
    return getErrorType() == GhidraMcpError.ErrorType.INTERNAL;
  }

  /** Create from any throwable */
  public static GhidraMcpException wrap(Throwable t) {
    if (t instanceof GhidraMcpException gme) {
      return gme;
    }
    return new GhidraMcpException(GhidraMcpError.internal(t), t);
  }

  /** Create from message */
  public static GhidraMcpException of(String msg) {
    return new GhidraMcpException(GhidraMcpError.of(msg));
  }

  public static GhidraMcpException of(String msg, String hint) {
    return new GhidraMcpException(GhidraMcpError.of(msg, hint));
  }

  /** Create from throwable with operation context */
  public static GhidraMcpException fromException(Throwable t, String operation, String toolClass) {
    if (t == null) {
      return new GhidraMcpException(
          GhidraMcpError.internal().message("Unknown error during " + operation).build());
    }
    String msg = t.getMessage();
    if (msg == null) msg = t.getClass().getSimpleName();
    return new GhidraMcpException(
        GhidraMcpError.internal().message(operation + ": " + msg).build(), t);
  }

  @Override
  public String toString() {
    String type = err != null ? err.getErrorType().name() : "UNKNOWN";
    String msg = err != null ? err.getMessage() : getMessage();
    String hint = err != null ? err.getHint() : null;
    return hint != null
        ? "GhidraMcpException[" + type + "]: " + msg + " [" + hint + "]"
        : "GhidraMcpException[" + type + "]: " + msg;
  }
}
