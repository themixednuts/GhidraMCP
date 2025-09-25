package com.themixednuts.exceptions;

import com.themixednuts.models.GhidraMcpError;

/**
 * Custom exception that carries structured error information for Ghidra MCP
 * tools.
 * This exception wraps a {@link GhidraMcpError} object providing detailed
 * context,
 * suggestions, and debug information that can be serialized and sent to MCP
 * clients.
 */
public class GhidraMcpException extends Exception {

    private final GhidraMcpError err;

    /**
     * Creates a new GhidraMcpException with structured error information.
     *
     * @param err The detailed error information
     */
    public GhidraMcpException(GhidraMcpError err) {
        super(err.getMessage());
        this.err = err;
    }

    /**
     * Creates a new GhidraMcpException with structured error information and a
     * cause.
     *
     * @param structuredError The detailed error information
     * @param cause           The underlying exception that caused this error
     */
    public GhidraMcpException(GhidraMcpError structuredError, Throwable cause) {
        super(structuredError.getMessage(), cause);
        this.err = structuredError;
    }

    /**
     * Gets the structured error information.
     *
     * @return The detailed error information including context, suggestions, and
     *         debug data
     */
    public GhidraMcpError getErr() {
        return err;
    }

    /**
     * Gets the error type from the structured error.
     *
     * @return The error type
     */
    public GhidraMcpError.ErrorType getErrorType() {
        return err.getErrorType();
    }

    /**
     * Gets the error code from the structured error.
     *
     * @return The error code string
     */
    public String getErrorCode() {
        return err.getErrorCode();
    }

    /**
     * Checks if this is a validation error.
     *
     * @return true if this is a validation error
     */
    public boolean isValidationError() {
        return (err.getErrorType() == GhidraMcpError.ErrorType.VALIDATION);
    }

    /**
     * Checks if this is a resource not found error.
     *
     * @return true if this is a resource not found error
     */
    public boolean isResourceNotFoundError() {
        return (
            err.getErrorType() == GhidraMcpError.ErrorType.RESOURCE_NOT_FOUND
        );
    }

    /**
     * Checks if this is a data type parsing error.
     *
     * @return true if this is a data type parsing error
     */
    public boolean isDataTypeParsingError() {
        return (
            err.getErrorType() == GhidraMcpError.ErrorType.DATA_TYPE_PARSING
        );
    }

    /**
     * Checks if this is an execution error.
     *
     * @return true if this is an execution error
     */
    public boolean isExecutionError() {
        return (err.getErrorType() == GhidraMcpError.ErrorType.EXECUTION);
    }

    /**
     * Creates a GhidraMcpException from a regular exception with minimal error
     * information.
     * This is useful for wrapping unexpected exceptions that don't have structured
     * error details.
     *
     * @param cause         The original exception
     * @param toolOperation The operation that was being performed
     * @param toolClass     The class of the tool that threw the exception
     * @return A new GhidraMcpException with basic error information
     */
    public static GhidraMcpException fromException(
        Throwable cause,
        String toolOperation,
        String toolClass
    ) {
        GhidraMcpError error = GhidraMcpError.internal()
            .errorCode(GhidraMcpError.ErrorCode.UNEXPECTED_ERROR)
            .message("Unexpected error occurred: " + cause.getMessage())
            .context(
                new GhidraMcpError.ErrorContext(
                    toolOperation,
                    "internal operation",
                    null,
                    null,
                    java.util.Map.of(
                        "exceptionType",
                        cause.getClass().getSimpleName()
                    )
                )
            )
            .debugInfo(
                new GhidraMcpError.ErrorDebugInfo(
                    getStackTraceString(cause),
                    null, // Will be set by GhidraMcpErrorUtils if needed
                    toolClass,
                    java.time.Instant.now().toString(),
                    java.util.Map.of("originalMessage", cause.getMessage())
                )
            )
            .build();

        return new GhidraMcpException(error, cause);
    }

    /**
     * Helper method to convert stack trace to string.
     */
    private static String getStackTraceString(Throwable throwable) {
        java.io.StringWriter sw = new java.io.StringWriter();
        java.io.PrintWriter pw = new java.io.PrintWriter(sw);
        throwable.printStackTrace(pw);
        return sw.toString();
    }

    @Override
    public String toString() {
        return (
            "GhidraMcpException{" +
            "errorType=" +
            err.getErrorType() +
            ", errorCode='" +
            err.getErrorCode() +
            '\'' +
            ", message='" +
            getMessage() +
            '\'' +
            '}'
        );
    }
}
