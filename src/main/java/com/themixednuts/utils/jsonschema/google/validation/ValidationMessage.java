package com.themixednuts.utils.jsonschema.google.validation;

import java.util.Objects;

/**
 * Represents a validation error or warning for Google AI API schema validation.
 * Similar to NetworkNT's ValidationMessage but tailored for Google schema format.
 */
public class ValidationMessage {
    
    private final String path;
    private final String message;
    private final String keyword;
    private final ValidationSeverity severity;

    public enum ValidationSeverity {
        ERROR,
        WARNING
    }

    private ValidationMessage(String path, String message, String keyword, ValidationSeverity severity) {
        this.path = Objects.requireNonNull(path, "Path cannot be null");
        this.message = Objects.requireNonNull(message, "Message cannot be null");
        this.keyword = keyword;
        this.severity = Objects.requireNonNull(severity, "Severity cannot be null");
    }

    /**
     * Creates an error validation message.
     */
    public static ValidationMessage error(String path, String keyword, String message) {
        return new ValidationMessage(path, message, keyword, ValidationSeverity.ERROR);
    }

    /**
     * Creates a warning validation message.
     */
    public static ValidationMessage warning(String path, String keyword, String message) {
        return new ValidationMessage(path, message, keyword, ValidationSeverity.WARNING);
    }

    /**
     * Gets the JSON path where the validation error occurred.
     */
    public String getPath() {
        return path;
    }

    /**
     * Gets the validation error message.
     */
    public String getMessage() {
        return message;
    }

    /**
     * Gets the schema keyword that failed validation (e.g., "minLength", "minimum").
     */
    public String getKeyword() {
        return keyword;
    }

    /**
     * Gets the severity of this validation message.
     */
    public ValidationSeverity getSeverity() {
        return severity;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ValidationMessage that = (ValidationMessage) o;
        return Objects.equals(path, that.path) &&
                Objects.equals(message, that.message) &&
                Objects.equals(keyword, that.keyword) &&
                severity == that.severity;
    }

    @Override
    public int hashCode() {
        return Objects.hash(path, message, keyword, severity);
    }

    @Override
    public String toString() {
        return String.format("%s: %s [%s] at %s",
                severity,
                message,
                keyword != null ? keyword : "unknown",
                path);
    }
}

