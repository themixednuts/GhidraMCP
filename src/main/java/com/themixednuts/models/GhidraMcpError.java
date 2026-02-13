package com.themixednuts.models;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;
import java.util.Locale;

/** Structured error model for MCP responses. */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class GhidraMcpError {

  private final String message;
  private final String hint;
  private final ErrorType errorType;
  private final ErrorCode payloadCode;
  private final ErrorContext context;
  private final List<String> relatedResources;
  private final List<ErrorSuggestion> suggestions;

  private GhidraMcpError(
      String message,
      String hint,
      ErrorType errorType,
      ErrorCode payloadCode,
      ErrorContext context,
      List<String> relatedResources,
      List<ErrorSuggestion> suggestions) {
    this.message = message;
    this.hint = hint;
    this.errorType = errorType != null ? errorType : ErrorType.INTERNAL;
    this.payloadCode = payloadCode != null ? payloadCode : defaultPayloadCode(this.errorType);
    this.context = context;
    this.relatedResources = relatedResources;
    this.suggestions = suggestions;
  }

  // =================== JSON Output ===================

  @JsonProperty("message")
  public String getMessage() {
    return message;
  }

  @JsonProperty("hint")
  public String getHint() {
    return hint;
  }

  @JsonProperty("error_type")
  public String getPayloadErrorType() {
    return errorType.name().toLowerCase(Locale.ROOT);
  }

  @JsonProperty("error_code")
  public String getPayloadErrorCode() {
    return payloadCode.name().toLowerCase(Locale.ROOT);
  }

  @JsonProperty("context")
  public ErrorContext getContext() {
    return context;
  }

  @JsonProperty("related_resources")
  public List<String> getRelatedResources() {
    return relatedResources;
  }

  @JsonProperty("suggestions")
  public List<ErrorSuggestion> getSuggestions() {
    return suggestions;
  }

  // =================== Internal Accessors ===================

  @JsonIgnore
  public ErrorType getErrorType() {
    return errorType;
  }

  @JsonIgnore
  public String getCode() {
    return payloadCode.name();
  }

  @JsonIgnore
  public String getErrorCode() {
    return payloadCode.name();
  }

  @JsonIgnore
  public String getFix() {
    return hint;
  }

  @JsonIgnore
  public Object getDetails() {
    return null;
  }

  @JsonIgnore
  public Object getSee() {
    return null;
  }

  // =================== Factory Methods ===================

  public static GhidraMcpError of(String msg) {
    return new GhidraMcpError(
        msg, null, ErrorType.INTERNAL, ErrorCode.UNEXPECTED_ERROR, null, null, null);
  }

  public static GhidraMcpError of(String msg, String hint) {
    return new GhidraMcpError(
        msg, hint, ErrorType.INTERNAL, ErrorCode.UNEXPECTED_ERROR, null, null, null);
  }

  public static GhidraMcpError error(String msg) {
    return new GhidraMcpError(
        msg, null, ErrorType.INTERNAL, ErrorCode.UNEXPECTED_ERROR, null, null, null);
  }

  public static GhidraMcpError error(String msg, String hint) {
    return new GhidraMcpError(
        msg, hint, ErrorType.INTERNAL, ErrorCode.UNEXPECTED_ERROR, null, null, null);
  }

  public static GhidraMcpError notFound(String what, String id) {
    return new GhidraMcpError(
        what + " '" + id + "' not found",
        null,
        ErrorType.RESOURCE_NOT_FOUND,
        ErrorCode.NOT_FOUND,
        null,
        null,
        null);
  }

  public static GhidraMcpError notFound(String what, String id, String hint) {
    return new GhidraMcpError(
        what + " '" + id + "' not found",
        hint,
        ErrorType.RESOURCE_NOT_FOUND,
        ErrorCode.NOT_FOUND,
        null,
        null,
        null);
  }

  public static GhidraMcpError missing(String arg) {
    return new GhidraMcpError(
        "Missing: " + arg,
        null,
        ErrorType.VALIDATION,
        ErrorCode.MISSING_REQUIRED_ARGUMENT,
        null,
        null,
        null);
  }

  public static GhidraMcpError invalid(String arg, String reason) {
    return new GhidraMcpError(
        "Invalid " + arg + ": " + reason,
        null,
        ErrorType.VALIDATION,
        ErrorCode.INVALID_ARGUMENT_VALUE,
        null,
        null,
        null);
  }

  public static GhidraMcpError invalid(String arg, Object val, String reason) {
    return new GhidraMcpError(
        "Invalid " + arg + "=" + truncate(val, 50) + ": " + reason,
        null,
        ErrorType.VALIDATION,
        ErrorCode.INVALID_ARGUMENT_VALUE,
        null,
        null,
        null);
  }

  public static GhidraMcpError parse(String what, String input) {
    return new GhidraMcpError(
        "Cannot parse " + what + ": " + truncate(input, 30),
        null,
        ErrorType.DATA_TYPE_PARSING,
        ErrorCode.PARSE_ERROR,
        null,
        null,
        null);
  }

  public static GhidraMcpError failed(String op, String reason) {
    return new GhidraMcpError(
        op + " failed: " + reason, null, ErrorType.EXECUTION, ErrorCode.FAILED, null, null, null);
  }

  public static GhidraMcpError noResults(String search) {
    return new GhidraMcpError(
        "No results: " + search,
        "Broaden search criteria",
        ErrorType.SEARCH_NO_RESULTS,
        ErrorCode.NO_SEARCH_RESULTS,
        null,
        null,
        null);
  }

  public static GhidraMcpError conflict(String msg) {
    return new GhidraMcpError(
        msg, null, ErrorType.VALIDATION, ErrorCode.CONFLICTING_ARGUMENTS, null, null, null);
  }

  public static GhidraMcpError internal(Throwable t) {
    String m = t != null ? t.getMessage() : "unknown";
    return new GhidraMcpError(
        "Internal error: " + m,
        null,
        ErrorType.INTERNAL,
        ErrorCode.UNEXPECTED_ERROR,
        null,
        null,
        null);
  }

  public static GhidraMcpError internal(String msg) {
    return new GhidraMcpError(
        "Internal error: " + msg,
        null,
        ErrorType.INTERNAL,
        ErrorCode.UNEXPECTED_ERROR,
        null,
        null,
        null);
  }

  // =================== Builder Factory Methods ===================

  public static Builder validation() {
    return new Builder(ErrorType.VALIDATION);
  }

  public static Builder resourceNotFound() {
    return new Builder(ErrorType.RESOURCE_NOT_FOUND);
  }

  public static Builder dataTypeParsing() {
    return new Builder(ErrorType.DATA_TYPE_PARSING);
  }

  public static Builder execution() {
    return new Builder(ErrorType.EXECUTION);
  }

  public static Builder permissionState() {
    return new Builder(ErrorType.PERMISSION_STATE);
  }

  public static Builder internal() {
    return new Builder(ErrorType.INTERNAL);
  }

  public static Builder searchNoResults() {
    return new Builder(ErrorType.SEARCH_NO_RESULTS);
  }

  // =================== Builder ===================

  public static class Builder {
    private final ErrorType errorType;
    private String message;
    private String hint;
    private ErrorCode payloadCode;
    private ErrorContext context;
    private List<String> relatedResources;
    private List<ErrorSuggestion> suggestions;

    Builder(ErrorType errorType) {
      this.errorType = errorType;
    }

    public Builder message(String message) {
      this.message = message;
      return this;
    }

    public Builder hint(String hint) {
      this.hint = hint;
      return this;
    }

    public Builder fix(String fix) {
      this.hint = fix;
      return this;
    }

    public Builder see(String... tools) {
      this.hint = "See: " + String.join(", ", tools);
      return this;
    }

    /** Sets the structured payload error code. */
    public Builder code(ErrorCode code) {
      this.payloadCode = code;
      return this;
    }

    public Builder errorCode(ErrorCode code) {
      this.payloadCode = code;
      return this;
    }

    /** Extracts action from first suggestion as hint */
    public Builder suggestions(List<ErrorSuggestion> suggestions) {
      this.suggestions = suggestions;
      if (suggestions != null && !suggestions.isEmpty()) {
        ErrorSuggestion first = suggestions.get(0);
        if (first.action() != null) {
          this.hint = first.action();
        }
      }
      return this;
    }

    public Builder context(ErrorContext context) {
      this.context = context;
      return this;
    }

    public Builder relatedResources(List<String> resources) {
      this.relatedResources = resources;
      return this;
    }

    public GhidraMcpError build() {
      return new GhidraMcpError(
          message, hint, errorType, payloadCode, context, relatedResources, suggestions);
    }
  }

  // =================== Enums ===================

  public enum ErrorType {
    VALIDATION,
    RESOURCE_NOT_FOUND,
    DATA_TYPE_PARSING,
    EXECUTION,
    PERMISSION_STATE,
    INTERNAL,
    SEARCH_NO_RESULTS
  }

  public enum ErrorCode {
    MISSING_ARG,
    INVALID_ARG,
    NOT_FOUND,
    PARSE_ERROR,
    FAILED,
    MISSING_REQUIRED_ARGUMENT,
    INVALID_ARGUMENT_VALUE,
    CONFLICTING_ARGUMENTS,
    FUNCTION_NOT_FOUND,
    SYMBOL_NOT_FOUND,
    DATA_TYPE_NOT_FOUND,
    ADDRESS_NOT_FOUND,
    BOOKMARK_NOT_FOUND,
    TRANSACTION_FAILED,
    OPERATION_FAILED,
    SCRIPT_EXECUTION_FAILED,
    INVALID_POINTER_SYNTAX,
    UNEXPECTED_ERROR,
    PROGRAM_NOT_OPEN,
    INVALID_PROGRAM_STATE,
    ADDRESS_PARSE_FAILED,
    NO_SEARCH_RESULTS;

    public String code() {
      return name();
    }

    public String getCode() {
      return name();
    }
  }

  // =================== Supporting Records ===================

  public record ErrorContext(
      String toolName,
      String operation,
      Object inputArguments,
      Object providedValues,
      Object metadata) {}

  public record ErrorSuggestion(
      SuggestionType type,
      String message,
      String action,
      List<String> relatedArgs,
      List<String> relatedTools) {
    public enum SuggestionType {
      FIX_REQUEST,
      ALTERNATIVE_TOOL,
      ALTERNATIVE_ARG,
      RESOURCE_HINT,
      CHECK_RESOURCES
    }
  }

  // =================== Utility ===================

  private static String truncate(Object val, int max) {
    if (val == null) return "null";
    String s = val.toString();
    return s.length() > max ? s.substring(0, max - 3) + "..." : s;
  }

  private static ErrorCode defaultPayloadCode(ErrorType errorType) {
    return switch (errorType) {
      case VALIDATION -> ErrorCode.INVALID_ARGUMENT_VALUE;
      case RESOURCE_NOT_FOUND -> ErrorCode.NOT_FOUND;
      case DATA_TYPE_PARSING -> ErrorCode.PARSE_ERROR;
      case EXECUTION -> ErrorCode.OPERATION_FAILED;
      case PERMISSION_STATE -> ErrorCode.INVALID_PROGRAM_STATE;
      case SEARCH_NO_RESULTS -> ErrorCode.NO_SEARCH_RESULTS;
      case INTERNAL -> ErrorCode.UNEXPECTED_ERROR;
    };
  }
}
