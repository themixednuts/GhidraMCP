package com.themixednuts.models;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;
import java.util.Map;

/**
 * Minimal error model - JSON output is just msg and optional hint.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class GhidraMcpError {

    private final String msg;
    private final String hint;
    private final ErrorType errorType;

    private GhidraMcpError(String msg, String hint, ErrorType errorType) {
        this.msg = msg;
        this.hint = hint;
        this.errorType = errorType != null ? errorType : ErrorType.INTERNAL;
    }

    // =================== JSON Output ===================

    @JsonProperty("msg")
    public String getMsg() {
        return msg;
    }

    @JsonProperty("hint")
    public String getHint() {
        return hint;
    }

    // =================== Internal Accessors ===================

    @JsonIgnore
    public ErrorType getErrorType() {
        return errorType;
    }

    @JsonIgnore
    public String getMessage() {
        return msg;
    }

    @JsonIgnore
    public String getCode() {
        return errorType.name();
    }

    @JsonIgnore
    public String getErrorCode() {
        return errorType.name();
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
        return new GhidraMcpError(msg, null, ErrorType.INTERNAL);
    }

    public static GhidraMcpError of(String msg, String hint) {
        return new GhidraMcpError(msg, hint, ErrorType.INTERNAL);
    }

    public static GhidraMcpError error(String msg) {
        return new GhidraMcpError(msg, null, ErrorType.INTERNAL);
    }

    public static GhidraMcpError error(String msg, String hint) {
        return new GhidraMcpError(msg, hint, ErrorType.INTERNAL);
    }

    public static GhidraMcpError notFound(String what, String id) {
        return new GhidraMcpError(what + " '" + id + "' not found", null, ErrorType.RESOURCE_NOT_FOUND);
    }

    public static GhidraMcpError notFound(String what, String id, String hint) {
        return new GhidraMcpError(what + " '" + id + "' not found", hint, ErrorType.RESOURCE_NOT_FOUND);
    }

    public static GhidraMcpError missing(String arg) {
        return new GhidraMcpError("Missing: " + arg, null, ErrorType.VALIDATION);
    }

    public static GhidraMcpError missingArg(String arg) {
        return new GhidraMcpError("Missing: " + arg, null, ErrorType.VALIDATION);
    }

    public static GhidraMcpError invalid(String arg, String reason) {
        return new GhidraMcpError("Invalid " + arg + ": " + reason, null, ErrorType.VALIDATION);
    }

    public static GhidraMcpError invalidArg(String arg, String reason) {
        return new GhidraMcpError("Invalid " + arg + ": " + reason, null, ErrorType.VALIDATION);
    }

    public static GhidraMcpError invalid(String arg, Object val, String reason) {
        return new GhidraMcpError("Invalid " + arg + "=" + truncate(val, 50) + ": " + reason, null, ErrorType.VALIDATION);
    }

    public static GhidraMcpError invalidArg(String arg, Object val, String reason) {
        return invalid(arg, val, reason);
    }

    public static GhidraMcpError parse(String what, String input) {
        return new GhidraMcpError("Cannot parse " + what + ": " + truncate(input, 30), null, ErrorType.DATA_TYPE_PARSING);
    }

    public static GhidraMcpError parseError(String what, String input) {
        return parse(what, input);
    }

    public static GhidraMcpError failed(String op, String reason) {
        return new GhidraMcpError(op + " failed: " + reason, null, ErrorType.EXECUTION);
    }

    public static GhidraMcpError noResults(String search) {
        return new GhidraMcpError("No results: " + search, "Broaden search criteria", ErrorType.SEARCH_NO_RESULTS);
    }

    public static GhidraMcpError conflict(String msg) {
        return new GhidraMcpError(msg, null, ErrorType.VALIDATION);
    }

    public static GhidraMcpError internal(Throwable t) {
        String m = t != null ? t.getMessage() : "unknown";
        return new GhidraMcpError("Internal error: " + m, null, ErrorType.INTERNAL);
    }

    public static GhidraMcpError internal(String msg) {
        return new GhidraMcpError("Internal error: " + msg, null, ErrorType.INTERNAL);
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
        private String msg;
        private String hint;

        Builder(ErrorType errorType) {
            this.errorType = errorType;
        }

        public Builder msg(String msg) {
            this.msg = msg;
            return this;
        }

        public Builder message(String msg) {
            this.msg = msg;
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

        /** Ignored - errorCode not used in output */
        public Builder code(ErrorCode code) {
            return this;
        }

        /** Ignored - errorCode not used in output */
        public Builder errorCode(ErrorCode code) {
            return this;
        }

        /** Extracts action from first suggestion as hint */
        public Builder suggestions(List<ErrorSuggestion> suggestions) {
            if (suggestions != null && !suggestions.isEmpty()) {
                ErrorSuggestion first = suggestions.get(0);
                if (first.action() != null) {
                    this.hint = first.action();
                }
            }
            return this;
        }

        /** Ignored - context not used in output */
        public Builder context(ErrorContext context) {
            return this;
        }

        /** Ignored - relatedResources not used in output */
        public Builder relatedResources(List<String> resources) {
            return this;
        }

        public GhidraMcpError build() {
            return new GhidraMcpError(msg, hint, errorType);
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
        Object metadata
    ) {}

    public record ErrorSuggestion(
        SuggestionType type,
        String message,
        String action,
        List<String> relatedArgs,
        List<String> relatedTools
    ) {
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
}
