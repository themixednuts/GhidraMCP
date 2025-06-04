package com.themixednuts.models;

import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

/**
 * Comprehensive error information for Ghidra MCP tools.
 * Provides structured error details, context, suggestions, and debugging
 * information.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({ "errorType", "errorCode", "message", "context", "suggestions", "relatedResources", "debugInfo" })
public class GhidraMcpError {

	private final ErrorType errorType;
	private final String errorCode;
	private final String message;
	private final ErrorContext context;
	private final List<ErrorSuggestion> suggestions;
	private final List<String> relatedResources;
	private final ErrorDebugInfo debugInfo;

	/**
	 * Categories of errors that can occur in Ghidra MCP tools.
	 */
	public enum ErrorType {
		/** Invalid arguments, wrong types, missing required fields */
		VALIDATION,

		/** Resources not found (functions, data types, files, symbols, etc.) */
		RESOURCE_NOT_FOUND,

		/** Data type parsing failures (invalid pointer/array notation, etc.) */
		DATA_TYPE_PARSING,

		/** Ghidra API failures, transaction issues, program state errors */
		EXECUTION,

		/** Permission denied, invalid program state, access issues */
		PERMISSION_STATE,

		/** Script execution failures, tool invocation errors */
		TOOL_EXECUTION,

		/** Search operations that returned no results */
		SEARCH_NO_RESULTS,

		/** Multiple operation failures in grouped tools */
		GROUPED_OPERATIONS,

		/** Unexpected errors, system failures */
		INTERNAL
	}

	/**
	 * Specific error subcategories for better programmatic handling.
	 */
	public enum ErrorCode {
		// Validation errors
		MISSING_REQUIRED_ARGUMENT("VAL_001"),
		INVALID_ARGUMENT_TYPE("VAL_002"),
		INVALID_ARGUMENT_VALUE("VAL_003"),
		ARGUMENT_OUT_OF_RANGE("VAL_004"),
		CONFLICTING_ARGUMENTS("VAL_005"),

		// Resource not found errors
		FUNCTION_NOT_FOUND("RNF_001"),
		DATA_TYPE_NOT_FOUND("RNF_002"),
		FILE_NOT_FOUND("RNF_003"),
		SYMBOL_NOT_FOUND("RNF_004"),
		ADDRESS_NOT_FOUND("RNF_005"),
		CATEGORY_NOT_FOUND("RNF_006"),
		NAMESPACE_NOT_FOUND("RNF_007"),
		BOOKMARK_NOT_FOUND("RNF_008"),
		SCRIPT_NOT_FOUND("RNF_009"),

		// Data type parsing errors
		INVALID_POINTER_SYNTAX("DTP_001"),
		INVALID_ARRAY_SYNTAX("DTP_002"),
		INVALID_TYPE_PATH("DTP_003"),
		CIRCULAR_TYPE_REFERENCE("DTP_004"),
		TYPE_SIZE_MISMATCH("DTP_005"),

		// Execution errors
		TRANSACTION_FAILED("EXE_001"),
		DECOMPILATION_FAILED("EXE_002"),
		MEMORY_ACCESS_FAILED("EXE_003"),
		ADDRESS_PARSE_FAILED("EXE_004"),
		INSTRUCTION_PARSE_FAILED("EXE_005"),

		// Permission/State errors
		PROGRAM_NOT_OPEN("PER_001"),
		READ_ONLY_PROGRAM("PER_002"),
		INVALID_PROGRAM_STATE("PER_003"),
		ACCESS_DENIED("PER_004"),

		// Tool execution errors
		SCRIPT_EXECUTION_FAILED("TOL_001"),
		ANALYSIS_FAILED("TOL_002"),
		DISASSEMBLY_FAILED("TOL_003"),

		// Search errors
		NO_SEARCH_RESULTS("SRC_001"),
		SEARCH_LIMIT_EXCEEDED("SRC_002"),
		INVALID_SEARCH_CRITERIA("SRC_003"),

		// Grouped operation errors
		PARTIAL_OPERATION_FAILURE("GRP_001"),
		ALL_OPERATIONS_FAILED("GRP_002"),
		INVALID_OPERATION_FORMAT("GRP_003"),

		// Internal errors
		SERIALIZATION_FAILED("INT_001"),
		UNEXPECTED_ERROR("INT_002"),
		CONFIGURATION_ERROR("INT_003");

		private final String code;

		ErrorCode(String code) {
			this.code = code;
		}

		public String getCode() {
			return code;
		}
	}

	/**
	 * Context information about what was being attempted when the error occurred.
	 */
	@JsonInclude(JsonInclude.Include.NON_NULL)
	@JsonPropertyOrder({ "operation", "targetResource", "arguments", "attemptedValues", "validationDetails" })
	public static class ErrorContext {
		private final String operation;
		private final String targetResource;
		private final Map<String, Object> arguments;
		private final Map<String, Object> attemptedValues;
		private final Map<String, Object> validationDetails;

		public ErrorContext(String operation, String targetResource, Map<String, Object> arguments,
				Map<String, Object> attemptedValues, Map<String, Object> validationDetails) {
			this.operation = operation;
			this.targetResource = targetResource;
			this.arguments = arguments;
			this.attemptedValues = attemptedValues;
			this.validationDetails = validationDetails;
		}

		@JsonProperty("operation")
		public String getOperation() {
			return operation;
		}

		@JsonProperty("targetResource")
		public String getTargetResource() {
			return targetResource;
		}

		@JsonProperty("arguments")
		public Map<String, Object> getArguments() {
			return arguments;
		}

		@JsonProperty("attemptedValues")
		public Map<String, Object> getAttemptedValues() {
			return attemptedValues;
		}

		@JsonProperty("validationDetails")
		public Map<String, Object> getValidationDetails() {
			return validationDetails;
		}
	}

	/**
	 * Suggestion for how to fix the error or what to try next.
	 */
	@JsonInclude(JsonInclude.Include.NON_NULL)
	@JsonPropertyOrder({ "type", "message", "action", "examples", "relatedTools" })
	public static class ErrorSuggestion {
		private final SuggestionType type;
		private final String message;
		private final String action;
		private final List<String> examples;
		private final List<String> relatedTools;

		public enum SuggestionType {
			/** Fix the current request */
			FIX_REQUEST,
			/** Try a different approach */
			ALTERNATIVE_APPROACH,
			/** Use a different tool */
			USE_DIFFERENT_TOOL,
			/** Check available resources */
			CHECK_RESOURCES,
			/** Similar/alternative values */
			SIMILAR_VALUES
		}

		public ErrorSuggestion(SuggestionType type, String message, String action,
				List<String> examples, List<String> relatedTools) {
			this.type = type;
			this.message = message;
			this.action = action;
			this.examples = examples;
			this.relatedTools = relatedTools;
		}

		@JsonProperty("type")
		public SuggestionType getType() {
			return type;
		}

		@JsonProperty("message")
		public String getMessage() {
			return message;
		}

		@JsonProperty("action")
		public String getAction() {
			return action;
		}

		@JsonProperty("examples")
		public List<String> getExamples() {
			return examples;
		}

		@JsonProperty("relatedTools")
		public List<String> getRelatedTools() {
			return relatedTools;
		}
	}

	/**
	 * Debug information for troubleshooting errors.
	 */
	@JsonInclude(JsonInclude.Include.NON_NULL)
	@JsonPropertyOrder({ "stackTrace", "ghidraVersion", "toolClass", "timestamp", "additionalInfo" })
	public static class ErrorDebugInfo {
		private final String stackTrace;
		private final String ghidraVersion;
		private final String toolClass;
		private final String timestamp;
		private final Map<String, Object> additionalInfo;

		public ErrorDebugInfo(String stackTrace, String ghidraVersion, String toolClass,
				String timestamp, Map<String, Object> additionalInfo) {
			this.stackTrace = stackTrace;
			this.ghidraVersion = ghidraVersion;
			this.toolClass = toolClass;
			this.timestamp = timestamp;
			this.additionalInfo = additionalInfo;
		}

		@JsonProperty("stackTrace")
		public String getStackTrace() {
			return stackTrace;
		}

		@JsonProperty("ghidraVersion")
		public String getGhidraVersion() {
			return ghidraVersion;
		}

		@JsonProperty("toolClass")
		public String getToolClass() {
			return toolClass;
		}

		@JsonProperty("timestamp")
		public String getTimestamp() {
			return timestamp;
		}

		@JsonProperty("additionalInfo")
		public Map<String, Object> getAdditionalInfo() {
			return additionalInfo;
		}
	}

	// Main constructor
	public GhidraMcpError(ErrorType errorType, String errorCode, String message, ErrorContext context,
			List<ErrorSuggestion> suggestions, List<String> relatedResources, ErrorDebugInfo debugInfo) {
		this.errorType = errorType;
		this.errorCode = errorCode;
		this.message = message;
		this.context = context;
		this.suggestions = suggestions;
		this.relatedResources = relatedResources;
		this.debugInfo = debugInfo;
	}

	// Getters
	@JsonProperty("errorType")
	public ErrorType getErrorType() {
		return errorType;
	}

	@JsonProperty("errorCode")
	public String getErrorCode() {
		return errorCode;
	}

	@JsonProperty("message")
	public String getMessage() {
		return message;
	}

	@JsonProperty("context")
	public ErrorContext getContext() {
		return context;
	}

	@JsonProperty("suggestions")
	public List<ErrorSuggestion> getSuggestions() {
		return suggestions;
	}

	@JsonProperty("relatedResources")
	public List<String> getRelatedResources() {
		return relatedResources;
	}

	@JsonProperty("debugInfo")
	public ErrorDebugInfo getDebugInfo() {
		return debugInfo;
	}

	// Builder class for easy construction
	public static class Builder {
		private ErrorType errorType;
		private ErrorCode errorCode;
		private String message;
		private ErrorContext context;
		private List<ErrorSuggestion> suggestions;
		private List<String> relatedResources;
		private ErrorDebugInfo debugInfo;

		public Builder errorType(ErrorType errorType) {
			this.errorType = errorType;
			return this;
		}

		public Builder errorCode(ErrorCode errorCode) {
			this.errorCode = errorCode;
			return this;
		}

		public Builder message(String message) {
			this.message = message;
			return this;
		}

		public Builder context(ErrorContext context) {
			this.context = context;
			return this;
		}

		public Builder suggestions(List<ErrorSuggestion> suggestions) {
			this.suggestions = suggestions;
			return this;
		}

		public Builder relatedResources(List<String> relatedResources) {
			this.relatedResources = relatedResources;
			return this;
		}

		public Builder debugInfo(ErrorDebugInfo debugInfo) {
			this.debugInfo = debugInfo;
			return this;
		}

		public GhidraMcpError build() {
			return new GhidraMcpError(
					errorType,
					errorCode != null ? errorCode.getCode() : null,
					message,
					context,
					suggestions,
					relatedResources,
					debugInfo);
		}
	}

	// Static factory methods for common error types
	public static Builder validation() {
		return new Builder().errorType(ErrorType.VALIDATION);
	}

	public static Builder resourceNotFound() {
		return new Builder().errorType(ErrorType.RESOURCE_NOT_FOUND);
	}

	public static Builder dataTypeParsing() {
		return new Builder().errorType(ErrorType.DATA_TYPE_PARSING);
	}

	public static Builder execution() {
		return new Builder().errorType(ErrorType.EXECUTION);
	}

	public static Builder permissionState() {
		return new Builder().errorType(ErrorType.PERMISSION_STATE);
	}

	public static Builder toolExecution() {
		return new Builder().errorType(ErrorType.TOOL_EXECUTION);
	}

	public static Builder searchNoResults() {
		return new Builder().errorType(ErrorType.SEARCH_NO_RESULTS);
	}

	public static Builder groupedOperations() {
		return new Builder().errorType(ErrorType.GROUPED_OPERATIONS);
	}

	public static Builder internal() {
		return new Builder().errorType(ErrorType.INTERNAL);
	}
}