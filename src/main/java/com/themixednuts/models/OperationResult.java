package com.themixednuts.models;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;
import java.util.Map;

/**
 * Standardized operation result for create, update, delete operations. Provides consistent response
 * format across all tools.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class OperationResult {
  private final boolean success;
  private final String operation;
  private final String target;
  private final String message;
  private final String details;

  // Optional additional data
  private Object result;
  private List<String> warnings;
  private Map<String, Object> metadata;

  public OperationResult(boolean success, String operation, String target, String message) {
    this.success = success;
    this.operation = operation;
    this.target = target;
    this.message = message;
    this.details = null;
  }

  public OperationResult(
      boolean success, String operation, String target, String message, String details) {
    this.success = success;
    this.operation = operation;
    this.target = target;
    this.message = message;
    this.details = details;
  }

  @JsonProperty("success")
  public boolean isSuccess() {
    return success;
  }

  @JsonProperty("operation")
  public String getOperation() {
    return operation;
  }

  @JsonProperty("target")
  public String getTarget() {
    return target;
  }

  @JsonProperty("message")
  public String getMessage() {
    return message;
  }

  @JsonProperty("details")
  public String getDetails() {
    return details;
  }

  @JsonProperty("result")
  public Object getResult() {
    return result;
  }

  public OperationResult setResult(Object result) {
    this.result = result;
    return this;
  }

  @JsonProperty("warnings")
  public List<String> getWarnings() {
    return warnings;
  }

  public OperationResult setWarnings(List<String> warnings) {
    this.warnings = warnings;
    return this;
  }

  @JsonProperty("metadata")
  public Map<String, Object> getMetadata() {
    return metadata;
  }

  public OperationResult setMetadata(Map<String, Object> metadata) {
    this.metadata = metadata;
    return this;
  }

  // Static factory methods for common patterns
  public static OperationResult success(String operation, String target, String message) {
    return new OperationResult(true, operation, target, message);
  }

  public static OperationResult failure(String operation, String target, String message) {
    return new OperationResult(false, operation, target, message);
  }

  public static OperationResult failure(
      String operation, String target, String message, String details) {
    return new OperationResult(false, operation, target, message, details);
  }
}
