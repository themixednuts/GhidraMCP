package com.themixednuts.models;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;
import java.util.Map;

/**
 * Standardized payload for create / update / delete operations. Failures are reported on the
 * envelope, so this class only carries the per-operation context that's useful on a success: which
 * operation ran, what target it touched, a human-readable message, and any extras the tool wants to
 * attach. Tools should throw {@code GhidraMcpException} for failures rather than building an {@code
 * OperationResult} with a failure flag.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class OperationResult {
  private final String operation;
  private final String target;
  private final String message;

  private Object result;
  private List<String> warnings;
  private Map<String, Object> metadata;

  public OperationResult(String operation, String target, String message) {
    this.operation = operation;
    this.target = target;
    this.message = message;
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

  public static OperationResult success(String operation, String target, String message) {
    return new OperationResult(operation, target, message);
  }
}
