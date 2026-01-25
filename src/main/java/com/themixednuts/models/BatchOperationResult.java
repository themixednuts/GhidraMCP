package com.themixednuts.models;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

/**
 * Result of a batch operation containing all individual operation results. Used by
 * BatchOperationsTool to return structured results for multiple tool executions.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class BatchOperationResult {
  private final boolean success;
  private final int totalOperations;
  private final int successfulOperations;
  private final int failedOperations;
  private final List<IndividualOperationResult> operations;
  private final String message;

  public BatchOperationResult(
      boolean success,
      int totalOperations,
      int successfulOperations,
      int failedOperations,
      List<IndividualOperationResult> operations,
      String message) {
    this.success = success;
    this.totalOperations = totalOperations;
    this.successfulOperations = successfulOperations;
    this.failedOperations = failedOperations;
    this.operations = operations;
    this.message = message;
  }

  @JsonProperty("success")
  public boolean isSuccess() {
    return success;
  }

  @JsonProperty("total_operations")
  public int getTotalOperations() {
    return totalOperations;
  }

  @JsonProperty("successful_operations")
  public int getSuccessfulOperations() {
    return successfulOperations;
  }

  @JsonProperty("failed_operations")
  public int getFailedOperations() {
    return failedOperations;
  }

  @JsonProperty("operations")
  public List<IndividualOperationResult> getOperations() {
    return operations;
  }

  @JsonProperty("message")
  public String getMessage() {
    return message;
  }

  /** Represents a single operation result within a batch. */
  @JsonInclude(JsonInclude.Include.NON_NULL)
  public static class IndividualOperationResult {
    private final int operationIndex;
    private final String toolName;
    private final boolean success;
    private final Object result;
    private final GhidraMcpError error;

    public IndividualOperationResult(
        int operationIndex, String toolName, boolean success, Object result, GhidraMcpError error) {
      this.operationIndex = operationIndex;
      this.toolName = toolName;
      this.success = success;
      this.result = result;
      this.error = error;
    }

    @JsonProperty("operation_index")
    public int getOperationIndex() {
      return operationIndex;
    }

    @JsonProperty("tool_name")
    public String getToolName() {
      return toolName;
    }

    @JsonProperty("success")
    public boolean isSuccess() {
      return success;
    }

    @JsonProperty("result")
    public Object getResult() {
      return result;
    }

    @JsonProperty("error")
    public GhidraMcpError getError() {
      return error;
    }

    public static IndividualOperationResult success(int index, String toolName, Object result) {
      return new IndividualOperationResult(index, toolName, true, result, null);
    }

    public static IndividualOperationResult failure(
        int index, String toolName, GhidraMcpError error) {
      return new IndividualOperationResult(index, toolName, false, null, error);
    }
  }
}
