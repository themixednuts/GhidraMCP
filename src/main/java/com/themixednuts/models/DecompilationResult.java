package com.themixednuts.models;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;
import java.util.Map;

/**
 * Comprehensive decompilation result model. Used by DecompileCodeTool to return structured
 * decompilation data.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class DecompilationResult {
  private final String type;
  private final String targetName;
  private final String entryAddress;
  private final boolean decompilationSuccessful;
  private final String decompiledCode;
  private final String errorMessage;

  // Optional analysis data
  private Integer parameterCount;
  private String returnType;
  private Integer bodySize;
  private List<Map<String, Object>> pcodeOperations;
  private Integer pcodeCount;
  private Map<String, Object> astInfo;

  public DecompilationResult(
      String type,
      String targetName,
      String entryAddress,
      boolean successful,
      String code,
      String error) {
    this.type = type;
    this.targetName = targetName;
    this.entryAddress = entryAddress;
    this.decompilationSuccessful = successful;
    this.decompiledCode = code;
    this.errorMessage = error;
  }

  @JsonProperty("type")
  public String getType() {
    return type;
  }

  @JsonProperty("target_name")
  public String getTargetName() {
    return targetName;
  }

  @JsonProperty("entry_address")
  public String getEntryAddress() {
    return entryAddress;
  }

  @JsonProperty("decompilation_successful")
  public boolean isDecompilationSuccessful() {
    return decompilationSuccessful;
  }

  @JsonProperty("decompiled_code")
  public String getDecompiledCode() {
    return decompiledCode;
  }

  @JsonProperty("error_message")
  public String getErrorMessage() {
    return errorMessage;
  }

  @JsonProperty("parameter_count")
  public Integer getParameterCount() {
    return parameterCount;
  }

  public void setParameterCount(Integer parameterCount) {
    this.parameterCount = parameterCount;
  }

  @JsonProperty("return_type")
  public String getReturnType() {
    return returnType;
  }

  public void setReturnType(String returnType) {
    this.returnType = returnType;
  }

  @JsonProperty("body_size")
  public Integer getBodySize() {
    return bodySize;
  }

  public void setBodySize(Integer bodySize) {
    this.bodySize = bodySize;
  }

  @JsonProperty("pcode_operations")
  public List<Map<String, Object>> getPcodeOperations() {
    return pcodeOperations;
  }

  public void setPcodeOperations(List<Map<String, Object>> pcodeOperations) {
    this.pcodeOperations = pcodeOperations;
    if (pcodeOperations != null) {
      this.pcodeCount = pcodeOperations.size();
    }
  }

  @JsonProperty("pcode_count")
  public Integer getPcodeCount() {
    return pcodeCount;
  }

  @JsonProperty("ast_info")
  public Map<String, Object> getAstInfo() {
    return astInfo;
  }

  public void setAstInfo(Map<String, Object> astInfo) {
    this.astInfo = astInfo;
  }
}
