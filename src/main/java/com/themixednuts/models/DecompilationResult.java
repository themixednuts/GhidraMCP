package com.themixednuts.models;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;
import java.util.Map;

/**
 * Decompilation payload returned by InspectTool's decompile action. Failure cases are reported via
 * the response envelope, not via a flag inside the payload — if a {@code DecompilationResult} is
 * present the decompile completed.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class DecompilationResult {
  private final String targetName;
  private final String entryAddress;
  private final String decompiledCode;
  private final Integer bodySize;
  private Integer basicBlockCount;
  private List<Map<String, Object>> pcodeOperations;

  public DecompilationResult(
      String targetName, String entryAddress, String decompiledCode, Integer bodySize) {
    this.targetName = targetName;
    this.entryAddress = entryAddress;
    this.decompiledCode = decompiledCode;
    this.bodySize = bodySize;
  }

  @JsonProperty("target_name")
  public String getTargetName() {
    return targetName;
  }

  @JsonProperty("entry_address")
  public String getEntryAddress() {
    return entryAddress;
  }

  @JsonProperty("decompiled_code")
  public String getDecompiledCode() {
    return decompiledCode;
  }

  @JsonProperty("body_size")
  public Integer getBodySize() {
    return bodySize;
  }

  @JsonProperty("basic_block_count")
  public Integer getBasicBlockCount() {
    return basicBlockCount;
  }

  public void setBasicBlockCount(Integer basicBlockCount) {
    this.basicBlockCount = basicBlockCount;
  }

  @JsonProperty("pcode_operations")
  public List<Map<String, Object>> getPcodeOperations() {
    return pcodeOperations;
  }

  public void setPcodeOperations(List<Map<String, Object>> pcodeOperations) {
    this.pcodeOperations = pcodeOperations;
  }
}
