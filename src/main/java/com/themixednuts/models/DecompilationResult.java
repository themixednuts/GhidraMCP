package com.themixednuts.models;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.themixednuts.utils.TextSearch;
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
  private String decompilationId;
  private Integer codeStartLine;
  private Integer codeTotalLines;
  private Integer nextLine;
  private Integer basicBlockCount;
  private List<Map<String, Object>> pcodeOperations;
  private String searchText;
  private Integer totalMatches;
  private Integer omittedMatches;
  private Integer nextMatchOffset;
  private List<Integer> matchingLines;

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

  @JsonProperty("decompilation_id")
  public String getDecompilationId() {
    return decompilationId;
  }

  public void setDecompilationId(String decompilationId) {
    this.decompilationId = decompilationId;
  }

  @JsonProperty("code_start_line")
  public Integer getCodeStartLine() {
    return codeStartLine;
  }

  @JsonProperty("code_total_lines")
  public Integer getCodeTotalLines() {
    return codeTotalLines;
  }

  @JsonProperty("next_line")
  public Integer getNextLine() {
    return nextLine;
  }

  public void setCodeWindow(int startLine, int totalLines, Integer nextLine) {
    this.codeStartLine = startLine;
    this.codeTotalLines = totalLines;
    this.nextLine = nextLine;
  }

  public void setCodeSearch(String query, TextSearch search) {
    this.searchText = query;
    this.codeTotalLines = search.totalLines();
    this.totalMatches = search.totalMatches();
    this.omittedMatches = search.omittedMatches();
    this.nextMatchOffset = search.nextMatchOffset();
    this.matchingLines = search.matchingLines();
  }

  @JsonProperty("search_text")
  public String getSearchText() {
    return searchText;
  }

  @JsonProperty("total_matches")
  public Integer getTotalMatches() {
    return totalMatches;
  }

  @JsonProperty("omitted_matches")
  public Integer getOmittedMatches() {
    return omittedMatches;
  }

  @JsonProperty("next_match_offset")
  public Integer getNextMatchOffset() {
    return nextMatchOffset;
  }

  @JsonProperty("matching_lines")
  public List<Integer> getMatchingLines() {
    return matchingLines;
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
