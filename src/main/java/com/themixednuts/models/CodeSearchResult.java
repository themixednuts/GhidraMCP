package com.themixednuts.models;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

/** Bounded matches from one page of a program-wide decompiled code search. */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record CodeSearchResult(
    List<Hit> matches,
    @JsonProperty("functions_scanned") int functionsScanned,
    @JsonProperty("next_cursor") String nextCursor,
    boolean complete,
    @JsonProperty("interrupted_at") String interruptedAt) {
  public record Hit(
      @JsonProperty("function_name") String functionName,
      @JsonProperty("entry_address") String entryAddress,
      @JsonProperty("decompilation_id") String decompilationId,
      String excerpt,
      @JsonProperty("matching_lines") List<Integer> matchingLines,
      @JsonProperty("total_matches_in_function") int totalMatchesInFunction) {}
}
