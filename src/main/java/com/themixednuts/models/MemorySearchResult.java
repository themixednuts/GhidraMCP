package com.themixednuts.models;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.themixednuts.utils.PaginatedResult;

/** Memory search result model. Used by ManageMemoryTool for search operations. */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class MemorySearchResult {
  private final String searchTerm;
  private final String searchType;
  private final boolean caseSensitive;
  private final PaginatedResult<MemoryMatch> results;
  private final int totalMatches;
  private final int returnedCount;
  private final int pageSize;
  private final long searchTimeMs;

  public MemorySearchResult(
      String searchTerm,
      String searchType,
      boolean caseSensitive,
      PaginatedResult<MemoryMatch> results,
      int totalMatches,
      int returnedCount,
      int pageSize,
      long searchTimeMs) {
    this.searchTerm = searchTerm;
    this.searchType = searchType;
    this.caseSensitive = caseSensitive;
    this.results = results;
    this.totalMatches = totalMatches;
    this.returnedCount = returnedCount;
    this.pageSize = pageSize;
    this.searchTimeMs = searchTimeMs;
  }

  @JsonProperty("search_term")
  public String getSearchTerm() {
    return searchTerm;
  }

  @JsonProperty("search_type")
  public String getSearchType() {
    return searchType;
  }

  @JsonProperty("case_sensitive")
  public boolean isCaseSensitive() {
    return caseSensitive;
  }

  @JsonProperty("results")
  public PaginatedResult<MemoryMatch> getResults() {
    return results;
  }

  @JsonProperty("total_matches")
  public int getTotalMatches() {
    return totalMatches;
  }

  @JsonProperty("returned_count")
  public int getReturnedCount() {
    return returnedCount;
  }

  @JsonProperty("page_size")
  public int getPageSize() {
    return pageSize;
  }

  @JsonProperty("search_time_ms")
  public long getSearchTimeMs() {
    return searchTimeMs;
  }

  /** Individual memory match within a search result. */
  @JsonInclude(JsonInclude.Include.NON_NULL)
  public static class MemoryMatch {
    private final String address;
    private final String hexBytes;
    private final String readable;
    private final int length;

    public MemoryMatch(String address, String hexBytes, String readable, int length) {
      this.address = address;
      this.hexBytes = hexBytes;
      this.readable = readable;
      this.length = length;
    }

    @JsonProperty("address")
    public String getAddress() {
      return address;
    }

    @JsonProperty("hex_bytes")
    public String getHexBytes() {
      return hexBytes;
    }

    @JsonProperty("readable")
    public String getReadable() {
      return readable;
    }

    @JsonProperty("length")
    public int getLength() {
      return length;
    }
  }
}
