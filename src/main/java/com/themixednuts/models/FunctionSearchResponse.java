package com.themixednuts.models;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

/**
 * Standard search response wrapper for function-based queries.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class FunctionSearchResponse {

    private final FunctionSearchCriteria criteria;
    private final List<FunctionInfo> results;
    private final int totalFound;
    private final int returnedCount;
    private final int limit;
    private final boolean truncated;
    private final String nextCursor;

    public FunctionSearchResponse(FunctionSearchCriteria criteria,
                                  List<FunctionInfo> results,
                                  int totalFound,
                                  int returnedCount,
                                  int limit,
                                  boolean truncated,
                                  String nextCursor) {
        this.criteria = criteria;
        this.results = results;
        this.totalFound = totalFound;
        this.returnedCount = returnedCount;
        this.limit = limit;
        this.truncated = truncated;
        this.nextCursor = nextCursor;
    }

    @JsonProperty("criteria")
    public FunctionSearchCriteria getCriteria() {
        return criteria;
    }

    @JsonProperty("results")
    public List<FunctionInfo> getResults() {
        return results;
    }

    @JsonProperty("total_found")
    public int getTotalFound() {
        return totalFound;
    }

    @JsonProperty("returned_count")
    public int getReturnedCount() {
        return returnedCount;
    }

    @JsonProperty("limit")
    public int getLimit() {
        return limit;
    }

    @JsonProperty("truncated")
    public boolean isTruncated() {
        return truncated;
    }

    @JsonProperty("next_cursor")
    public String getNextCursor() {
        return nextCursor;
    }
}

