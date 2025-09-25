package com.themixednuts.models;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

/**
 * Memory search result model.
 * Used by ManageMemoryTool for search operations.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class MemorySearchResult {
    private final String searchTerm;
    private final String searchType;
    private final int totalMatches;
    private final List<MemoryMatch> matches;
    private final long searchTimeMs;

    public MemorySearchResult(String searchTerm, String searchType, List<MemoryMatch> matches, long searchTimeMs) {
        this.searchTerm = searchTerm;
        this.searchType = searchType;
        this.matches = matches;
        this.totalMatches = matches != null ? matches.size() : 0;
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

    @JsonProperty("total_matches")
    public int getTotalMatches() {
        return totalMatches;
    }

    @JsonProperty("matches")
    public List<MemoryMatch> getMatches() {
        return matches;
    }

    @JsonProperty("search_time_ms")
    public long getSearchTimeMs() {
        return searchTimeMs;
    }

    /**
     * Individual memory match within a search result.
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class MemoryMatch {
        private final String address;
        private final String context;
        private final int matchLength;
        private final String memoryBlockName;

        public MemoryMatch(String address, String context, int matchLength, String memoryBlockName) {
            this.address = address;
            this.context = context;
            this.matchLength = matchLength;
            this.memoryBlockName = memoryBlockName;
        }

        @JsonProperty("address")
        public String getAddress() {
            return address;
        }

        @JsonProperty("context")
        public String getContext() {
            return context;
        }

        @JsonProperty("match_length")
        public int getMatchLength() {
            return matchLength;
        }

        @JsonProperty("memory_block")
        public String getMemoryBlockName() {
            return memoryBlockName;
        }
    }
}