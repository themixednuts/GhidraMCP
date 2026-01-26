package com.themixednuts.models.versiontracking;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

/** Represents metadata and statistics about a Version Tracking session. */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record VTSessionInfo(
    @JsonProperty("name") String name,
    @JsonProperty("source_program") String sourceProgram,
    @JsonProperty("destination_program") String destinationProgram,
    @JsonProperty("total_matches") int totalMatches,
    @JsonProperty("accepted_matches") int acceptedMatches,
    @JsonProperty("rejected_matches") int rejectedMatches,
    @JsonProperty("blocked_matches") int blockedMatches,
    @JsonProperty("applied_markup_count") int appliedMarkupCount,
    @JsonProperty("match_sets") List<String> matchSets) {}
