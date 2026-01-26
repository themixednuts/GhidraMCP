package com.themixednuts.models.versiontracking;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/** Represents details about a Version Tracking match between source and destination addresses. */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record VTMatchInfo(
    @JsonProperty("source_address") String sourceAddress,
    @JsonProperty("destination_address") String destinationAddress,
    @JsonProperty("match_type") String matchType,
    @JsonProperty("similarity") double similarity,
    @JsonProperty("confidence") double confidence,
    @JsonProperty("status") String status,
    @JsonProperty("correlator") String correlator,
    @JsonProperty("source_name") String sourceName,
    @JsonProperty("destination_name") String destinationName,
    @JsonProperty("markup_item_count") int markupItemCount) {}
