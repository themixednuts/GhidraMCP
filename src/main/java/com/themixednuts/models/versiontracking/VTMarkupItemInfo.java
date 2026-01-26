package com.themixednuts.models.versiontracking;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Represents details about a Version Tracking markup item (analysis data that can be transferred).
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record VTMarkupItemInfo(
    @JsonProperty("markup_type") String markupType,
    @JsonProperty("source_address") String sourceAddress,
    @JsonProperty("destination_address") String destinationAddress,
    @JsonProperty("source_value") String sourceValue,
    @JsonProperty("destination_value") String destinationValue,
    @JsonProperty("status") String status
) {}
