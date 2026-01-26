package com.themixednuts.models.versiontracking;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Represents information about a Version Tracking correlator type.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record VTCorrelatorInfo(
    @JsonProperty("name") String name,
    @JsonProperty("type") String type,
    @JsonProperty("description") String description
) {}
