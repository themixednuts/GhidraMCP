package com.themixednuts.models;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Criteria metadata returned alongside function search results.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class FunctionSearchCriteria {

    private final String targetType;
    private final String searchPattern;
    private final String targetValue;
    private final String cursor;

    public FunctionSearchCriteria(String targetType, String searchPattern, String targetValue, String cursor) {
        this.targetType = targetType;
        this.searchPattern = normalize(searchPattern);
        this.targetValue = normalize(targetValue);
        this.cursor = normalize(cursor);
    }

    private static String normalize(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    @JsonProperty("target_type")
    public String getTargetType() {
        return targetType;
    }

    @JsonProperty("search_pattern")
    public String getSearchPattern() {
        return searchPattern;
    }

    @JsonProperty("target_value")
    public String getTargetValue() {
        return targetValue;
    }

    @JsonProperty("cursor")
    public String getCursor() {
        return cursor;
    }
}

