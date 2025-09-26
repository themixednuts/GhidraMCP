package com.themixednuts.models;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Represents a single analysis option within a Ghidra program along with its metadata.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AnalysisOptionInfo {

    private final String name;
    private final String description;
    private final String type;
    private final String value;
    private final boolean usingDefaultValue;

    public AnalysisOptionInfo(String name,
            String description,
            String type,
            String value,
            boolean usingDefaultValue) {
        this.name = name;
        this.description = description;
        this.type = type;
        this.value = value;
        this.usingDefaultValue = usingDefaultValue;
    }

    @JsonProperty("name")
    public String getName() {
        return name;
    }

    @JsonProperty("description")
    public String getDescription() {
        return description;
    }

    @JsonProperty("type")
    public String getType() {
        return type;
    }

    @JsonProperty("value")
    public String getValue() {
        return value;
    }

    @JsonProperty("using_default_value")
    public boolean isUsingDefaultValue() {
        return usingDefaultValue;
    }
}


