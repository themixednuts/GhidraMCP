package com.themixednuts.models;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class DataTypeReadResult {

    private final String name;
    private final String pathName;
    private final String kind;
    private final int size;
    private final String description;
    private final List<DataTypeComponentDetail> components;
    private final List<DataTypeEnumValue> enumValues;
    private final int componentCount;
    private final int valueCount;

    public DataTypeReadResult(String name,
                              String pathName,
                              String kind,
                              int size,
                              String description,
                              List<DataTypeComponentDetail> components,
                              List<DataTypeEnumValue> enumValues,
                              int componentCount,
                              int valueCount) {
        this.name = name;
        this.pathName = pathName;
        this.kind = kind;
        this.size = size;
        this.description = description;
        this.components = components;
        this.enumValues = enumValues;
        this.componentCount = componentCount;
        this.valueCount = valueCount;
    }

    @JsonProperty("name")
    public String getName() {
        return name;
    }

    @JsonProperty("path_name")
    public String getPathName() {
        return pathName;
    }

    @JsonProperty("kind")
    public String getKind() {
        return kind;
    }

    @JsonProperty("size")
    public int getSize() {
        return size;
    }

    @JsonProperty("description")
    public String getDescription() {
        return description;
    }

    @JsonProperty("components")
    public List<DataTypeComponentDetail> getComponents() {
        return components;
    }

    @JsonProperty("enum_values")
    public List<DataTypeEnumValue> getEnumValues() {
        return enumValues;
    }

    @JsonProperty("component_count")
    public int getComponentCount() {
        return componentCount;
    }

    @JsonProperty("value_count")
    public int getValueCount() {
        return valueCount;
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record DataTypeComponentDetail(
        String name,
        String type,
        Integer offset,
        Integer length
    ) {}

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record DataTypeEnumValue(
        String name,
        Long value
    ) {}
}

