package com.themixednuts.models;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class DataTypeListEntry {

    private final String name;
    private final String path;
    private final String kind;
    private final int size;
    private final String description;
    private final String category;

    public DataTypeListEntry(String name,
                              String path,
                              String kind,
                              int size,
                              String description,
                              String category) {
        this.name = name;
        this.path = path;
        this.kind = kind;
        this.size = size;
        this.description = description;
        this.category = category;
    }

    @JsonProperty("name")
    public String getName() {
        return name;
    }

    @JsonProperty("path")
    public String getPath() {
        return path;
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

    @JsonProperty("category")
    public String getCategory() {
        return category;
    }
}

