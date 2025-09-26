package com.themixednuts.models;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class MemorySegmentAnalysisResult {

    private final String name;
    private final String startAddress;
    private final String endAddress;
    private final long size;
    private final String permissions;
    private final String type;
    private final boolean initialized;
    private final String comment;
    private final String sourceName;
    private final boolean overlay;

    public MemorySegmentAnalysisResult(String name,
                                       String startAddress,
                                       String endAddress,
                                       long size,
                                       String permissions,
                                       String type,
                                       boolean initialized,
                                       String comment,
                                       String sourceName,
                                       boolean overlay) {
        this.name = name;
        this.startAddress = startAddress;
        this.endAddress = endAddress;
        this.size = size;
        this.permissions = permissions;
        this.type = type;
        this.initialized = initialized;
        this.comment = comment;
        this.sourceName = sourceName;
        this.overlay = overlay;
    }

    @JsonProperty("name")
    public String getName() {
        return name;
    }

    @JsonProperty("start_address")
    public String getStartAddress() {
        return startAddress;
    }

    @JsonProperty("end_address")
    public String getEndAddress() {
        return endAddress;
    }

    @JsonProperty("size")
    public long getSize() {
        return size;
    }

    @JsonProperty("permissions")
    public String getPermissions() {
        return permissions;
    }

    @JsonProperty("type")
    public String getType() {
        return type;
    }

    @JsonProperty("initialized")
    public boolean isInitialized() {
        return initialized;
    }

    @JsonProperty("comment")
    public String getComment() {
        return comment;
    }

    @JsonProperty("source_name")
    public String getSourceName() {
        return sourceName;
    }

    @JsonProperty("overlay")
    public boolean isOverlay() {
        return overlay;
    }
}

