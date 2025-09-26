package com.themixednuts.models;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class MemorySegmentsOverview {

    private final List<MemorySegmentInfo> segments;
    private final int totalSegments;

    public MemorySegmentsOverview(List<MemorySegmentInfo> segments) {
        this.segments = segments;
        this.totalSegments = segments != null ? segments.size() : 0;
    }

    @JsonProperty("segments")
    public List<MemorySegmentInfo> getSegments() {
        return segments;
    }

    @JsonProperty("total_segments")
    public int getTotalSegments() {
        return totalSegments;
    }
}

