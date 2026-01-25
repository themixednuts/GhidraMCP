package com.themixednuts.models;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class FunctionGraphEdge {

  private final String sourceId;
  private final String targetId;
  private final String edgeType;

  public FunctionGraphEdge(String sourceId, String targetId, String edgeType) {
    this.sourceId = sourceId;
    this.targetId = targetId;
    this.edgeType = edgeType;
  }

  @JsonProperty("source_id")
  public String getSourceId() {
    return sourceId;
  }

  @JsonProperty("target_id")
  public String getTargetId() {
    return targetId;
  }

  @JsonProperty("edge_type")
  public String getEdgeType() {
    return edgeType;
  }
}
