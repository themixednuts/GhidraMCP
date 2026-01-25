package com.themixednuts.models;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class FunctionGraphNode {

  private final String id;
  private final String addressRange;
  private final String label;

  public FunctionGraphNode(String id, String addressRange, String label) {
    this.id = id;
    this.addressRange = addressRange;
    this.label = label;
  }

  @JsonProperty("id")
  public String getId() {
    return id;
  }

  @JsonProperty("address_range")
  public String getAddressRange() {
    return addressRange;
  }

  @JsonProperty("label")
  public String getLabel() {
    return label;
  }
}
