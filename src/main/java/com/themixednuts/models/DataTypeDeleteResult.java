package com.themixednuts.models;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class DataTypeDeleteResult {

  private final String deletedType;
  private final String category;

  public DataTypeDeleteResult(String deletedType, String category) {
    this.deletedType = deletedType;
    this.category = category;
  }

  @JsonProperty("deleted_type")
  public String getDeletedType() {
    return deletedType;
  }

  @JsonProperty("category")
  public String getCategory() {
    return category;
  }
}
