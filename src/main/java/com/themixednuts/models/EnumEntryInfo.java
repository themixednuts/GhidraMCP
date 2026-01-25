package com.themixednuts.models;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/** Model representing an entry within an Enum data type. */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class EnumEntryInfo {

  private final String name;
  private final long value;
  private final String comment;

  public EnumEntryInfo(String name, long value, String comment) {
    this.name = name;
    this.value = value;
    this.comment = comment;
  }

  public EnumEntryInfo(String name, long value) {
    this.name = name;
    this.value = value;
    this.comment = null;
  }

  @JsonProperty("name")
  public String getName() {
    return name;
  }

  @JsonProperty("value")
  public long getValue() {
    return value;
  }

  @JsonProperty("comment")
  public String getComment() {
    return comment;
  }
}
