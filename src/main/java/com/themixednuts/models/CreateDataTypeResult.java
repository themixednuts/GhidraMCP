package com.themixednuts.models;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Map;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class CreateDataTypeResult {

  private final String kind;
  private final String name;
  private final String pathName;
  private final String message;
  private final Map<String, Object> details;

  public CreateDataTypeResult(
      String kind, String name, String pathName, String message, Map<String, Object> details) {
    this.kind = kind;
    this.name = name;
    this.pathName = pathName;
    this.message = message;
    this.details = details;
  }

  @JsonProperty("kind")
  public String getKind() {
    return kind;
  }

  @JsonProperty("name")
  public String getName() {
    return name;
  }

  @JsonProperty("path_name")
  public String getPathName() {
    return pathName;
  }

  @JsonProperty("message")
  public String getMessage() {
    return message;
  }

  @JsonProperty("details")
  public Map<String, Object> getDetails() {
    return details;
  }
}
