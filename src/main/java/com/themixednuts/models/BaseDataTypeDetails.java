package com.themixednuts.models;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/** Base model containing common details for data types retrieved by GhidraGetDataTypeTool. */
@JsonInclude(JsonInclude.Include.NON_NULL)
public abstract class BaseDataTypeDetails {

  private final DataTypeKind kind;
  private final String path;
  private final String name;
  private final String categoryPath;
  private final int length;
  private final int alignment;
  private final String description;
  private Long dataTypeId;

  protected BaseDataTypeDetails(
      DataTypeKind kind,
      String path,
      String name,
      String categoryPath,
      int length,
      int alignment,
      String description) {
    this.kind = kind;
    this.path = path;
    this.name = name;
    this.categoryPath = categoryPath;
    this.length = length;
    this.alignment = alignment;
    this.description = description;
  }

  @JsonProperty("kind")
  public DataTypeKind getKind() {
    return kind;
  }

  @JsonProperty("path")
  public String getPath() {
    return path;
  }

  @JsonProperty("name")
  public String getName() {
    return name;
  }

  @JsonProperty("category_path")
  public String getCategoryPath() {
    return categoryPath;
  }

  @JsonProperty("length")
  public int getLength() {
    return length;
  }

  @JsonProperty("alignment")
  public int getAlignment() {
    return alignment;
  }

  @JsonProperty("description")
  public String getDescription() {
    return description;
  }

  @JsonProperty("data_type_id")
  public Long getDataTypeId() {
    return dataTypeId;
  }

  public void setDataTypeId(Long dataTypeId) {
    this.dataTypeId = dataTypeId;
  }
}
