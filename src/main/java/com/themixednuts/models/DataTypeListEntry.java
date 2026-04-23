package com.themixednuts.models;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

@JsonPropertyOrder({"name", "path", "data_type_id", "kind", "size", "member_count", "entry_count"})
@JsonInclude(JsonInclude.Include.NON_NULL)
public class DataTypeListEntry {

  private final String name;
  private final String path;
  private final Long dataTypeId;
  private final String kind;
  private final int size;
  private final Integer memberCount;
  private final Integer entryCount;

  public DataTypeListEntry(
      String name,
      String path,
      Long dataTypeId,
      String kind,
      int size,
      Integer memberCount,
      Integer entryCount) {
    this.name = name;
    this.path = path;
    this.dataTypeId = dataTypeId;
    this.kind = kind;
    this.size = size;
    this.memberCount = memberCount;
    this.entryCount = entryCount;
  }

  @JsonProperty("name")
  public String getName() {
    return name;
  }

  @JsonProperty("path")
  public String getPath() {
    return path;
  }

  @JsonProperty("data_type_id")
  @JsonFormat(shape = JsonFormat.Shape.STRING)
  public Long getDataTypeId() {
    return dataTypeId;
  }

  @JsonProperty("kind")
  public String getKind() {
    return kind;
  }

  @JsonProperty("size")
  public int getSize() {
    return size;
  }

  @JsonProperty("member_count")
  public Integer getMemberCount() {
    return memberCount;
  }

  @JsonProperty("entry_count")
  public Integer getEntryCount() {
    return entryCount;
  }
}
