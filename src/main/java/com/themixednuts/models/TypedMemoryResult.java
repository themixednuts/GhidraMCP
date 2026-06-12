package com.themixednuts.models;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class TypedMemoryResult {
  private final String address;
  private final String dataType;
  private final String dataTypePath;
  private final String dataTypeKind;
  private final Integer length;
  private final String hexData;
  private final Boolean applied;
  private final Integer fieldOffset;
  private final Integer fieldCount;
  private final List<TypedMemoryField> fields;

  public TypedMemoryResult(
      String address,
      String dataType,
      String dataTypePath,
      String dataTypeKind,
      Integer length,
      String hexData,
      Boolean applied,
      Integer fieldOffset,
      Integer fieldCount,
      List<TypedMemoryField> fields) {
    this.address = address;
    this.dataType = dataType;
    this.dataTypePath = dataTypePath;
    this.dataTypeKind = dataTypeKind;
    this.length = length;
    this.hexData = hexData;
    this.applied = applied;
    this.fieldOffset = fieldOffset;
    this.fieldCount = fieldCount;
    this.fields = fields;
  }

  @JsonProperty("address")
  public String getAddress() {
    return address;
  }

  @JsonProperty("data_type")
  public String getDataType() {
    return dataType;
  }

  @JsonProperty("data_type_path")
  public String getDataTypePath() {
    return dataTypePath;
  }

  @JsonProperty("data_type_kind")
  public String getDataTypeKind() {
    return dataTypeKind;
  }

  @JsonProperty("length")
  public Integer getLength() {
    return length;
  }

  @JsonProperty("hex_data")
  public String getHexData() {
    return hexData;
  }

  @JsonProperty("applied")
  public Boolean getApplied() {
    return applied;
  }

  @JsonProperty("field_offset")
  public Integer getFieldOffset() {
    return fieldOffset;
  }

  @JsonProperty("field_count")
  public Integer getFieldCount() {
    return fieldCount;
  }

  @JsonProperty("fields")
  public List<TypedMemoryField> getFields() {
    return fields;
  }
}
