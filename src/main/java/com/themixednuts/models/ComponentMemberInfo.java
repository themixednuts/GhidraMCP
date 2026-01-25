package com.themixednuts.models;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import ghidra.program.model.data.DataTypeComponent;

/**
 * Unified model representing a member (component) within a Structure or Union. Consolidates
 * StructureMemberInfo and UnionMemberInfo into a single model.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ComponentMemberInfo {

  private final String name;
  private final String dataTypePath;
  private final int length;
  private final String comment;

  // Structure-specific fields (null for Union members)
  private final Integer offset;
  private final Integer ordinal;
  private final Boolean isBitField;

  /** Constructor for Structure members (includes all fields). */
  public ComponentMemberInfo(
      String name,
      String dataTypePath,
      int offset,
      int ordinal,
      int length,
      String comment,
      boolean isBitField) {
    this.name = name;
    this.dataTypePath = dataTypePath;
    this.offset = offset;
    this.ordinal = ordinal;
    this.length = length;
    this.comment = comment;
    this.isBitField = isBitField;
  }

  /** Constructor for Union members (no offset, ordinal, or bitfield info). */
  public ComponentMemberInfo(String name, String dataTypePath, int length, String comment) {
    this.name = name;
    this.dataTypePath = dataTypePath;
    this.length = length;
    this.comment = comment;
    this.offset = null;
    this.ordinal = null;
    this.isBitField = null;
  }

  /** Constructor from Ghidra DataTypeComponent (auto-detects type). */
  public ComponentMemberInfo(DataTypeComponent component, boolean includeStructureFields) {
    this.name = component.getFieldName();
    this.dataTypePath = component.getDataType().getPathName();
    this.length = component.getLength();
    this.comment = component.getComment();

    if (includeStructureFields) {
      this.offset = component.getOffset();
      this.ordinal = component.getOrdinal();
      this.isBitField = component.isBitFieldComponent();
    } else {
      this.offset = null;
      this.ordinal = null;
      this.isBitField = null;
    }
  }

  @JsonProperty("name")
  public String getName() {
    return name;
  }

  @JsonProperty("data_type_path")
  public String getDataTypePath() {
    return dataTypePath;
  }

  @JsonProperty("length")
  public int getLength() {
    return length;
  }

  @JsonProperty("comment")
  public String getComment() {
    return comment;
  }

  @JsonProperty("offset")
  public Integer getOffset() {
    return offset;
  }

  @JsonProperty("ordinal")
  public Integer getOrdinal() {
    return ordinal;
  }

  @JsonProperty("is_bit_field")
  public Boolean isBitField() {
    return isBitField;
  }
}
