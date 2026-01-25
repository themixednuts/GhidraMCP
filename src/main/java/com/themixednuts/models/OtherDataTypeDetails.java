package com.themixednuts.models;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import ghidra.program.model.data.DataType;
import java.util.Optional;

/** Model representing details for other non-specifically-handled data types. */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class OtherDataTypeDetails extends BaseDataTypeDetails {

  private final String dataTypeClassName;

  public OtherDataTypeDetails(DataType dt) {
    super(
        DataTypeKind.OTHER, // Updated to OTHER
        dt.getPathName(),
        dt.getName(),
        dt.getCategoryPath().getPath(),
        dt.getLength(),
        dt.getAlignment(),
        Optional.ofNullable(dt.getDescription()).orElse(""));
    this.dataTypeClassName = dt.getClass().getSimpleName();
  }

  @JsonProperty("data_type_class_name")
  public String getDataTypeClassName() {
    return dataTypeClassName;
  }
}
