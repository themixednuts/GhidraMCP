package com.themixednuts.models;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import ghidra.program.model.data.DataType;
// Import specific types for instanceof checks
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.Union;

/** Utility class to hold relevant information about a Ghidra DataType for JSON serialization. */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class DataTypeInfo {

  private final String name;
  private final String type;
  private final int len;
  private BaseDataTypeDetails details;

  public DataTypeInfo(DataType dataType) {
    this.name = dataType.getDisplayName();
    this.len = dataType.getAlignedLength();

    // Determine type string
    if (dataType instanceof Structure) {
      this.type = "struct";
      this.details = new StructureDetails((Structure) dataType);
    } else if (dataType instanceof Union) {
      this.type = "union";
      this.details = new UnionDetails((Union) dataType);
    } else if (dataType instanceof Enum) {
      this.type = "enum";
      this.details = new EnumDetails((Enum) dataType);
    } else if (dataType instanceof TypeDef) {
      this.type = "typedef";
      this.details = new TypedefDetails((TypeDef) dataType);
    } else if (dataType instanceof FunctionDefinitionDataType) {
      this.type = "function_definition";
      this.details = new FunctionDefinitionDetails((FunctionDefinitionDataType) dataType);
    } else if (dataType instanceof Pointer) {
      this.type = "pointer";
      this.details = new PointerDetails((Pointer) dataType);
    } else {
      this.type = "other";
      this.details = new OtherDataTypeDetails(dataType);
    }
  }

  @JsonProperty("name")
  public String getName() {
    return name;
  }

  @JsonProperty("type")
  public String getType() {
    return type;
  }

  @JsonProperty("length")
  public int getLength() {
    return len;
  }

  @JsonProperty("details")
  @JsonInclude(JsonInclude.Include.NON_NULL)
  public BaseDataTypeDetails getDetails() {
    return details;
  }
}
