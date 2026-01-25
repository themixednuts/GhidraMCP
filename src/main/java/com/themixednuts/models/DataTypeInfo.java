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

  // Fields duplicated in BaseDataTypeDetails are removed:
  // name, pathName, categoryPath, length, alignment, description

  private final String displayName;
  private final int alignedLength;
  private final boolean isZeroLength;
  private final boolean isStructure;
  private final boolean isUnion;
  private final boolean isEnum;
  private final boolean isTypeDef;
  private final boolean isPointer;
  private final boolean isFunctionDefinition;
  private BaseDataTypeDetails details;

  public DataTypeInfo(DataType dataType) {
    // Initialize fields unique to DataTypeInfo
    this.displayName = dataType.getDisplayName();
    this.alignedLength = dataType.getAlignedLength();
    this.isZeroLength = dataType.isZeroLength();

    // Set type flags
    this.isStructure = dataType instanceof Structure;
    this.isUnion = dataType instanceof Union;
    this.isEnum = dataType instanceof Enum;
    this.isTypeDef = dataType instanceof TypeDef;
    this.isPointer = dataType instanceof Pointer;
    this.isFunctionDefinition = dataType instanceof FunctionDefinitionDataType;

    // Populate details based on the type - this now creates the object containing
    // the previously duplicated fields.
    if (this.isStructure) {
      this.details = new StructureDetails((Structure) dataType);
    } else if (this.isUnion) {
      this.details = new UnionDetails((Union) dataType);
    } else if (this.isEnum) {
      this.details = new EnumDetails((Enum) dataType);
    } else if (this.isTypeDef) {
      this.details = new TypedefDetails((TypeDef) dataType);
    } else if (this.isFunctionDefinition) {
      this.details = new FunctionDefinitionDetails((FunctionDefinitionDataType) dataType);
    } else if (this.isPointer) {
      this.details = new PointerDetails((Pointer) dataType);
    } else {
      this.details = new OtherDataTypeDetails(dataType);
    }
  }

  // Getters for fields unique to DataTypeInfo
  @JsonProperty("display_name")
  public String getDisplayName() {
    return displayName;
  }

  @JsonProperty("aligned_length")
  public int getAlignedLength() {
    return alignedLength;
  }

  @JsonProperty("is_zero_length")
  public boolean isZeroLength() {
    return isZeroLength;
  }

  // Getters for type flags
  @JsonProperty("is_structure")
  public boolean isStructure() {
    return isStructure;
  }

  @JsonProperty("is_union")
  public boolean isUnion() {
    return isUnion;
  }

  @JsonProperty("is_enum")
  public boolean isEnum() {
    return isEnum;
  }

  @JsonProperty("is_type_def")
  public boolean isTypeDef() {
    return isTypeDef;
  }

  @JsonProperty("is_pointer")
  public boolean isPointer() {
    return isPointer;
  }

  @JsonProperty("is_function_definition")
  public boolean isFunctionDefinition() {
    return isFunctionDefinition;
  }

  @JsonProperty("details")
  @JsonInclude(JsonInclude.Include.NON_NULL)
  public BaseDataTypeDetails getDetails() {
    return details;
  }

  // Removed getters for name, pathName, categoryPath, length, alignment,
  // description
}
