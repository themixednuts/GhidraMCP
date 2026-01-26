package com.themixednuts.models;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/** Represents a single listing entry (instruction or data) from a Ghidra program. */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ListingInfo {
  private final String address;
  private final String label;
  private final String mnemonic;
  private final String operands;
  private final String dataRepresentation;
  private final String type;
  private final Integer length;
  private final String functionName;
  private final String comment;

  public ListingInfo(
      String address,
      String label,
      String instruction,
      String mnemonic,
      String operands,
      String dataRepresentation,
      String type,
      Integer length,
      String functionName,
      String comment) {
    this.address = address;
    this.label = label;
    // Note: 'instruction' param kept for backward compatibility but not stored
    // (it's redundant: instruction = mnemonic + " " + operands)
    this.mnemonic = mnemonic;
    this.operands = operands;
    this.dataRepresentation = dataRepresentation;
    this.type = type;
    this.length = length;
    this.functionName = functionName;
    this.comment = comment;
  }

  @JsonProperty("address")
  public String getAddress() {
    return address;
  }

  @JsonProperty("label")
  public String getLabel() {
    return label;
  }

  @JsonProperty("mnemonic")
  public String getMnemonic() {
    return mnemonic;
  }

  @JsonProperty("operands")
  public String getOperands() {
    return operands;
  }

  @JsonProperty("data_representation")
  public String getDataRepresentation() {
    return dataRepresentation;
  }

  @JsonProperty("type")
  public String getType() {
    return type;
  }

  @JsonProperty("length")
  public Integer getLength() {
    return length;
  }

  @JsonProperty("function_name")
  public String getFunctionName() {
    return functionName;
  }

  @JsonProperty("comment")
  public String getComment() {
    return comment;
  }
}
