package com.themixednuts.models;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Namespace;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class FunctionInfo {
  private final String name;
  private final String entryPoint;
  private final String signature;
  private final String callingConvention;
  private final String namespace;
  private final String startAddress;
  private final String endAddress;

  public FunctionInfo(Function function) {
    this.name = function.getName();

    if (function.getEntryPoint() != null) {
      this.entryPoint = function.getEntryPoint().toString();
    } else {
      this.entryPoint = null;
    }

    this.signature = function.getSignature(true).getPrototypeString();
    this.callingConvention = function.getCallingConventionName();

    Namespace parentNs = function.getParentNamespace();
    this.namespace = (parentNs != null) ? parentNs.getName(true) : null;

    if (function.getBody() != null) {
      this.startAddress =
          function.getBody().getMinAddress() != null
              ? function.getBody().getMinAddress().toString()
              : null;
      this.endAddress =
          function.getBody().getMaxAddress() != null
              ? function.getBody().getMaxAddress().toString()
              : null;
    } else {
      this.startAddress = null;
      this.endAddress = null;
    }
  }

  @JsonProperty("name")
  public String getName() {
    return name;
  }

  @JsonProperty("entry_point")
  public String getEntryPoint() {
    return entryPoint;
  }

  @JsonProperty("signature")
  public String getSignature() {
    return signature;
  }

  @JsonProperty("calling_convention")
  public String getCallingConvention() {
    return callingConvention;
  }

  @JsonProperty("namespace")
  public String getNamespace() {
    return namespace;
  }

  @JsonProperty("start_address")
  public String getStartAddress() {
    return startAddress;
  }

  @JsonProperty("end_address")
  public String getEndAddress() {
    return endAddress;
  }
}
