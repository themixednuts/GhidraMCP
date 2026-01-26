package com.themixednuts.models;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Namespace;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class FunctionInfo {
  private final String name;
  private final String addr;
  private final String sig;
  private final String cc;
  private final String ns;
  private final String start;
  private final String end;

  public FunctionInfo(Function function) {
    this.name = function.getName();

    if (function.getEntryPoint() != null) {
      this.addr = function.getEntryPoint().toString();
    } else {
      this.addr = null;
    }

    this.sig = function.getSignature(true).getPrototypeString();
    this.cc = function.getCallingConventionName();

    Namespace parentNs = function.getParentNamespace();
    this.ns = (parentNs != null) ? parentNs.getName(true) : null;

    if (function.getBody() != null) {
      this.start =
          function.getBody().getMinAddress() != null
              ? function.getBody().getMinAddress().toString()
              : null;
      this.end =
          function.getBody().getMaxAddress() != null
              ? function.getBody().getMaxAddress().toString()
              : null;
    } else {
      this.start = null;
      this.end = null;
    }
  }

  @JsonProperty("name")
  public String getName() {
    return name;
  }

  @JsonProperty("addr")
  public String getAddress() {
    return addr;
  }

  @JsonProperty("sig")
  public String getSignature() {
    return sig;
  }

  @JsonProperty("cc")
  public String getCallingConvention() {
    return cc;
  }

  @JsonProperty("ns")
  public String getNamespace() {
    return ns;
  }

  @JsonProperty("start")
  public String getStart() {
    return start;
  }

  @JsonProperty("end")
  public String getEnd() {
    return end;
  }
}
