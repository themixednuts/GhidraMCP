package com.themixednuts.models;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;

/** Utility class to hold relevant information about a Ghidra Symbol for JSON serialization. */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class SymbolInfo {

  private final String name;
  private final String addr;
  private final String type;
  private final String src;
  private final String ns;
  private final boolean primary;
  private final boolean global;
  private final boolean external;

  public SymbolInfo(Symbol symbol) {
    this.name = symbol.getName();

    Address symAddr = symbol.getAddress();
    this.addr = (symAddr != null) ? symAddr.toString() : null;

    SymbolType symType = symbol.getSymbolType();
    this.type = (symType != null) ? symType.toString() : null;

    SourceType srcType = symbol.getSource();
    this.src = (srcType != null) ? srcType.toString() : null;

    Namespace parentNs = symbol.getParentNamespace();
    this.ns = (parentNs != null) ? parentNs.getName(true) : null;

    this.primary = symbol.isPrimary();
    this.global = symbol.isGlobal();
    this.external = symbol.isExternal();
  }

  @JsonProperty("name")
  public String getName() {
    return name;
  }

  @JsonProperty("addr")
  public String getAddr() {
    return addr;
  }

  @JsonProperty("type")
  public String getType() {
    return type;
  }

  @JsonProperty("src")
  public String getSrc() {
    return src;
  }

  @JsonProperty("ns")
  public String getNs() {
    return ns;
  }

  @JsonProperty("primary")
  public boolean isPrimary() {
    return primary;
  }

  @JsonProperty("global")
  public boolean isGlobal() {
    return global;
  }

  @JsonProperty("external")
  public boolean isExternal() {
    return external;
  }
}
