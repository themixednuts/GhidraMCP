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
  private final String address;
  private final String type;
  private final String source;
  private final String namespace;
  private final boolean primary;
  private final boolean global;
  private final boolean external;

  public SymbolInfo(Symbol symbol) {
    this.name = symbol.getName();

    Address symAddr = symbol.getAddress();
    this.address = (symAddr != null) ? symAddr.toString() : null;

    SymbolType symType = symbol.getSymbolType();
    this.type = (symType != null) ? symType.toString() : null;

    SourceType srcType = symbol.getSource();
    this.source = (srcType != null) ? srcType.toString() : null;

    Namespace parentNs = symbol.getParentNamespace();
    this.namespace = (parentNs != null) ? parentNs.getName(true) : null;

    this.primary = symbol.isPrimary();
    this.global = symbol.isGlobal();
    this.external = symbol.isExternal();
  }

  @JsonProperty("name")
  public String getName() {
    return name;
  }

  @JsonProperty("address")
  public String getAddress() {
    return address;
  }

  @JsonProperty("type")
  public String getType() {
    return type;
  }

  @JsonProperty("source")
  public String getSource() {
    return source;
  }

  @JsonProperty("namespace")
  public String getNamespace() {
    return namespace;
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
