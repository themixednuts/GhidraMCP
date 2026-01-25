package com.themixednuts.models;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import ghidra.app.util.NamespaceUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;

/** Utility class to hold relevant information about a Ghidra Symbol for JSON serialization. */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class SymbolInfo {

  private final String name;
  private final String qualifiedName;
  private final String address;
  private final String symbolType;
  private final String sourceType;
  private final String namespace;
  private final boolean isPrimary;
  private final boolean isGlobal;
  private final boolean isExternal;

  public SymbolInfo(Symbol symbol) {
    this.name = symbol.getName();

    Address symAddr = symbol.getAddress();
    this.address = (symAddr != null) ? symAddr.toString() : null;

    SymbolType symType = symbol.getSymbolType();
    this.symbolType = (symType != null) ? symType.toString() : null;

    SourceType srcType = symbol.getSource();
    this.sourceType = (srcType != null) ? srcType.toString() : null;

    Namespace parentNs = symbol.getParentNamespace();
    this.namespace = (parentNs != null) ? parentNs.getName(true) : null;

    // Get fully qualified name using NamespaceUtils
    this.qualifiedName =
        (parentNs != null)
            ? NamespaceUtils.getNamespaceQualifiedName(parentNs, symbol.getName(), false)
            : symbol.getName();

    this.isPrimary = symbol.isPrimary();
    this.isGlobal = symbol.isGlobal();
    this.isExternal = symbol.isExternal();
  }

  @JsonProperty("name")
  public String getName() {
    return name;
  }

  @JsonProperty("qualified_name")
  public String getQualifiedName() {
    return qualifiedName;
  }

  @JsonProperty("address")
  public String getAddress() {
    return address;
  }

  @JsonProperty("symbol_type")
  public String getSymbolType() {
    return symbolType;
  }

  @JsonProperty("source_type")
  public String getSourceType() {
    return sourceType;
  }

  @JsonProperty("namespace")
  public String getNamespace() {
    return namespace;
  }

  @JsonProperty("is_primary")
  public boolean isPrimary() {
    return isPrimary;
  }

  @JsonProperty("is_global")
  public boolean isGlobal() {
    return isGlobal;
  }

  @JsonProperty("is_external")
  public boolean isExternal() {
    return isExternal;
  }
}
