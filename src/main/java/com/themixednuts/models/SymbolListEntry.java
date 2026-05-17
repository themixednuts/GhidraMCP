package com.themixednuts.models;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;

/** Compact symbol row for list responses. Detailed metadata is available via symbols.get. */
@JsonInclude(JsonInclude.Include.NON_NULL)
public final class SymbolListEntry {
  private final long symbolId;
  private final String name;
  private final String address;
  private final String type;
  private final String namespace;

  public SymbolListEntry(Symbol symbol) {
    this.symbolId = symbol.getID();
    this.name = symbol.getName();
    this.address = formatMemoryAddress(symbol.getAddress());

    SymbolType symbolType = symbol.getSymbolType();
    this.type = symbolType != null ? symbolType.toString() : null;

    Namespace parentNamespace = symbol.getParentNamespace();
    this.namespace =
        parentNamespace != null && !parentNamespace.isGlobal()
            ? parentNamespace.getName(true)
            : null;
  }

  @JsonProperty("symbol_id")
  public long getSymbolId() {
    return symbolId;
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

  @JsonProperty("namespace")
  public String getNamespace() {
    return namespace;
  }

  private static String formatMemoryAddress(Address address) {
    return address != null && address.isMemoryAddress() ? address.toString() : null;
  }
}
