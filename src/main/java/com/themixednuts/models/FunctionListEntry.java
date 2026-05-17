package com.themixednuts.models;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;

/** Compact function row for list responses. Detailed metadata is available via functions.get. */
@JsonInclude(JsonInclude.Include.NON_NULL)
public final class FunctionListEntry {
  private final Long symbolId;
  private final String name;
  private final String entryPoint;
  private final String signature;
  private final String namespace;

  public FunctionListEntry(Function function) {
    Symbol symbol = function.getSymbol();
    this.symbolId = symbol != null ? symbol.getID() : null;
    this.name = function.getName();
    this.entryPoint = function.getEntryPoint() != null ? function.getEntryPoint().toString() : null;
    this.signature = function.getSignature(true).getPrototypeString();

    Namespace parentNamespace = function.getParentNamespace();
    this.namespace =
        parentNamespace != null && !parentNamespace.isGlobal()
            ? parentNamespace.getName(true)
            : null;
  }

  @JsonProperty("symbol_id")
  public Long getSymbolId() {
    return symbolId;
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

  @JsonProperty("namespace")
  public String getNamespace() {
    return namespace;
  }
}
