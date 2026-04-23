package com.themixednuts.models;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.symbol.Symbol;

/**
 * Compact variable targeting information for decompiler-backed function variables.
 *
 * <p>This model intentionally mirrors the identifier needed by functions.update_variable /
 * functions.rename_variable rather than echoing the full listing/decompiler variable state.
 */
@JsonPropertyOrder({"name", "variable_symbol_id", "data_type", "storage", "is_parameter"})
@JsonInclude(JsonInclude.Include.NON_NULL)
public final class FunctionVariableInfo {

  private final String name;
  private final Long variableSymbolId;
  private final String dataType;
  private final String storage;
  private final Boolean isParameter;

  public FunctionVariableInfo(Variable variable, Long variableSymbolId) {
    this(variable, variableSymbolId, true);
  }

  public FunctionVariableInfo(Variable variable, Long variableSymbolId, boolean includeMetadata) {
    String rawName = variable.getName();
    this.name = rawName == null || rawName.isBlank() ? "<unnamed_variable>" : rawName;
    Symbol symbol = variable.getSymbol();
    this.variableSymbolId =
        variableSymbolId != null ? variableSymbolId : symbol != null ? symbol.getID() : null;
    this.dataType =
        includeMetadata && variable.getDataType() != null
            ? variable.getDataType().getDisplayName()
            : null;
    this.storage =
        includeMetadata && variable.getVariableStorage() != null
            ? variable.getVariableStorage().toString()
            : null;
    this.isParameter = includeMetadata ? variable instanceof Parameter : null;
  }

  public FunctionVariableInfo(HighSymbol highSymbol) {
    this(highSymbol, true);
  }

  public FunctionVariableInfo(HighSymbol highSymbol, boolean includeMetadata) {
    HighVariable highVariable = highSymbol.getHighVariable();
    String rawName =
        highVariable != null && highVariable.getName() != null && !highVariable.getName().isBlank()
            ? highVariable.getName()
            : highSymbol.getName();
    this.name = rawName == null || rawName.isBlank() ? "<unnamed_variable>" : rawName;
    this.variableSymbolId = highSymbol.getId();
    this.dataType =
        includeMetadata && highVariable != null && highVariable.getDataType() != null
            ? highVariable.getDataType().getDisplayName()
            : includeMetadata && highSymbol.getDataType() != null
                ? highSymbol.getDataType().getDisplayName()
                : null;
    this.storage =
        includeMetadata && highVariable != null && highVariable.getRepresentative() != null
            ? highVariable.getRepresentative().toString()
            : includeMetadata && highSymbol.getStorage() != null
                ? highSymbol.getStorage().toString()
                : null;
    this.isParameter = includeMetadata ? highSymbol.isParameter() : null;
  }

  @JsonProperty("name")
  public String getName() {
    return name;
  }

  @JsonProperty("variable_symbol_id")
  @JsonFormat(shape = JsonFormat.Shape.STRING)
  public Long getVariableSymbolId() {
    return variableSymbolId;
  }

  @JsonProperty("data_type")
  public String getDataType() {
    return dataType;
  }

  @JsonProperty("storage")
  public String getStorage() {
    return storage;
  }

  @JsonProperty("is_parameter")
  public Boolean getIsParameter() {
    return isParameter;
  }

  @JsonIgnore
  public boolean isParameter() {
    return Boolean.TRUE.equals(isParameter);
  }

  @JsonIgnore
  public String getEffectiveName() {
    return name;
  }

  @JsonIgnore
  public Long getSymbolId() {
    return variableSymbolId;
  }

  @JsonIgnore
  public Long getHighSymbolId() {
    return variableSymbolId;
  }
}
