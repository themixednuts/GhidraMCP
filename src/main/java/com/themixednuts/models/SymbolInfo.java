package com.themixednuts.models;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import ghidra.program.model.symbol.SourceType;

/**
 * Utility class to hold relevant information about a Ghidra Symbol for JSON
 * serialization.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class SymbolInfo {

	@JsonProperty("name")
	private final String name;

	@JsonProperty("address")
	private final String address;

	@JsonProperty("symbol_type")
	private final String symbolType;

	@JsonProperty("source_type")
	private final String sourceType;

	@JsonProperty("namespace")
	private final String namespace;

	@JsonProperty("is_primary")
	private final boolean isPrimary;

	@JsonProperty("is_global")
	private final boolean isGlobal;

	@JsonProperty("is_external")
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

		this.isPrimary = symbol.isPrimary();
		this.isGlobal = symbol.isGlobal();
		this.isExternal = symbol.isExternal();
	}

	// Getters
	public String getName() {
		return name;
	}

	public String getAddress() {
		return address;
	}

	public String getSymbolType() {
		return symbolType;
	}

	public String getSourceType() {
		return sourceType;
	}

	public String getNamespace() {
		return namespace;
	}

	public boolean isPrimary() {
		return isPrimary;
	}

	public boolean isGlobal() {
		return isGlobal;
	}

	public boolean isExternal() {
		return isExternal;
	}
}