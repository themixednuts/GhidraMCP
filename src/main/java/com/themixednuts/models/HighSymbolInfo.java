package com.themixednuts.models;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import ghidra.program.model.data.DataType;
import ghidra.program.model.pcode.HighSymbol;

/**
 * POJO for serializing basic information about a HighSymbol from the
 * decompiler.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class HighSymbolInfo {

	private final String name;
	private final String dataTypeName;

	// Consider adding other relevant HighSymbol fields if needed (e.g., size,
	// storage)
	// @JsonProperty("size")
	// private final int size;

	public HighSymbolInfo(HighSymbol highSymbol) {
		this.name = highSymbol.getName();

		DataType dt = highSymbol.getDataType();
		this.dataTypeName = (dt != null) ? dt.getDisplayName() : "<unknown>";

		// this.size = highSymbol.getSize();
	}

	@JsonProperty("name")
	public String getName() {
		return name;
	}

	@JsonProperty("data_type_name")
	public String getDataTypeName() {
		return dataTypeName;
	}

	// public int getSize() {
	// return size;
	// }
}