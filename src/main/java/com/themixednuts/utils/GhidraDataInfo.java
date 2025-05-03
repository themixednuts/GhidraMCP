package com.themixednuts.utils;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.address.Address;

/**
 * Utility class to hold relevant information about a Ghidra Data item for JSON
 * serialization.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class GhidraDataInfo {

	@JsonProperty("label")
	private final String label;

	@JsonProperty("address")
	private final String address;

	@JsonProperty("value")
	private final String valueRepresentation;

	@JsonProperty("data_type")
	private final String dataTypeName;

	@JsonProperty("length")
	private final int length;

	public GhidraDataInfo(Data data) {
		this.label = data.getLabel(); // Can be null
		Address dataAddr = data.getAddress();
		this.address = (dataAddr != null) ? dataAddr.toString() : null;
		this.valueRepresentation = data.getDefaultValueRepresentation(); // Or another representation if needed
		DataType dt = data.getDataType();
		this.dataTypeName = (dt != null) ? dt.getDisplayName() : null;
		this.length = data.getLength();
	}

	// Getters
	public String getLabel() {
		return label;
	}

	public String getAddress() {
		return address;
	}

	public String getValueRepresentation() {
		return valueRepresentation;
	}

	public String getDataTypeName() {
		return dataTypeName;
	}

	public int getLength() {
		return length;
	}
}