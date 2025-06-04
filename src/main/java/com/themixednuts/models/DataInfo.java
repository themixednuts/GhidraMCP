package com.themixednuts.models;

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
public class DataInfo {

	private final String label;
	private final String address;
	private final String valueRepresentation;
	private final String dataTypeName;
	private final int length;

	public DataInfo(Data data) {
		this.label = data.getLabel(); // Can be null
		Address dataAddr = data.getAddress();
		this.address = (dataAddr != null) ? dataAddr.toString() : null;
		this.valueRepresentation = data.getDefaultValueRepresentation(); // Or another representation if needed
		DataType dt = data.getDataType();
		this.dataTypeName = (dt != null) ? dt.getDisplayName() : null;
		this.length = data.getLength();
	}

	@JsonProperty("label")
	public String getLabel() {
		return label;
	}

	@JsonProperty("address")
	public String getAddress() {
		return address;
	}

	@JsonProperty("value")
	public String getValueRepresentation() {
		return valueRepresentation;
	}

	@JsonProperty("data_type")
	public String getDataTypeName() {
		return dataTypeName;
	}

	@JsonProperty("length")
	public int getLength() {
		return length;
	}
}