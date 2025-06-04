package com.themixednuts.models;

import java.util.Optional;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.themixednuts.tools.datatypes.DataTypeKind;
import ghidra.program.model.data.DataType;

/**
 * Model representing details for other non-specifically-handled data types.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class OtherDataTypeDetails extends BaseDataTypeDetails {

	private final String dataTypeClassName;

	public OtherDataTypeDetails(DataType dt) {
		super(
				DataTypeKind.OTHER, // Updated to OTHER
				dt.getPathName(),
				dt.getName(),
				dt.getCategoryPath().getPath(),
				dt.getLength(),
				dt.getAlignment(),
				Optional.ofNullable(dt.getDescription()).orElse(""));
		this.dataTypeClassName = dt.getClass().getSimpleName();
	}

	@JsonProperty("data_type_class_name")
	public String getDataTypeClassName() {
		return dataTypeClassName;
	}
}
