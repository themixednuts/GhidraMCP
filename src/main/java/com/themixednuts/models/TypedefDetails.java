package com.themixednuts.models;

import java.util.Optional;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.themixednuts.tools.datatypes.DataTypeKind;
import ghidra.program.model.data.DataType; // For baseDt
import ghidra.program.model.data.TypeDef; // Added

/**
 * Model representing the detailed definition of a Typedef data type.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class TypedefDetails extends BaseDataTypeDetails {

	@JsonProperty("base_data_type_path")
	private final String baseDataTypePath;

	@JsonProperty("is_auto_named")
	private final boolean isAutoNamed;

	public TypedefDetails(TypeDef typedefDt) { // Constructor takes Ghidra TypeDef object
		super(
				DataTypeKind.TYPEDEF,
				typedefDt.getPathName(),
				typedefDt.getName(),
				typedefDt.getCategoryPath().getPath(),
				typedefDt.getLength(),
				typedefDt.getAlignment(),
				Optional.ofNullable(typedefDt.getDescription()).orElse(""));
		DataType baseDt = typedefDt.getBaseDataType();
		this.baseDataTypePath = (baseDt != null) ? baseDt.getPathName() : null;
		this.isAutoNamed = typedefDt.isAutoNamed();
	}

	// Getters
	public String getBaseDataTypePath() {
		return baseDataTypePath;
	}

	public boolean isAutoNamed() {
		return isAutoNamed;
	}
}
