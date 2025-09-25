package com.themixednuts.models;

import java.util.Optional;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.TypeDef;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class TypedefDetails extends BaseDataTypeDetails {

	private final String baseDataTypePath;
	private final boolean isAutoNamed;

	public TypedefDetails(TypeDef typedefDt) {
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

	@JsonProperty("base_data_type_path")
	public String getBaseDataTypePath() {
		return baseDataTypePath;
	}

	@JsonProperty("is_auto_named")
	public boolean isAutoNamed() {
		return isAutoNamed;
	}
}
