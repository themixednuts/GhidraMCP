package com.themixednuts.models;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import ghidra.program.model.data.DataTypeComponent;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class UnionMemberInfo {
	public String name;
	public String dataTypePath;
	public int length;
	public String comment;

	// Default constructor for deserialization if needed
	public UnionMemberInfo() {
	}

	public UnionMemberInfo(DataTypeComponent component) {
		this.name = component.getFieldName(); // Use getFieldName() which can be null
		this.dataTypePath = component.getDataType().getPathName();
		this.length = component.getLength();
		this.comment = component.getComment();
	}

	// --- Getters (optional but good practice) ---

	@JsonProperty("name")
	public String getName() {
		return name;
	}

	@JsonProperty("data_type_path")
	public String getDataTypePath() {
		return dataTypePath;
	}

	@JsonProperty("length")
	public int getLength() {
		return length;
	}

	@JsonProperty("comment")
	public String getComment() {
		return comment;
	}
}