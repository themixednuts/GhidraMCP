package com.themixednuts.models;

import ghidra.program.model.data.DataTypeComponent;

/**
 * POJO representing information about a member within a Union.
 */
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

	public String getName() {
		return name;
	}

	public String getDataTypePath() {
		return dataTypePath;
	}

	public int getLength() {
		return length;
	}

	public String getComment() {
		return comment;
	}
}