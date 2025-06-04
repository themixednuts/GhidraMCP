package com.themixednuts.models;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonInclude;
import ghidra.program.model.data.DataType;

/**
 * POJO representing basic information about a suggested DataType.
 * Used when a requested data type is not found.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class DataTypeSuggestionInfo {

	private final String name;
	private final String path;
	private final String category;
	private final int length;

	public DataTypeSuggestionInfo(DataType dataType) {
		this.name = dataType.getName();
		this.path = dataType.getPathName();
		this.category = dataType.getCategoryPath().getPath();
		this.length = dataType.getLength();
		// Add other relevant fields if needed
	}

	@JsonProperty("name")
	public String getName() {
		return name;
	}

	@JsonProperty("path")
	public String getPath() {
		return path;
	}

	@JsonProperty("category")
	public String getCategory() {
		return category;
	}

	@JsonProperty("length")
	public int getLength() {
		return length;
	}
}