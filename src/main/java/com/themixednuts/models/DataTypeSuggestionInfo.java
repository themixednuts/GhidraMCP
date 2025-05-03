package com.themixednuts.models;

import com.fasterxml.jackson.annotation.JsonProperty;
import ghidra.program.model.data.DataType;

/**
 * POJO representing basic information about a suggested DataType.
 * Used when a requested data type is not found.
 */
public class DataTypeSuggestionInfo {

	@JsonProperty("name")
	private final String name;
	@JsonProperty("path")
	private final String path;
	@JsonProperty("category")
	private final String category;
	@JsonProperty("length")
	private final int length;

	public DataTypeSuggestionInfo(DataType dataType) {
		this.name = dataType.getName();
		this.path = dataType.getPathName();
		this.category = dataType.getCategoryPath().getPath();
		this.length = dataType.getLength();
		// Add other relevant fields if needed
	}

	// Getters (optional, but good practice if needed elsewhere)
	public String getName() {
		return name;
	}

	public String getPath() {
		return path;
	}

	public String getCategory() {
		return category;
	}

	public int getLength() {
		return length;
	}
}