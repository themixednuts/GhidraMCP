package com.themixednuts.models;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * POJO representing basic information about a Data Type Category.
 */
public class CategoryInfo {
	@JsonProperty("path")
	public final String path;

	@JsonCreator // Needed for deserialization if used as input
	public CategoryInfo(@JsonProperty("path") String path) {
		this.path = path;
	}

	// Optional getter
	public String getPath() {
		return path;
	}
}