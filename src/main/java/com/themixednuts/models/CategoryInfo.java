package com.themixednuts.models;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * POJO representing basic information about a Data Type Category.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CategoryInfo {
	public final String path;

	@JsonCreator
	public CategoryInfo(@JsonProperty("path") String path) {
		this.path = path;
	}

	@JsonProperty("path")
	public String getPath() {
		return path;
	}
}