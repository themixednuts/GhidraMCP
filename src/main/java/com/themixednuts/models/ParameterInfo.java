package com.themixednuts.models;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Model representing a single parameter within a Function Definition.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ParameterInfo {

	@JsonProperty("name")
	private final String name;

	@JsonProperty("data_type_path")
	private final String dataTypePath;

	@JsonProperty("comment")
	private final String comment;

	@JsonProperty("length")
	private final int length;

	public ParameterInfo(String name, String dataTypePath, String comment, int length) {
		this.name = name;
		this.dataTypePath = dataTypePath;
		this.comment = comment;
		this.length = length;
	}

	// Getters
	public String getName() {
		return name;
	}

	public String getDataTypePath() {
		return dataTypePath;
	}

	public String getComment() {
		return comment;
	}

	public int getLength() {
		return length;
	}
}
