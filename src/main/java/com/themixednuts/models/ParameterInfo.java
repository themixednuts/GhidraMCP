package com.themixednuts.models;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Model representing a single parameter within a Function Definition.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ParameterInfo {

	private final String name;
	private final String dataTypePath;
	private final String comment;
	private final int length;

	public ParameterInfo(String name, String dataTypePath, String comment, int length) {
		this.name = name;
		this.dataTypePath = dataTypePath;
		this.comment = comment;
		this.length = length;
	}

	@JsonProperty("name")
	public String getName() {
		return name;
	}

	@JsonProperty("data_type_path")
	public String getDataTypePath() {
		return dataTypePath;
	}

	@JsonProperty("comment")
	public String getComment() {
		return comment;
	}

	@JsonProperty("length")
	public int getLength() {
		return length;
	}
}
