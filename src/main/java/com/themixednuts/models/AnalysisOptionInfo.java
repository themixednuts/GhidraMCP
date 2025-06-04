package com.themixednuts.models;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class AnalysisOptionInfo {
	private final String name;
	private final String description;
	private final String optionType;
	private final String value;

	public AnalysisOptionInfo(String name, String description, String optionType, String value) {
		this.name = name;
		this.description = description;
		this.optionType = optionType;
		this.value = value;
	}

	@JsonProperty("name")
	public String getName() {
		return name;
	}

	@JsonProperty("description")
	public String getDescription() {
		return description;
	}

	@JsonProperty("option_type")
	public String getOptionType() {
		return optionType;
	}

	@JsonProperty("value")
	public String getValue() {
		return value;
	}
}