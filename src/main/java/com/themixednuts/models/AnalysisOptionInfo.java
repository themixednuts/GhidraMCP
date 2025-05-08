package com.themixednuts.models;

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

	public String getName() {
		return name;
	}

	public String getDescription() {
		return description;
	}

	public String getOptionType() {
		return optionType;
	}

	public String getValue() {
		return value;
	}
}