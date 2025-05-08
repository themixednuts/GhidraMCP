package com.themixednuts.models;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Model representing a single entry (name-value pair) within an Enum.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class EnumEntryInfo {

	@JsonProperty("name")
	private final String name;

	@JsonProperty("value")
	private final long value;

	public EnumEntryInfo(String name, long value) {
		this.name = name;
		this.value = value;
	}

	// Getters
	public String getName() {
		return name;
	}

	public long getValue() {
		return value;
	}
}
