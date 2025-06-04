package com.themixednuts.models;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Model representing a single entry (name-value pair) within an Enum.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class EnumEntryInfo {

	private final String name;
	private final long value;

	public EnumEntryInfo(String name, long value) {
		this.name = name;
		this.value = value;
	}

	@JsonProperty("name")
	public String getName() {
		return name;
	}

	@JsonProperty("value")
	public long getValue() {
		return value;
	}
}
