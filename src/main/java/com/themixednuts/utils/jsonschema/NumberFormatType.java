package com.themixednuts.utils.jsonschema;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Defines standard format identifiers for NUMBER type JSON Schemas.
 */
public enum NumberFormatType {
	@JsonProperty("float")
	FLOAT("float"),
	@JsonProperty("double")
	DOUBLE("double");

	private final String value;

	NumberFormatType(String value) {
		this.value = value;
	}

	@Override
	public String toString() {
		return value;
	}
}