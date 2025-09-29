package com.themixednuts.utils.jsonschema;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Defines standard format identifiers for STRING type JSON Schemas,
 * based on OpenAPI/JSON Schema standards.
 */
public enum StringFormatType {
	@JsonProperty("date-time")
	DATE_TIME("date-time"),
	@JsonProperty("email")
	EMAIL("email"),
	@JsonProperty("uuid")
	UUID("uuid"),
	@JsonProperty("uri")
	URI("uri"),
	@JsonProperty("byte")
	BYTE("byte");

	private final String value;

	StringFormatType(String value) {
		this.value = value;
	}

	@Override
	public String toString() {
		return value;
	}
}