package com.themixednuts.utils.jsonschema;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Represents common integer formats used in JSON Schema (subset relevant to
 * OpenAPI 3.0.3 / Google AI).
 */
public enum IntegerFormatType {
	@JsonProperty("int32")
	INT32("int32"),
	@JsonProperty("int64")
	INT64("int64");

	private final String value;

	IntegerFormatType(String value) {
		this.value = value;
	}

	@Override
	public String toString() {
		return value;
	}
}