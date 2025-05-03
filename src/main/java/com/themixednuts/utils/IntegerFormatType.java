package com.themixednuts.utils;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Defines standard format identifiers for INTEGER type JSON Schemas.
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