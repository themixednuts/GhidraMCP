package com.themixednuts.utils;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Defines standard format identifiers for STRING type JSON Schemas,
 * based on OpenAPI/JSON Schema standards.
 * Note: The Google AI spec mentions 'enum' as a format, which seems incorrect
 * based on standard JSON Schema; 'enum' is a keyword, not a format.
 * Common formats like date-time, email, etc., are included here.
 */
public enum StringFormatType {
	@JsonProperty("date-time")
	DATE_TIME("date-time"), // RFC3339 Section 5.6
	// DATE("date"), // Consider adding if needed
	// TIME("time"), // Consider adding if needed
	@JsonProperty("email")
	EMAIL("email"), // RFC5322 Section 3.4.1
	// IDN_EMAIL("idn-email"), // Consider adding if needed
	// HOSTNAME("hostname"), // Consider adding if needed
	// IDN_HOSTNAME("idn-hostname"), // Consider adding if needed
	// IPV4("ipv4"), // Consider adding if needed
	// IPV6("ipv6"), // Consider adding if needed
	@JsonProperty("uuid")
	UUID("uuid"), // RFC4122
	@JsonProperty("uri")
	URI("uri"), // RFC3986
	// URI_REFERENCE("uri-reference"), // Consider adding if needed
	// IRI("iri"), // Consider adding if needed
	// IRI_REFERENCE("iri-reference"), // Consider adding if needed
	@JsonProperty("byte")
	BYTE("byte"); // Base64 encoding
	// PASSWORD("password"), // Consider adding if needed (often just hints UI)

	private final String value;

	StringFormatType(String value) {
		this.value = value;
	}

	@Override
	public String toString() {
		return value;
	}
}