package com.themixednuts.utils.jsonschema.google;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * OpenAPI 3.0.3 / Google AI API string format types.
 * 
 * @see <a href="https://spec.openapis.org/oas/v3.0.3#data-types">OpenAPI 3.0.3
 *      Data Types</a>
 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API
 *      Schema</a>
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
