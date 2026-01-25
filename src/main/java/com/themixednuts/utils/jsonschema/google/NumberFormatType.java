package com.themixednuts.utils.jsonschema.google;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * OpenAPI 3.0.3 number format types used by Google AI API. JSON Schema Draft 7 does NOT use these.
 *
 * @see <a href="https://spec.openapis.org/oas/v3.0.3#data-types">OpenAPI 3.0.3 Data Types</a>
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
