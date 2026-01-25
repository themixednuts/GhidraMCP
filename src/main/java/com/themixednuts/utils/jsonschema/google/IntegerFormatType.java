package com.themixednuts.utils.jsonschema.google;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * OpenAPI 3.0.3 integer format types used by Google AI API. JSON Schema Draft 7 does NOT use these
 * - it uses minimum/maximum instead.
 *
 * @see <a href="https://spec.openapis.org/oas/v3.0.3#data-types">OpenAPI 3.0.3 Data Types</a>
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
