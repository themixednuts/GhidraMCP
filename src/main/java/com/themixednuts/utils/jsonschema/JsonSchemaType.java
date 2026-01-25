package com.themixednuts.utils.jsonschema;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Represents the valid data types for a JSON Schema according to the OpenAPI 3.0.3 specification,
 * as referenced by the Google AI API documentation.
 *
 * @see <a href="https://spec.openapis.org/oas/v3.0.3#data-types">OpenAPI 3.0.3 Data Types</a>
 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema</a>
 */
public enum JsonSchemaType {
  @JsonProperty("string")
  STRING("string"),
  @JsonProperty("number")
  NUMBER("number"),
  @JsonProperty("integer")
  INTEGER("integer"),
  @JsonProperty("boolean")
  BOOLEAN("boolean"),
  @JsonProperty("array")
  ARRAY("array"),
  @JsonProperty("object")
  OBJECT("object"),
  @JsonProperty("null")
  NULL("null");
  // TYPE_UNSPECIFIED from Google's internal enum is omitted as it shouldn't be
  // used directly in a built schema.

  private final String value;

  JsonSchemaType(String value) {
    this.value = value;
  }

  /**
   * Returns the string representation of the schema type as expected in the JSON schema.
   *
   * @return The JSON schema type string.
   */
  @Override
  public String toString() {
    return value;
  }
}
