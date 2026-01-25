package com.themixednuts.utils.jsonschema;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.Optional;

/**
 * An immutable representation of a JSON Schema, built using schema builders. Provides methods to
 * access the underlying schema node and serialize it to a JSON string.
 */
public final class JsonSchema {

  private static final ObjectMapper DEFAULT_MAPPER = new ObjectMapper();
  private final ObjectNode schemaNode;

  /**
   * Public constructor for use by schema builders in different packages. Creates an instance by
   * directly using the provided node for maximum efficiency.
   *
   * @param schemaNode The schema node constructed by the builder. Must not be null.
   */
  public JsonSchema(ObjectNode schemaNode) {
    this.schemaNode = schemaNode != null ? schemaNode : DEFAULT_MAPPER.createObjectNode();
  }

  public JsonSchema() {
    this.schemaNode = DEFAULT_MAPPER.createObjectNode();
  }

  /**
   * Returns the underlying JSON schema {@link ObjectNode}. For maximum efficiency, this returns the
   * actual node without copying. Modifications to the returned node will affect this {@code
   * JsonSchema} instance.
   *
   * @return The underlying schema node.
   */
  public ObjectNode getNode() {
    return schemaNode;
  }

  /**
   * Serializes the JSON schema to a string representation using the provided {@link ObjectMapper}.
   *
   * @param mapper The ObjectMapper to use for serialization. Must not be null.
   * @return An {@link Optional} containing the JSON string if serialization is successful,
   *     otherwise {@link Optional#empty()}.
   */
  public Optional<String> toJsonString(ObjectMapper mapper) {
    if (mapper == null) {
      return Optional.empty();
    }

    try {
      return Optional.of(mapper.writeValueAsString(this.schemaNode));
    } catch (Throwable e) {
      return Optional.empty();
    }
  }

  /**
   * Serializes the JSON schema to a string representation using the default {@link ObjectMapper}.
   *
   * @return An {@link Optional} containing the JSON string if serialization is successful,
   *     otherwise {@link Optional#empty()}.
   */
  public Optional<String> toJsonString() {
    return toJsonString(DEFAULT_MAPPER);
  }

  @Override
  public String toString() {
    return toJsonString().orElse("JsonSchema{ serialization_error }");
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    JsonSchema that = (JsonSchema) o;
    return schemaNode.equals(that.schemaNode);
  }

  @Override
  public int hashCode() {
    return schemaNode.hashCode();
  }
}
