package com.themixednuts.utils.jsonschema;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
// import ghidra.util.Msg; // Removed Ghidra dependency

import java.util.Optional;
// import java.util.logging.Level; // Removed logging dependency
// import java.util.logging.Logger; // Removed logging dependency

/**
 * An immutable representation of a JSON Schema, built using
 * {@link JsonSchemaBuilder}.
 * Provides methods to access the underlying schema node and serialize it to a
 * JSON string.
 */
public final class JsonSchema {

	// Add a logger instance
	// private static final Logger LOGGER =
	// Logger.getLogger(JsonSchema.class.getName()); // Removed logger

	private final ObjectNode schemaNode;

	/**
	 * Package-private constructor to be called by {@link JsonSchemaBuilder}.
	 * Creates an immutable instance by deep copying the provided node.
	 *
	 * @param schemaNode The schema node constructed by the builder. Must not be
	 *                   null.
	 */
	JsonSchema(ObjectNode schemaNode) {
		if (schemaNode == null) {
			this.schemaNode = JsonSchemaBuilder.DEFAULT_MAPPER.createObjectNode();
		} else {
			this.schemaNode = schemaNode.deepCopy();
		}
	}

	JsonSchema() {
		this.schemaNode = JsonSchemaBuilder.DEFAULT_MAPPER.createObjectNode();
	}

	/**
	 * Returns a deep copy of the underlying JSON schema {@link ObjectNode}.
	 * Modifications to the returned node will not affect this {@code JsonSchema}
	 * instance.
	 *
	 * @return A non-null, deep copy of the schema node.
	 */
	public ObjectNode getNode() {
		// Return a deep copy to maintain immutability of the internal node
		return schemaNode.deepCopy();
	}

	/**
	 * Serializes the JSON schema to a string representation using the provided
	 * {@link ObjectMapper}.
	 *
	 * @param mapper The ObjectMapper to use for serialization. Must not be null.
	 * @return An {@link Optional} containing the JSON string if serialization is
	 *         successful,
	 *         otherwise {@link Optional#empty()}.
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
	 * Serializes the JSON schema to a string representation using the default
	 * {@link ObjectMapper}
	 * defined in {@link JsonSchemaBuilder}.
	 * <p>
	 * Note: This uses the static default mapper, which might not have the same
	 * configuration
	 * as a custom mapper potentially used during the build process for
	 * default/example values.
	 * For serialization controlled by the consumer (recommended), use
	 * {@link #toJsonString(ObjectMapper)}.
	 *
	 * @return An {@link Optional} containing the JSON string if serialization is
	 *         successful,
	 *         otherwise {@link Optional#empty()}.
	 */
	public Optional<String> toJsonString() {
		// Use the default mapper from JsonSchemaBuilder (assuming package-private
		// access or make it accessible)
		return toJsonString(JsonSchemaBuilder.DEFAULT_MAPPER);
	}

	@Override
	public String toString() {
		// Provide a basic string representation, might be the JSON itself or a summary
		return toJsonString().orElse("JsonSchema{ serialization_error }");
	}

	@Override
	public boolean equals(Object o) {
		if (this == o)
			return true;
		if (o == null || getClass() != o.getClass())
			return false;
		JsonSchema that = (JsonSchema) o;
		// Equality based on the content of the schema node
		return schemaNode.equals(that.schemaNode);
	}

	@Override
	public int hashCode() {
		// Hash code based on the content of the schema node
		return schemaNode.hashCode();
	}
}