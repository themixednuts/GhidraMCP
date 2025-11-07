package com.themixednuts.utils.jsonschema;

/**
 * Base interface for any builder that can produce a JsonSchema.
 * Implemented by both Google AI and JSON Schema Draft 7 builders.
 */
public interface IBuildableSchemaType {
    /**
     * Builds and returns the final JsonSchema object.
     * 
     * @return The constructed JsonSchema
     */
    JsonSchema build();
}
