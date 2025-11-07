package com.themixednuts.utils.jsonschema.google.traits;

/**
 * Capability interface for Google AI API-specific schema fields (nullable, example).
 * These are OpenAPI/Google extensions not present in pure JSON Schema.
 *
 * <p>This interface follows the trait/capability pattern, allowing type-safe method
 * chaining with the concrete builder type.</p>
 *
 * @param <SELF> The concrete builder type for method chaining
 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema</a>
 */
public interface IGoogleSpecific<SELF> {

    /**
     * Specifies if this schema can be null.
     * This is an OpenAPI extension supported by Google AI API.
     *
     * @param nullable True if null is allowed, false otherwise
     * @return This builder instance for chaining
     */
    SELF nullable(boolean nullable);

    /**
     * Sets an example value for this schema.
     * According to Google spec: "Will only be populated when the object is the root."
     * However, this method is available on all builders for flexibility.
     *
     * @param example The example value (can be any JSON-compatible type)
     * @return This builder instance for chaining
     */
    SELF example(Object example);
}

