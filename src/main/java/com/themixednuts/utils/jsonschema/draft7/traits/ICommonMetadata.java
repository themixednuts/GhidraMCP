package com.themixednuts.utils.jsonschema.draft7.traits;

/**
 * Capability interface for common metadata fields (title, description,
 * default).
 * All schema types support these fields according to JSON Schema Draft 7
 * specification.
 *
 * <p>
 * This interface follows the trait/capability pattern, allowing type-safe
 * method
 * chaining with the concrete builder type.
 * </p>
 *
 * @param <SELF> The concrete builder type for method chaining
 * @see <a href=
 *      "https://json-schema.org/draft-07/json-schema-validation.html#rfc.section.10">Draft
 *      7 Metadata</a>
 */
public interface ICommonMetadata<SELF> {

    /**
     * Sets the title of the schema.
     *
     * @param title A short description of the schema's purpose
     * @return This builder instance for chaining
     */
    SELF title(String title);

    /**
     * Sets the description of the schema.
     *
     * @param description A longer explanation of the schema's purpose
     * @return This builder instance for chaining
     */
    SELF description(String description);

    /**
     * Sets the default value for the schema.
     *
     * @param value The default value (can be any JSON-compatible type)
     * @return This builder instance for chaining
     */
    SELF defaultValue(Object value);
}
