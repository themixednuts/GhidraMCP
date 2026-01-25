package com.themixednuts.utils.jsonschema.google.traits;

/**
 * Capability interface for common metadata fields (title, description, default). All schema types
 * support these fields according to Google AI API Schema specification.
 *
 * <p>This interface follows the trait/capability pattern, allowing type-safe method chaining with
 * the concrete builder type.
 *
 * @param <SELF> The concrete builder type for method chaining
 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema</a>
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
   * Sets the description of the schema. This could contain examples of use. Parameter description
   * may be formatted as Markdown.
   *
   * @param description A longer explanation of the schema's purpose
   * @return This builder instance for chaining
   */
  SELF description(String description);

  /**
   * Sets the default value for the schema. Per JSON Schema, this field is intended for
   * documentation generators and doesn't affect validation.
   *
   * @param value The default value (can be any JSON-compatible type)
   * @return This builder instance for chaining
   */
  SELF defaultValue(Object value);
}
