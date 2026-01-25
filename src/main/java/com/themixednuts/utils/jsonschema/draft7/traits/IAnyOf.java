package com.themixednuts.utils.jsonschema.draft7.traits;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.themixednuts.utils.jsonschema.IBuildableSchemaType;
import java.util.List;

/**
 * Capability interface for anyOf keyword. All schema types support anyOf - the schema must validate
 * against ANY (one or more) of the provided schemas.
 *
 * <p>This interface follows the trait/capability pattern, allowing type-safe method chaining with
 * the concrete builder type.
 *
 * <h3>Usage Example:</h3>
 *
 * <pre>{@code
 * SchemaBuilder.string()
 *         .anyOf(
 *                 SchemaBuilder.string().minLength(5),
 *                 SchemaBuilder.string().pattern("^[A-Z]"))
 * }</pre>
 *
 * @param <SELF> The concrete builder type for method chaining
 * @see <a href=
 *     "https://json-schema.org/draft-07/json-schema-validation.html#rfc.section.6.7.3">Draft 7
 *     anyOf</a>
 */
public interface IAnyOf<SELF> {

  /**
   * Adds anyOf constraint - schema must validate against ANY (one or more) of the provided schemas.
   *
   * @param schemas Varargs of schemas where at least one must match
   * @return This builder instance for chaining
   */
  SELF anyOf(IBuildableSchemaType... schemas);

  /**
   * Adds anyOf constraint using pre-built schema nodes.
   *
   * @param schemas Varargs of ObjectNode schemas where at least one must match
   * @return This builder instance for chaining
   */
  SELF anyOf(ObjectNode... schemas);

  /**
   * Adds anyOf constraint - schema must validate against ANY (one or more) of the provided schemas.
   *
   * @param schemas List of schemas where at least one must match
   * @return This builder instance for chaining
   */
  SELF anyOf(List<? extends IBuildableSchemaType> schemas);
}
