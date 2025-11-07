package com.themixednuts.utils.jsonschema.draft7.traits;

import com.themixednuts.utils.jsonschema.IBuildableSchemaType;

/**
 * Capability interface for conditional keywords (if/then/else).
 * Draft 7 allows these on any schema type for conditional validation.
 *
 * <p>
 * This interface follows the trait/capability pattern, allowing type-safe
 * method chaining with the concrete builder type.
 * </p>
 *
 * <h3>Usage Example:</h3>
 * 
 * <pre>{@code
 * SchemaBuilder.object()
 *         .property("type", SchemaBuilder.string())
 *         .ifThen(
 *                 SchemaBuilder.object().property("type", SchemaBuilder.string().constValue("admin")),
 *                 SchemaBuilder.object().requiredProperty("adminLevel"))
 * }</pre>
 *
 * @param <SELF> The concrete builder type for method chaining
 * @see <a href=
 *      "https://json-schema.org/draft-07/json-schema-validation.html#rfc.section.6.6">Draft
 *      7 Conditionals</a>
 */
public interface IConditionals<SELF> {

    /**
     * Adds conditional validation - if the "if" schema validates, then the "then"
     * schema must also validate.
     *
     * @param ifSchema   The condition schema
     * @param thenSchema The schema to apply if condition is true
     * @return This builder instance for chaining
     */
    SELF ifThen(IBuildableSchemaType ifSchema, IBuildableSchemaType thenSchema);

    /**
     * Adds conditional validation with else clause - if the "if" schema validates,
     * then the "then" schema must also validate, otherwise the "else" schema must
     * validate.
     *
     * @param ifSchema   The condition schema
     * @param thenSchema The schema to apply if condition is true
     * @param elseSchema The schema to apply if condition is false
     * @return This builder instance for chaining
     */
    SELF ifThenElse(IBuildableSchemaType ifSchema, IBuildableSchemaType thenSchema,
            IBuildableSchemaType elseSchema);
}
