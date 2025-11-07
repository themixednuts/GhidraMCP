package com.themixednuts.utils.jsonschema.draft7.traits;

import com.themixednuts.utils.jsonschema.IBuildableSchemaType;
import java.util.List;

/**
 * Capability interface for composition keywords (allOf, oneOf, not).
 * Draft 7 allows these on any schema type for combining and modifying schemas.
 *
 * <p>
 * This interface follows the trait/capability pattern, allowing type-safe
 * method
 * chaining with the concrete builder type.
 * </p>
 *
 * <h3>Composition Keywords:</h3>
 * <ul>
 * <li><b>allOf</b>: Schema must match ALL provided schemas
 * (intersection/composition)</li>
 * <li><b>oneOf</b>: Schema must match EXACTLY ONE of the provided schemas
 * (discriminated union)</li>
 * <li><b>not</b>: Schema must NOT match the provided schema (negation)</li>
 * </ul>
 *
 * @param <SELF> The concrete builder type for method chaining
 * @see <a href=
 *      "https://json-schema.org/draft-07/json-schema-validation.html#rfc.section.6.7">Draft
 *      7 Composition</a>
 */
public interface IComposition<SELF> {

    /**
     * Adds allOf constraint - schema must validate against ALL provided schemas.
     *
     * @param schemas Varargs of schemas that must all match
     * @return This builder instance for chaining
     */
    SELF allOf(IBuildableSchemaType... schemas);

    /**
     * Adds allOf constraint - schema must validate against ALL provided schemas.
     *
     * @param schemas List of schemas that must all match
     * @return This builder instance for chaining
     */
    SELF allOf(List<? extends IBuildableSchemaType> schemas);

    /**
     * Adds oneOf constraint - schema must validate against EXACTLY ONE of the
     * provided schemas.
     *
     * @param schemas Varargs of schemas where exactly one must match
     * @return This builder instance for chaining
     */
    SELF oneOf(IBuildableSchemaType... schemas);

    /**
     * Adds oneOf constraint - schema must validate against EXACTLY ONE of the
     * provided schemas.
     *
     * @param schemas List of schemas where exactly one must match
     * @return This builder instance for chaining
     */
    SELF oneOf(List<? extends IBuildableSchemaType> schemas);

    /**
     * Adds not constraint - schema must NOT validate against the provided schema.
     *
     * @param schema Schema that must NOT match
     * @return This builder instance for chaining
     */
    SELF not(IBuildableSchemaType schema);
}
