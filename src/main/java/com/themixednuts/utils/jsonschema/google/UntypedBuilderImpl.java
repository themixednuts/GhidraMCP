package com.themixednuts.utils.jsonschema.google;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.themixednuts.utils.jsonschema.IBuildableSchemaType;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.google.traits.IAnyOf;
import com.themixednuts.utils.jsonschema.google.traits.ICommonMetadata;
import com.themixednuts.utils.jsonschema.google.traits.IGoogleSpecific;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * Builder for Google AI API schemas WITHOUT a base type constraint.
 * Used for anyOf schemas where the type is determined solely by the union.
 * 
 * <p>
 * Note: Google AI API only supports anyOf (not allOf/oneOf/not per the spec).
 * </p>
 * 
 * <p>Example: Union of different types</p>
 * <pre>{@code
 * // Schema that accepts either a string OR an integer
 * JsonSchema schema = SchemaBuilder.anyOf(
 *     SchemaBuilder.string().minLength(10),
 *     SchemaBuilder.integer().minimum(0)
 * ).build();
 * }</pre>
 */
final class UntypedBuilderImpl implements
        IBuildableSchemaType,
        ICommonMetadata<UntypedBuilderImpl>,
        IGoogleSpecific<UntypedBuilderImpl>,
        IAnyOf<UntypedBuilderImpl> {

    private final ObjectNode schema;
    private final ObjectMapper mapper;

    // JSON Schema keyword constants
    private static final String TITLE = "title";
    private static final String DESCRIPTION = "description";
    private static final String DEFAULT = "default";
    private static final String NULLABLE = "nullable";
    private static final String EXAMPLE = "example";
    private static final String ANY_OF = "anyOf";

    UntypedBuilderImpl(ObjectMapper mapper) {
        this.mapper = Objects.requireNonNull(mapper, "ObjectMapper cannot be null");
        this.schema = mapper.createObjectNode();
        // Intentionally NO "type" field
    }

    @Override
    public JsonSchema build() {
        return new JsonSchema(schema.deepCopy());
    }

    // ========== Common Metadata ==========

    @Override
    public UntypedBuilderImpl title(String title) {
        schema.put(TITLE, title);
        return this;
    }

    @Override
    public UntypedBuilderImpl description(String description) {
        schema.put(DESCRIPTION, description);
        return this;
    }

    @Override
    public UntypedBuilderImpl defaultValue(Object value) {
        schema.set(DEFAULT, mapper.valueToTree(value));
        return this;
    }

    // ========== Google-Specific ==========

    @Override
    public UntypedBuilderImpl nullable(boolean nullable) {
        schema.put(NULLABLE, nullable);
        return this;
    }

    @Override
    public UntypedBuilderImpl example(Object value) {
        schema.set(EXAMPLE, mapper.valueToTree(value));
        return this;
    }

    // ========== AnyOf (only composition keyword in Google spec) ==========

    @Override
    public UntypedBuilderImpl anyOf(IBuildableSchemaType... schemas) {
        Objects.requireNonNull(schemas, "anyOf schemas array cannot be null");
        ObjectNode[] builtSchemas = Arrays.stream(schemas)
                .map(s -> {
                    Objects.requireNonNull(s, "Schema in anyOf array cannot be null");
                    return s.build().getNode();
                })
                .toArray(ObjectNode[]::new);
        return anyOf(builtSchemas);
    }

    @Override
    public UntypedBuilderImpl anyOf(ObjectNode... schemas) {
        Objects.requireNonNull(schemas, "anyOf schemas array cannot be null");
        if (schemas.length == 0) {
            throw new IllegalArgumentException("anyOf array cannot be empty");
        }
        var anyOfNode = schema.putArray(ANY_OF);
        for (ObjectNode schemaNode : schemas) {
            Objects.requireNonNull(schemaNode, "Schema in anyOf array cannot be null");
            anyOfNode.add(schemaNode);
        }
        return this;
    }

    @Override
    public UntypedBuilderImpl anyOf(List<? extends IBuildableSchemaType> schemas) {
        Objects.requireNonNull(schemas, "anyOf schemas list cannot be null");
        if (schemas.isEmpty()) {
            throw new IllegalArgumentException("anyOf list cannot be empty");
        }
        return anyOf(schemas.toArray(new IBuildableSchemaType[0]));
    }
}

