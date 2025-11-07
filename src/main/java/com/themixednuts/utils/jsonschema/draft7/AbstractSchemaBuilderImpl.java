package com.themixednuts.utils.jsonschema.draft7;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.themixednuts.utils.jsonschema.IBuildableSchemaType;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaType;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * Abstract base class for all schema builder implementations.
 * Provides shared implementation logic for common keywords and
 * composition/conditional operations.
 *
 * @param <SELF> The concrete builder type for method chaining
 */
abstract class AbstractSchemaBuilderImpl<SELF> {

    protected final ObjectNode schema;
    protected final ObjectMapper mapper;
    protected final JsonSchemaType type;

    // JSON Schema keyword constants
    protected static final String TYPE = "type";
    protected static final String TITLE = "title";
    protected static final String DESCRIPTION = "description";
    protected static final String DEFAULT = "default";
    protected static final String ENUM = "enum";
    protected static final String CONST = "const";
    protected static final String ALL_OF = "allOf";
    protected static final String ANY_OF = "anyOf";
    protected static final String ONE_OF = "oneOf";
    protected static final String NOT = "not";
    protected static final String IF = "if";
    protected static final String THEN = "then";
    protected static final String ELSE = "else";

    protected AbstractSchemaBuilderImpl(JsonSchemaType type, ObjectMapper mapper) {
        this.mapper = Objects.requireNonNull(mapper, "ObjectMapper cannot be null");
        this.schema = mapper.createObjectNode();
        this.type = Objects.requireNonNull(type, "Schema type cannot be null");
        this.schema.put(TYPE, type.toString());
    }

    /**
     * Returns this instance cast to the concrete builder type.
     * Subclasses should override this to return the correct type.
     */
    protected abstract SELF self();

    // ========== Common Metadata Methods ==========

    public SELF title(String title) {
        schema.put(TITLE, title);
        return self();
    }

    public SELF description(String description) {
        schema.put(DESCRIPTION, description);
        return self();
    }

    public SELF defaultValue(Object value) {
        schema.set(DEFAULT, toJsonNode(value));
        return self();
    }

    // ========== Composition Methods ==========

    public SELF allOf(IBuildableSchemaType... schemas) {
        Objects.requireNonNull(schemas, "allOf schemas array cannot be null");
        if (schemas.length == 0) {
            throw new IllegalArgumentException("allOf array cannot be empty");
        }

        ArrayNode allOfNode = schema.putArray(ALL_OF);
        for (IBuildableSchemaType schemaBuilder : schemas) {
            Objects.requireNonNull(schemaBuilder, "Schema in allOf array cannot be null");
            allOfNode.add(schemaBuilder.build().getNode());
        }

        return self();
    }

    public SELF allOf(List<? extends IBuildableSchemaType> schemas) {
        Objects.requireNonNull(schemas, "allOf schemas list cannot be null");
        if (schemas.isEmpty()) {
            throw new IllegalArgumentException("allOf list cannot be empty");
        }
        return allOf(schemas.toArray(new IBuildableSchemaType[0]));
    }

    public SELF oneOf(IBuildableSchemaType... schemas) {
        Objects.requireNonNull(schemas, "oneOf schemas array cannot be null");
        if (schemas.length == 0) {
            throw new IllegalArgumentException("oneOf array cannot be empty");
        }

        ArrayNode oneOfNode = schema.putArray(ONE_OF);
        for (IBuildableSchemaType schemaBuilder : schemas) {
            Objects.requireNonNull(schemaBuilder, "Schema in oneOf array cannot be null");
            oneOfNode.add(schemaBuilder.build().getNode());
        }

        return self();
    }

    public SELF oneOf(List<? extends IBuildableSchemaType> schemas) {
        Objects.requireNonNull(schemas, "oneOf schemas list cannot be null");
        if (schemas.isEmpty()) {
            throw new IllegalArgumentException("oneOf list cannot be empty");
        }
        return oneOf(schemas.toArray(new IBuildableSchemaType[0]));
    }

    public SELF not(IBuildableSchemaType notSchema) {
        Objects.requireNonNull(notSchema, "not schema cannot be null");
        schema.set(NOT, notSchema.build().getNode());
        return self();
    }

    // ========== Conditional Methods ==========

    public SELF ifThen(IBuildableSchemaType ifSchema, IBuildableSchemaType thenSchema) {
        Objects.requireNonNull(ifSchema, "if schema cannot be null");
        Objects.requireNonNull(thenSchema, "then schema cannot be null");

        schema.set(IF, ifSchema.build().getNode());
        schema.set(THEN, thenSchema.build().getNode());

        return self();
    }

    public SELF ifThenElse(IBuildableSchemaType ifSchema, IBuildableSchemaType thenSchema,
            IBuildableSchemaType elseSchema) {
        Objects.requireNonNull(ifSchema, "if schema cannot be null");
        Objects.requireNonNull(thenSchema, "then schema cannot be null");
        Objects.requireNonNull(elseSchema, "else schema cannot be null");

        schema.set(IF, ifSchema.build().getNode());
        schema.set(THEN, thenSchema.build().getNode());
        schema.set(ELSE, elseSchema.build().getNode());

        return self();
    }

    // ========== AnyOf Methods ==========

    public SELF anyOf(IBuildableSchemaType... schemas) {
        Objects.requireNonNull(schemas, "anyOf schemas array cannot be null");
        ObjectNode[] builtSchemas = Arrays.stream(schemas)
                .map(s -> {
                    Objects.requireNonNull(s, "Schema in anyOf array cannot be null");
                    return s.build().getNode();
                })
                .toArray(ObjectNode[]::new);
        return anyOf(builtSchemas);
    }

    public SELF anyOf(ObjectNode... schemas) {
        Objects.requireNonNull(schemas, "anyOf schemas array cannot be null");
        if (schemas.length == 0) {
            throw new IllegalArgumentException("anyOf array cannot be empty");
        }
        ArrayNode anyOfNode = schema.putArray(ANY_OF);
        for (ObjectNode schemaNode : schemas) {
            Objects.requireNonNull(schemaNode, "Schema in anyOf array cannot be null");
            anyOfNode.add(schemaNode);
        }
        return self();
    }

    public SELF anyOf(List<? extends IBuildableSchemaType> schemas) {
        Objects.requireNonNull(schemas, "anyOf schemas list cannot be null");
        if (schemas.isEmpty()) {
            throw new IllegalArgumentException("anyOf list cannot be empty");
        }
        return anyOf(schemas.toArray(new IBuildableSchemaType[0]));
    }

    // ========== Helper Methods ==========

    protected JsonNode toJsonNode(Object value) {
        return mapper.valueToTree(value);
    }

    public JsonSchema build() {
        return new JsonSchema(schema);
    }
}
