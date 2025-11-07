package com.themixednuts.utils.jsonschema.draft7;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.themixednuts.utils.jsonschema.JsonSchemaType;
import com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.IIntegerSchemaBuilder;

import java.util.List;
import java.util.Objects;

/**
 * Implementation of IIntegerSchemaBuilder for building integer-type schemas.
 */
final class IntegerBuilderImpl extends AbstractSchemaBuilderImpl<IIntegerSchemaBuilder>
        implements IIntegerSchemaBuilder {

    private static final String MINIMUM = "minimum";
    private static final String MAXIMUM = "maximum";
    private static final String EXCLUSIVE_MINIMUM = "exclusiveMinimum";
    private static final String EXCLUSIVE_MAXIMUM = "exclusiveMaximum";
    private static final String MULTIPLE_OF = "multipleOf";

    IntegerBuilderImpl(ObjectMapper mapper) {
        super(JsonSchemaType.INTEGER, mapper);
    }

    @Override
    protected IIntegerSchemaBuilder self() {
        return this;
    }

    // Integer-specific validation
    @Override
    public IIntegerSchemaBuilder constValue(long value) {
        schema.put(CONST, value);
        return this;
    }

    @Override
    public IIntegerSchemaBuilder constValue(int value) {
        return constValue((long) value);
    }

    @Override
    public IIntegerSchemaBuilder minimum(long minimum) {
        schema.put(MINIMUM, minimum);
        return this;
    }

    @Override
    public IIntegerSchemaBuilder maximum(long maximum) {
        schema.put(MAXIMUM, maximum);
        return this;
    }

    @Override
    public IIntegerSchemaBuilder minimum(int minimum) {
        return minimum((long) minimum);
    }

    @Override
    public IIntegerSchemaBuilder maximum(int maximum) {
        return maximum((long) maximum);
    }

    @Override
    public IIntegerSchemaBuilder exclusiveMinimum(long exclusiveMinimum) {
        schema.put(EXCLUSIVE_MINIMUM, exclusiveMinimum);
        return this;
    }

    @Override
    public IIntegerSchemaBuilder exclusiveMaximum(long exclusiveMaximum) {
        schema.put(EXCLUSIVE_MAXIMUM, exclusiveMaximum);
        return this;
    }

    @Override
    public IIntegerSchemaBuilder exclusiveMinimum(int exclusiveMinimum) {
        return exclusiveMinimum((long) exclusiveMinimum);
    }

    @Override
    public IIntegerSchemaBuilder exclusiveMaximum(int exclusiveMaximum) {
        return exclusiveMaximum((long) exclusiveMaximum);
    }

    @Override
    public IIntegerSchemaBuilder multipleOf(long multipleOf) {
        if (multipleOf <= 0) {
            throw new IllegalArgumentException("multipleOf must be greater than 0, got: " + multipleOf);
        }
        schema.put(MULTIPLE_OF, multipleOf);
        return this;
    }

    @Override
    public IIntegerSchemaBuilder multipleOf(int multipleOf) {
        return multipleOf((long) multipleOf);
    }

    @Override
    public IIntegerSchemaBuilder enumValues(List<?> values) {
        Objects.requireNonNull(values, "Enum values list cannot be null");
        if (values.isEmpty()) {
            throw new IllegalArgumentException("Enum values list cannot be empty");
        }
        ArrayNode enumNode = schema.putArray(ENUM);
        values.forEach(v -> enumNode.add(toJsonNode(v)));
        return this;
    }

    @Override
    public IIntegerSchemaBuilder enumValues(Object... values) {
        Objects.requireNonNull(values, "Enum values array cannot be null");
        if (values.length == 0) {
            throw new IllegalArgumentException("Enum values array cannot be empty");
        }
        ArrayNode enumNode = schema.putArray(ENUM);
        for (Object value : values) {
            enumNode.add(toJsonNode(value));
        }
        return this;
    }
}
