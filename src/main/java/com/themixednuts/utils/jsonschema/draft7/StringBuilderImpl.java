package com.themixednuts.utils.jsonschema.draft7;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.themixednuts.utils.jsonschema.JsonSchemaType;
import com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.IStringSchemaBuilder;

import java.util.List;
import java.util.Objects;

/**
 * Implementation of IStringSchemaBuilder for building string-type schemas.
 */
final class StringBuilderImpl extends AbstractSchemaBuilderImpl<IStringSchemaBuilder>
        implements IStringSchemaBuilder {

    private static final String MIN_LENGTH = "minLength";
    private static final String MAX_LENGTH = "maxLength";
    private static final String PATTERN = "pattern";

    StringBuilderImpl(ObjectMapper mapper) {
        super(JsonSchemaType.STRING, mapper);
    }

    @Override
    protected IStringSchemaBuilder self() {
        return this;
    }

    // String-specific overload for defaultValue
    @Override
    public IStringSchemaBuilder defaultValue(String value) {
        return defaultValue((Object) value);
    }

    // String-specific validation
    @Override
    public IStringSchemaBuilder constValue(String value) {
        schema.put(CONST, Objects.requireNonNull(value, "Const value cannot be null"));
        return this;
    }

    @Override
    public IStringSchemaBuilder minLength(int minLength) {
        if (minLength < 0) {
            throw new IllegalArgumentException("minLength cannot be negative: " + minLength);
        }
        schema.put(MIN_LENGTH, minLength);
        return this;
    }

    @Override
    public IStringSchemaBuilder maxLength(int maxLength) {
        if (maxLength < 0) {
            throw new IllegalArgumentException("maxLength cannot be negative: " + maxLength);
        }
        schema.put(MAX_LENGTH, maxLength);
        return this;
    }

    @Override
    public IStringSchemaBuilder pattern(String pattern) {
        schema.put(PATTERN, Objects.requireNonNull(pattern, "Pattern cannot be null"));
        return this;
    }

    // String-specific enum methods
    @Override
    public IStringSchemaBuilder enumValues(List<?> values) {
        Objects.requireNonNull(values, "Enum values list cannot be null");
        if (values.isEmpty()) {
            throw new IllegalArgumentException("Enum values list cannot be empty");
        }
        ArrayNode enumNode = schema.putArray(ENUM);
        values.forEach(v -> enumNode.add(toJsonNode(Objects.requireNonNull(v, "Enum value cannot be null"))));
        return this;
    }

    @Override
    public IStringSchemaBuilder enumValues(String... values) {
        Objects.requireNonNull(values, "Enum values array cannot be null");
        if (values.length == 0) {
            throw new IllegalArgumentException("Enum values array cannot be empty");
        }
        ArrayNode enumNode = schema.putArray(ENUM);
        for (String value : values) {
            enumNode.add(Objects.requireNonNull(value, "Enum value cannot be null"));
        }
        return this;
    }

    @Override
    public IStringSchemaBuilder enumValues(Class<? extends Enum<?>> enumClass) {
        Objects.requireNonNull(enumClass, "Enum class cannot be null");
        Enum<?>[] constants = enumClass.getEnumConstants();
        if (constants == null) {
            throw new IllegalArgumentException(enumClass.getName() + " is not an enum type or has no constants.");
        }
        if (constants.length == 0) {
            throw new IllegalArgumentException(enumClass.getName() + " has no enum constants.");
        }
        ArrayNode enumNode = schema.putArray(ENUM);
        for (Enum<?> constant : constants) {
            enumNode.add(constant.name());
        }
        return this;
    }

    @Override
    public IStringSchemaBuilder enumValues(Object... values) {
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
