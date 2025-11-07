package com.themixednuts.utils.jsonschema.google;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.themixednuts.utils.jsonschema.JsonSchemaType;
import com.themixednuts.utils.jsonschema.google.SchemaBuilder.INumberSchemaBuilder;

import java.math.BigDecimal;
import java.util.Objects;

/**
 * Implementation of INumberSchemaBuilder for building number-type schemas per
 * Google AI API.
 */
final class NumberBuilderImpl extends AbstractSchemaBuilderImpl<INumberSchemaBuilder>
        implements INumberSchemaBuilder {

    private static final String MINIMUM = "minimum";
    private static final String MAXIMUM = "maximum";

    NumberBuilderImpl(ObjectMapper mapper) {
        super(JsonSchemaType.NUMBER, mapper);
    }

    @Override
    protected INumberSchemaBuilder self() {
        return this;
    }

    // Number-specific overload for defaultValue
    @Override
    public INumberSchemaBuilder defaultValue(Number value) {
        return defaultValue((Object) value);
    }

    // Number-specific validation
    @Override
    public INumberSchemaBuilder minimum(BigDecimal minimum) {
        schema.put(MINIMUM, Objects.requireNonNull(minimum, "Minimum cannot be null"));
        return this;
    }

    @Override
    public INumberSchemaBuilder maximum(BigDecimal maximum) {
        schema.put(MAXIMUM, Objects.requireNonNull(maximum, "Maximum cannot be null"));
        return this;
    }

    @Override
    public INumberSchemaBuilder minimum(double minimum) {
        return minimum(BigDecimal.valueOf(minimum));
    }

    @Override
    public INumberSchemaBuilder maximum(double maximum) {
        return maximum(BigDecimal.valueOf(maximum));
    }

    @Override
    public INumberSchemaBuilder minimum(float minimum) {
        return minimum(BigDecimal.valueOf(minimum));
    }

    @Override
    public INumberSchemaBuilder maximum(float maximum) {
        return maximum(BigDecimal.valueOf(maximum));
    }

    // Format methods
    @Override
    public INumberSchemaBuilder format(String format) {
        return super.format(format);
    }

    @Override
    public INumberSchemaBuilder format(NumberFormatType formatType) {
        Objects.requireNonNull(formatType, "Format type cannot be null");
        return format(formatType.toString());
    }
}
