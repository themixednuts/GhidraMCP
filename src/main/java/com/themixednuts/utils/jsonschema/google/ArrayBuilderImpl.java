package com.themixednuts.utils.jsonschema.google;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.themixednuts.utils.jsonschema.IBuildableSchemaType;
import com.themixednuts.utils.jsonschema.JsonSchemaType;
import com.themixednuts.utils.jsonschema.google.SchemaBuilder.IArraySchemaBuilder;

import java.util.Objects;

/**
 * Implementation of IArraySchemaBuilder for building array-type schemas per
 * Google AI API.
 */
final class ArrayBuilderImpl extends AbstractSchemaBuilderImpl<IArraySchemaBuilder>
        implements IArraySchemaBuilder {

    private static final String MIN_ITEMS = "minItems";
    private static final String MAX_ITEMS = "maxItems";
    private static final String ITEMS = "items";

    ArrayBuilderImpl(ObjectMapper mapper) {
        super(JsonSchemaType.ARRAY, mapper);
    }

    @Override
    protected IArraySchemaBuilder self() {
        return this;
    }

    // Array-specific validation
    @Override
    public IArraySchemaBuilder minItems(int minItems) {
        if (minItems < 0) {
            throw new IllegalArgumentException("minItems cannot be negative: " + minItems);
        }
        // Per Google AI API spec: minItems is "string (int64 format)"
        schema.put(MIN_ITEMS, String.valueOf(minItems));
        return this;
    }

    @Override
    public IArraySchemaBuilder maxItems(int maxItems) {
        if (maxItems < 0) {
            throw new IllegalArgumentException("maxItems cannot be negative: " + maxItems);
        }
        // Per Google AI API spec: maxItems is "string (int64 format)"
        schema.put(MAX_ITEMS, String.valueOf(maxItems));
        return this;
    }

    @Override
    public IArraySchemaBuilder items(ObjectNode itemSchema) {
        Objects.requireNonNull(itemSchema, "Item schema cannot be null for array type");
        schema.set(ITEMS, itemSchema);
        return this;
    }

    @Override
    public IArraySchemaBuilder items(IBuildableSchemaType itemSchemaBuilder) {
        Objects.requireNonNull(itemSchemaBuilder, "Item schema builder cannot be null");
        return items(itemSchemaBuilder.build().getNode());
    }
}
