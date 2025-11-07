package com.themixednuts.utils.jsonschema.google;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.themixednuts.utils.jsonschema.JsonSchemaType;
import com.themixednuts.utils.jsonschema.google.SchemaBuilder.INullSchemaBuilder;

/**
 * Implementation of INullSchemaBuilder for building null-type schemas per
 * Google AI API.
 */
final class NullBuilderImpl extends AbstractSchemaBuilderImpl<INullSchemaBuilder>
        implements INullSchemaBuilder {

    NullBuilderImpl(ObjectMapper mapper) {
        super(JsonSchemaType.NULL, mapper);
    }

    @Override
    protected INullSchemaBuilder self() {
        return this;
    }

    // Null type has no specific validation methods beyond common metadata
}
