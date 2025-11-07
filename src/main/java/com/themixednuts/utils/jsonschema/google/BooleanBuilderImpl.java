package com.themixednuts.utils.jsonschema.google;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.themixednuts.utils.jsonschema.JsonSchemaType;
import com.themixednuts.utils.jsonschema.google.SchemaBuilder.IBooleanSchemaBuilder;

/**
 * Implementation of IBooleanSchemaBuilder for building boolean-type schemas per
 * Google AI API.
 */
final class BooleanBuilderImpl extends AbstractSchemaBuilderImpl<IBooleanSchemaBuilder>
        implements IBooleanSchemaBuilder {

    BooleanBuilderImpl(ObjectMapper mapper) {
        super(JsonSchemaType.BOOLEAN, mapper);
    }

    @Override
    protected IBooleanSchemaBuilder self() {
        return this;
    }

    // Boolean type has no specific validation methods beyond common metadata and
    // nullable
}
