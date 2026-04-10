package com.themixednuts.utils.jsonschema.draft7;

import com.themixednuts.utils.jsonschema.JsonSchemaType;
import com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.IBooleanSchemaBuilder;
import tools.jackson.databind.ObjectMapper;

/** Implementation of IBooleanSchemaBuilder for building boolean-type schemas. */
final class BooleanBuilderImpl extends AbstractSchemaBuilderImpl<IBooleanSchemaBuilder>
    implements IBooleanSchemaBuilder {

  BooleanBuilderImpl(ObjectMapper mapper) {
    super(JsonSchemaType.BOOLEAN, mapper);
  }

  @Override
  protected IBooleanSchemaBuilder self() {
    return this;
  }

  // Boolean-specific validation
  @Override
  public IBooleanSchemaBuilder constValue(boolean value) {
    schema.put(CONST, value);
    return this;
  }
}
