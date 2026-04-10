package com.themixednuts.utils.jsonschema.draft7;

import com.themixednuts.utils.jsonschema.JsonSchemaType;
import com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.INullSchemaBuilder;
import tools.jackson.databind.ObjectMapper;

/** Implementation of INullSchemaBuilder for building null-type schemas. */
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
