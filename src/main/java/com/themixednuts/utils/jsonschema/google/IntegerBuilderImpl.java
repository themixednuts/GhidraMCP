package com.themixednuts.utils.jsonschema.google;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.themixednuts.utils.jsonschema.JsonSchemaType;
import com.themixednuts.utils.jsonschema.google.SchemaBuilder.IIntegerSchemaBuilder;
import java.util.Objects;

/** Implementation of IIntegerSchemaBuilder for building integer-type schemas per Google AI API. */
final class IntegerBuilderImpl extends AbstractSchemaBuilderImpl<IIntegerSchemaBuilder>
    implements IIntegerSchemaBuilder {

  private static final String MINIMUM = "minimum";
  private static final String MAXIMUM = "maximum";

  IntegerBuilderImpl(ObjectMapper mapper) {
    super(JsonSchemaType.INTEGER, mapper);
  }

  @Override
  protected IIntegerSchemaBuilder self() {
    return this;
  }

  // Integer-specific validation
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

  // Format methods
  @Override
  public IIntegerSchemaBuilder format(String format) {
    return super.format(format);
  }

  @Override
  public IIntegerSchemaBuilder format(IntegerFormatType formatType) {
    Objects.requireNonNull(formatType, "Format type cannot be null");
    return format(formatType.toString());
  }
}
