package com.themixednuts.utils.jsonschema.draft7;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.themixednuts.utils.jsonschema.JsonSchemaType;
import com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.INumberSchemaBuilder;
import java.math.BigDecimal;
import java.util.List;
import java.util.Objects;

/** Implementation of INumberSchemaBuilder for building number-type schemas. */
final class NumberBuilderImpl extends AbstractSchemaBuilderImpl<INumberSchemaBuilder>
    implements INumberSchemaBuilder {

  private static final String MINIMUM = "minimum";
  private static final String MAXIMUM = "maximum";
  private static final String EXCLUSIVE_MINIMUM = "exclusiveMinimum";
  private static final String EXCLUSIVE_MAXIMUM = "exclusiveMaximum";
  private static final String MULTIPLE_OF = "multipleOf";

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
  public INumberSchemaBuilder constValue(BigDecimal value) {
    schema.put(CONST, Objects.requireNonNull(value, "Const value cannot be null"));
    return this;
  }

  @Override
  public INumberSchemaBuilder constValue(double value) {
    return constValue(BigDecimal.valueOf(value));
  }

  @Override
  public INumberSchemaBuilder constValue(float value) {
    return constValue(BigDecimal.valueOf(value));
  }

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

  @Override
  public INumberSchemaBuilder exclusiveMinimum(BigDecimal exclusiveMinimum) {
    schema.put(
        EXCLUSIVE_MINIMUM,
        Objects.requireNonNull(exclusiveMinimum, "Exclusive minimum cannot be null"));
    return this;
  }

  @Override
  public INumberSchemaBuilder exclusiveMaximum(BigDecimal exclusiveMaximum) {
    schema.put(
        EXCLUSIVE_MAXIMUM,
        Objects.requireNonNull(exclusiveMaximum, "Exclusive maximum cannot be null"));
    return this;
  }

  @Override
  public INumberSchemaBuilder exclusiveMinimum(double exclusiveMinimum) {
    return exclusiveMinimum(BigDecimal.valueOf(exclusiveMinimum));
  }

  @Override
  public INumberSchemaBuilder exclusiveMaximum(double exclusiveMaximum) {
    return exclusiveMaximum(BigDecimal.valueOf(exclusiveMaximum));
  }

  @Override
  public INumberSchemaBuilder exclusiveMinimum(float exclusiveMinimum) {
    return exclusiveMinimum(BigDecimal.valueOf(exclusiveMinimum));
  }

  @Override
  public INumberSchemaBuilder exclusiveMaximum(float exclusiveMaximum) {
    return exclusiveMaximum(BigDecimal.valueOf(exclusiveMaximum));
  }

  @Override
  public INumberSchemaBuilder multipleOf(BigDecimal multipleOf) {
    Objects.requireNonNull(multipleOf, "multipleOf cannot be null");
    if (multipleOf.compareTo(BigDecimal.ZERO) <= 0) {
      throw new IllegalArgumentException("multipleOf must be greater than 0, got: " + multipleOf);
    }
    schema.put(MULTIPLE_OF, multipleOf);
    return this;
  }

  @Override
  public INumberSchemaBuilder multipleOf(double multipleOf) {
    return multipleOf(BigDecimal.valueOf(multipleOf));
  }

  @Override
  public INumberSchemaBuilder multipleOf(float multipleOf) {
    return multipleOf(BigDecimal.valueOf(multipleOf));
  }

  @Override
  public INumberSchemaBuilder enumValues(List<?> values) {
    Objects.requireNonNull(values, "Enum values list cannot be null");
    if (values.isEmpty()) {
      throw new IllegalArgumentException("Enum values list cannot be empty");
    }
    ArrayNode enumNode = schema.putArray(ENUM);
    values.forEach(v -> enumNode.add(toJsonNode(v)));
    return this;
  }

  @Override
  public INumberSchemaBuilder enumValues(Object... values) {
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
