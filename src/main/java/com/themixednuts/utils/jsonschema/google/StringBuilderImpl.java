package com.themixednuts.utils.jsonschema.google;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.themixednuts.utils.jsonschema.JsonSchemaType;
import com.themixednuts.utils.jsonschema.google.SchemaBuilder.IStringSchemaBuilder;
import java.util.List;
import java.util.Objects;

/** Implementation of IStringSchemaBuilder for building string-type schemas per Google AI API. */
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

  // String-specific overloads
  @Override
  public IStringSchemaBuilder defaultValue(String value) {
    return defaultValue((Object) value);
  }

  @Override
  public IStringSchemaBuilder example(String value) {
    return example((Object) value);
  }

  // String-specific validation
  @Override
  public IStringSchemaBuilder minLength(int minLength) {
    if (minLength < 0) {
      throw new IllegalArgumentException("minLength cannot be negative: " + minLength);
    }
    // Google API expects string representation of int64
    schema.put(MIN_LENGTH, String.valueOf(minLength));
    return this;
  }

  @Override
  public IStringSchemaBuilder maxLength(int maxLength) {
    if (maxLength < 0) {
      throw new IllegalArgumentException("maxLength cannot be negative: " + maxLength);
    }
    // Google API expects string representation of int64
    schema.put(MAX_LENGTH, String.valueOf(maxLength));
    return this;
  }

  @Override
  public IStringSchemaBuilder pattern(String pattern) {
    schema.put(PATTERN, Objects.requireNonNull(pattern, "Pattern cannot be null"));
    return this;
  }

  // Format methods
  @Override
  public IStringSchemaBuilder format(String format) {
    return super.format(format);
  }

  @Override
  public IStringSchemaBuilder format(StringFormatType formatType) {
    Objects.requireNonNull(formatType, "Format type cannot be null");
    return format(formatType.toString());
  }

  // String-specific enum methods (auto-set format:"enum" per Google spec)
  @Override
  public IStringSchemaBuilder enumValues(List<String> values) {
    Objects.requireNonNull(values, "Enum values list cannot be null");
    if (values.isEmpty()) {
      throw new IllegalArgumentException("Enum values list cannot be empty");
    }
    // Set format to "enum" as per Google AI API specification
    schema.put(FORMAT, "enum");
    ArrayNode enumNode = schema.putArray(ENUM);
    values.forEach(v -> enumNode.add(Objects.requireNonNull(v, "Enum value cannot be null")));
    return this;
  }

  @Override
  public IStringSchemaBuilder enumValues(String... values) {
    Objects.requireNonNull(values, "Enum values array cannot be null");
    if (values.length == 0) {
      throw new IllegalArgumentException("Enum values array cannot be empty");
    }
    // Set format to "enum" as per Google AI API specification
    schema.put(FORMAT, "enum");
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
      throw new IllegalArgumentException(
          enumClass.getName() + " is not an enum type or has no constants.");
    }
    if (constants.length == 0) {
      throw new IllegalArgumentException(enumClass.getName() + " has no enum constants.");
    }
    // Set format to "enum" as per Google AI API specification
    schema.put(FORMAT, "enum");
    ArrayNode enumNode = schema.putArray(ENUM);
    for (Enum<?> constant : constants) {
      enumNode.add(constant.name());
    }
    return this;
  }
}
