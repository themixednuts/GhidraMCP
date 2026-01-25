package com.themixednuts.utils.jsonschema.google;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.themixednuts.utils.jsonschema.IBuildableSchemaType;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaType;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * Abstract base class for all Google AI API schema builder implementations. Provides shared
 * implementation logic for common metadata, Google-specific fields, and anyOf operations.
 *
 * @param <SELF> The concrete builder type for method chaining
 */
abstract class AbstractSchemaBuilderImpl<SELF> {

  protected final ObjectNode schema;
  protected final ObjectMapper mapper;
  protected final JsonSchemaType type;

  // JSON Schema keyword constants (Google AI API subset)
  protected static final String TYPE = "type";
  protected static final String FORMAT = "format";
  protected static final String TITLE = "title";
  protected static final String DESCRIPTION = "description";
  protected static final String NULLABLE = "nullable";
  protected static final String DEFAULT = "default";
  protected static final String EXAMPLE = "example";
  protected static final String ENUM = "enum";
  protected static final String ANY_OF = "anyOf";

  protected AbstractSchemaBuilderImpl(JsonSchemaType type, ObjectMapper mapper) {
    this.mapper = Objects.requireNonNull(mapper, "ObjectMapper cannot be null");
    this.schema = mapper.createObjectNode();
    this.type = Objects.requireNonNull(type, "Schema type cannot be null");
    this.schema.put(TYPE, type.toString());
  }

  /**
   * Returns this instance cast to the concrete builder type. Subclasses must override this to
   * return the correct type.
   */
  protected abstract SELF self();

  // ========== Common Metadata Methods ==========

  public SELF title(String title) {
    schema.put(TITLE, title);
    return self();
  }

  public SELF description(String description) {
    schema.put(DESCRIPTION, description);
    return self();
  }

  public SELF defaultValue(Object value) {
    schema.set(DEFAULT, toJsonNode(value));
    return self();
  }

  // ========== Google-Specific Methods ==========

  public SELF nullable(boolean nullable) {
    schema.put(NULLABLE, nullable);
    return self();
  }

  public SELF example(Object example) {
    schema.set(EXAMPLE, toJsonNode(example));
    return self();
  }

  // ========== Format Method ==========
  // Note: Implemented here but only exposed on types that support it (String,
  // Number, Integer)

  protected SELF format(String format) {
    schema.put(FORMAT, format);
    return self();
  }

  // ========== AnyOf Methods ==========

  public SELF anyOf(IBuildableSchemaType... schemas) {
    Objects.requireNonNull(schemas, "anyOf schemas array cannot be null");
    ObjectNode[] builtSchemas =
        Arrays.stream(schemas)
            .map(
                s -> {
                  Objects.requireNonNull(s, "Schema in anyOf array cannot be null");
                  return s.build().getNode();
                })
            .toArray(ObjectNode[]::new);
    return anyOf(builtSchemas);
  }

  public SELF anyOf(ObjectNode... schemas) {
    Objects.requireNonNull(schemas, "anyOf schemas array cannot be null");
    if (schemas.length == 0) {
      throw new IllegalArgumentException("anyOf array cannot be empty");
    }
    ArrayNode anyOfNode = schema.putArray(ANY_OF);
    for (ObjectNode schemaNode : schemas) {
      Objects.requireNonNull(schemaNode, "Schema in anyOf array cannot be null");
      anyOfNode.add(schemaNode);
    }
    return self();
  }

  public SELF anyOf(List<? extends IBuildableSchemaType> schemas) {
    Objects.requireNonNull(schemas, "anyOf schemas list cannot be null");
    if (schemas.isEmpty()) {
      throw new IllegalArgumentException("anyOf list cannot be empty");
    }
    return anyOf(schemas.toArray(new IBuildableSchemaType[0]));
  }

  // ========== Helper Methods ==========

  protected JsonNode toJsonNode(Object value) {
    return mapper.valueToTree(value);
  }

  public JsonSchema build() {
    return new JsonSchema(schema);
  }
}
