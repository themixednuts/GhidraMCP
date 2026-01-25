package com.themixednuts.utils.jsonschema.draft7;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.themixednuts.utils.jsonschema.IBuildableSchemaType;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.draft7.traits.IAnyOf;
import com.themixednuts.utils.jsonschema.draft7.traits.ICommonMetadata;
import com.themixednuts.utils.jsonschema.draft7.traits.IComposition;
import com.themixednuts.utils.jsonschema.draft7.traits.IConditionals;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * Builder for schemas WITHOUT a base type constraint. Used for pure composition schemas (oneOf,
 * anyOf, allOf, not) where the type is determined solely by the composition keywords.
 *
 * <p>Example: Union of different types
 *
 * <pre>{@code
 * // Schema that accepts either a string OR an integer
 * JsonSchema schema = SchemaBuilder.oneOf(
 *         SchemaBuilder.string().minLength(10),
 *         SchemaBuilder.integer().minimum(0)).build();
 * }</pre>
 */
final class UntypedBuilderImpl
    implements IBuildableSchemaType,
        ICommonMetadata<UntypedBuilderImpl>,
        IComposition<UntypedBuilderImpl>,
        IConditionals<UntypedBuilderImpl>,
        IAnyOf<UntypedBuilderImpl> {

  private final ObjectNode schema;
  private final ObjectMapper mapper;

  // JSON Schema keyword constants
  private static final String TITLE = "title";
  private static final String DESCRIPTION = "description";
  private static final String DEFAULT = "default";
  private static final String ALL_OF = "allOf";
  private static final String ANY_OF = "anyOf";
  private static final String ONE_OF = "oneOf";
  private static final String NOT = "not";
  private static final String IF = "if";
  private static final String THEN = "then";
  private static final String ELSE = "else";

  UntypedBuilderImpl(ObjectMapper mapper) {
    this.mapper = Objects.requireNonNull(mapper, "ObjectMapper cannot be null");
    this.schema = mapper.createObjectNode();
    // Intentionally NO "type" field
  }

  @Override
  public JsonSchema build() {
    return new JsonSchema(schema.deepCopy());
  }

  // ========== Common Metadata ==========

  @Override
  public UntypedBuilderImpl title(String title) {
    schema.put(TITLE, title);
    return this;
  }

  @Override
  public UntypedBuilderImpl description(String description) {
    schema.put(DESCRIPTION, description);
    return this;
  }

  @Override
  public UntypedBuilderImpl defaultValue(Object value) {
    schema.set(DEFAULT, mapper.valueToTree(value));
    return this;
  }

  // ========== Composition ==========

  @Override
  public UntypedBuilderImpl allOf(IBuildableSchemaType... schemas) {
    Objects.requireNonNull(schemas, "allOf schemas array cannot be null");
    if (schemas.length == 0) {
      throw new IllegalArgumentException("allOf array cannot be empty");
    }
    var allOfNode = schema.putArray(ALL_OF);
    for (IBuildableSchemaType s : schemas) {
      Objects.requireNonNull(s, "Schema in allOf array cannot be null");
      allOfNode.add(s.build().getNode());
    }
    return this;
  }

  @Override
  public UntypedBuilderImpl allOf(List<? extends IBuildableSchemaType> schemas) {
    return allOf(schemas.toArray(new IBuildableSchemaType[0]));
  }

  @Override
  public UntypedBuilderImpl oneOf(IBuildableSchemaType... schemas) {
    Objects.requireNonNull(schemas, "oneOf schemas array cannot be null");
    if (schemas.length == 0) {
      throw new IllegalArgumentException("oneOf array cannot be empty");
    }
    var oneOfNode = schema.putArray(ONE_OF);
    for (IBuildableSchemaType s : schemas) {
      Objects.requireNonNull(s, "Schema in oneOf array cannot be null");
      oneOfNode.add(s.build().getNode());
    }
    return this;
  }

  @Override
  public UntypedBuilderImpl oneOf(List<? extends IBuildableSchemaType> schemas) {
    return oneOf(schemas.toArray(new IBuildableSchemaType[0]));
  }

  @Override
  public UntypedBuilderImpl not(IBuildableSchemaType notSchema) {
    Objects.requireNonNull(notSchema, "not schema cannot be null");
    schema.set(NOT, notSchema.build().getNode());
    return this;
  }

  // ========== Conditionals ==========

  @Override
  public UntypedBuilderImpl ifThen(IBuildableSchemaType ifSchema, IBuildableSchemaType thenSchema) {
    Objects.requireNonNull(ifSchema, "if schema cannot be null");
    Objects.requireNonNull(thenSchema, "then schema cannot be null");
    schema.set(IF, ifSchema.build().getNode());
    schema.set(THEN, thenSchema.build().getNode());
    return this;
  }

  @Override
  public UntypedBuilderImpl ifThenElse(
      IBuildableSchemaType ifSchema,
      IBuildableSchemaType thenSchema,
      IBuildableSchemaType elseSchema) {
    Objects.requireNonNull(ifSchema, "if schema cannot be null");
    Objects.requireNonNull(thenSchema, "then schema cannot be null");
    Objects.requireNonNull(elseSchema, "else schema cannot be null");
    schema.set(IF, ifSchema.build().getNode());
    schema.set(THEN, thenSchema.build().getNode());
    schema.set(ELSE, elseSchema.build().getNode());
    return this;
  }

  // ========== AnyOf ==========

  @Override
  public UntypedBuilderImpl anyOf(IBuildableSchemaType... schemas) {
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

  @Override
  public UntypedBuilderImpl anyOf(ObjectNode... schemas) {
    Objects.requireNonNull(schemas, "anyOf schemas array cannot be null");
    if (schemas.length == 0) {
      throw new IllegalArgumentException("anyOf array cannot be empty");
    }
    var anyOfNode = schema.putArray(ANY_OF);
    for (ObjectNode schemaNode : schemas) {
      Objects.requireNonNull(schemaNode, "Schema in anyOf array cannot be null");
      anyOfNode.add(schemaNode);
    }
    return this;
  }

  @Override
  public UntypedBuilderImpl anyOf(List<? extends IBuildableSchemaType> schemas) {
    Objects.requireNonNull(schemas, "anyOf schemas list cannot be null");
    if (schemas.isEmpty()) {
      throw new IllegalArgumentException("anyOf list cannot be empty");
    }
    return anyOf(schemas.toArray(new IBuildableSchemaType[0]));
  }
}
