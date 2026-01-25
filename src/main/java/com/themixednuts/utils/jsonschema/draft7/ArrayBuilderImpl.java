package com.themixednuts.utils.jsonschema.draft7;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.themixednuts.utils.jsonschema.IBuildableSchemaType;
import com.themixednuts.utils.jsonschema.JsonSchemaType;
import com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.IArraySchemaBuilder;
import com.themixednuts.utils.jsonschema.draft7.SchemaBuilder.IObjectSchemaBuilder;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/** Implementation of IArraySchemaBuilder for building array-type schemas. */
final class ArrayBuilderImpl extends AbstractSchemaBuilderImpl<IArraySchemaBuilder>
    implements IArraySchemaBuilder {

  private static final String MIN_ITEMS = "minItems";
  private static final String MAX_ITEMS = "maxItems";
  private static final String UNIQUE_ITEMS = "uniqueItems";
  private static final String ITEMS = "items";
  private static final String CONTAINS = "contains";

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
    schema.put(MIN_ITEMS, minItems);
    return this;
  }

  @Override
  public IArraySchemaBuilder maxItems(int maxItems) {
    if (maxItems < 0) {
      throw new IllegalArgumentException("maxItems cannot be negative: " + maxItems);
    }
    schema.put(MAX_ITEMS, maxItems);
    return this;
  }

  @Override
  public IArraySchemaBuilder uniqueItems(boolean uniqueItems) {
    schema.put(UNIQUE_ITEMS, uniqueItems);
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

  @Override
  public IArraySchemaBuilder items(List<?> schemas) {
    Objects.requireNonNull(schemas, "items list cannot be null");
    if (schemas.isEmpty()) {
      throw new IllegalArgumentException("items list cannot be empty");
    }

    List<ObjectNode> subSchemaNodes = new ArrayList<>();
    for (Object schema : schemas) {
      Objects.requireNonNull(schema, "Schema in items list cannot be null");
      if (schema instanceof IBuildableSchemaType) {
        subSchemaNodes.add(((IBuildableSchemaType) schema).build().getNode());
      } else if (schema instanceof ObjectNode) {
        subSchemaNodes.add((ObjectNode) schema);
      } else {
        throw new IllegalArgumentException("Items must be IBuildableSchemaType or ObjectNode");
      }
    }

    IObjectSchemaBuilder itemsObjectSchemaBuilder = SchemaBuilder.object(this.mapper);
    itemsObjectSchemaBuilder.anyOf(subSchemaNodes.toArray(new ObjectNode[0]));

    schema.set(ITEMS, itemsObjectSchemaBuilder.build().getNode());
    return this;
  }

  @Override
  public IArraySchemaBuilder contains(ObjectNode containsSchema) {
    Objects.requireNonNull(containsSchema, "Contains schema cannot be null");
    schema.set(CONTAINS, containsSchema);
    return this;
  }

  @Override
  public IArraySchemaBuilder contains(IBuildableSchemaType containsSchemaBuilder) {
    Objects.requireNonNull(containsSchemaBuilder, "Contains schema builder cannot be null");
    return contains(containsSchemaBuilder.build().getNode());
  }
}
