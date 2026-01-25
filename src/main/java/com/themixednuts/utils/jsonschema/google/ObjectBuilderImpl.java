package com.themixednuts.utils.jsonschema.google;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.themixednuts.utils.jsonschema.IBuildableSchemaType;
import com.themixednuts.utils.jsonschema.JsonSchemaType;
import com.themixednuts.utils.jsonschema.google.SchemaBuilder.IArraySchemaBuilder;
import com.themixednuts.utils.jsonschema.google.SchemaBuilder.IBooleanSchemaBuilder;
import com.themixednuts.utils.jsonschema.google.SchemaBuilder.IIntegerSchemaBuilder;
import com.themixednuts.utils.jsonschema.google.SchemaBuilder.INullSchemaBuilder;
import com.themixednuts.utils.jsonschema.google.SchemaBuilder.INumberSchemaBuilder;
import com.themixednuts.utils.jsonschema.google.SchemaBuilder.IObjectSchemaBuilder;
import com.themixednuts.utils.jsonschema.google.SchemaBuilder.IStringSchemaBuilder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/** Implementation of IObjectSchemaBuilder for building object-type schemas per Google AI API. */
final class ObjectBuilderImpl extends AbstractSchemaBuilderImpl<IObjectSchemaBuilder>
    implements IObjectSchemaBuilder {

  private static final String PROPERTIES = "properties";
  private static final String REQUIRED = "required";
  private static final String MIN_PROPERTIES = "minProperties";
  private static final String MAX_PROPERTIES = "maxProperties";
  private static final String PROPERTY_ORDERING = "propertyOrdering";

  private Map<String, ObjectNode> propertiesMap = null;
  private List<String> requiredPropertiesList = null;

  ObjectBuilderImpl(ObjectMapper mapper) {
    super(JsonSchemaType.OBJECT, mapper);
  }

  @Override
  protected IObjectSchemaBuilder self() {
    return this;
  }

  // Object-specific property methods
  @Override
  public IObjectSchemaBuilder property(String name, ObjectNode propertySchema) {
    return property(name, propertySchema, false);
  }

  @Override
  public IObjectSchemaBuilder property(String name, ObjectNode propertySchema, boolean required) {
    Objects.requireNonNull(name, "Property name cannot be null");
    Objects.requireNonNull(propertySchema, "Property schema cannot be null");

    if (propertiesMap == null) {
      propertiesMap = new LinkedHashMap<>();
      schema.set(PROPERTIES, JsonNodeFactory.instance.objectNode());
    }

    propertiesMap.put(name, propertySchema);
    ((ObjectNode) schema.get(PROPERTIES)).set(name, propertySchema);

    if (required) {
      requiredProperty(name);
    }
    return this;
  }

  @Override
  public IObjectSchemaBuilder property(String name, IBuildableSchemaType propertySchemaBuilder) {
    Objects.requireNonNull(propertySchemaBuilder, "Property schema builder cannot be null");
    return property(name, propertySchemaBuilder.build().getNode(), false);
  }

  @Override
  public IObjectSchemaBuilder property(
      String name, IBuildableSchemaType propertySchemaBuilder, boolean required) {
    Objects.requireNonNull(propertySchemaBuilder, "Property schema builder cannot be null");
    return property(name, propertySchemaBuilder.build().getNode(), required);
  }

  @Override
  public IObjectSchemaBuilder requiredProperty(String name) {
    Objects.requireNonNull(name, "Required property name cannot be null");

    if (requiredPropertiesList == null) {
      requiredPropertiesList = new ArrayList<>();
      schema.set(REQUIRED, JsonNodeFactory.instance.arrayNode());
    }

    if (!requiredPropertiesList.contains(name)) {
      requiredPropertiesList.add(name);
      ((ArrayNode) schema.get(REQUIRED)).add(name);
    }
    return this;
  }

  @Override
  public IObjectSchemaBuilder minProperties(int minProperties) {
    if (minProperties < 0) {
      throw new IllegalArgumentException("minProperties cannot be negative: " + minProperties);
    }
    // Per Google AI API spec: minProperties is "string (int64 format)"
    schema.put(MIN_PROPERTIES, String.valueOf(minProperties));
    return this;
  }

  @Override
  public IObjectSchemaBuilder maxProperties(int maxProperties) {
    if (maxProperties < 0) {
      throw new IllegalArgumentException("maxProperties cannot be negative: " + maxProperties);
    }
    // Per Google AI API spec: maxProperties is "string (int64 format)"
    schema.put(MAX_PROPERTIES, String.valueOf(maxProperties));
    return this;
  }

  @Override
  public IObjectSchemaBuilder properties(Map<String, ?> propertiesMap) {
    Objects.requireNonNull(propertiesMap, "Properties map cannot be null");

    if (this.propertiesMap == null) {
      this.propertiesMap = new LinkedHashMap<>();
      schema.set(PROPERTIES, JsonNodeFactory.instance.objectNode());
    }

    ObjectNode propertiesNode = (ObjectNode) schema.get(PROPERTIES);

    for (Map.Entry<String, ?> entry : propertiesMap.entrySet()) {
      String name = entry.getKey();
      Object value = entry.getValue();
      Objects.requireNonNull(name, "Property name in map cannot be null");
      Objects.requireNonNull(value, "Property value for key '" + name + "' cannot be null");

      // Handle both ObjectNode and IBuildableSchemaType
      ObjectNode propertySchema;
      if (value instanceof ObjectNode) {
        propertySchema = (ObjectNode) value;
      } else if (value instanceof IBuildableSchemaType) {
        propertySchema = ((IBuildableSchemaType) value).build().getNode();
      } else {
        throw new IllegalArgumentException(
            "Property value must be ObjectNode or IBuildableSchemaType for key: " + name);
      }

      this.propertiesMap.put(name, propertySchema);
      propertiesNode.set(name, propertySchema);
    }
    return this;
  }

  // Google-specific: propertyOrdering
  @Override
  public IObjectSchemaBuilder propertyOrdering(List<String> names) {
    Objects.requireNonNull(names, "Property ordering list cannot be null");
    ArrayNode orderingNode = schema.putArray(PROPERTY_ORDERING);
    names.forEach(orderingNode::add);
    return this;
  }

  @Override
  public IObjectSchemaBuilder propertyOrdering(String... names) {
    return propertyOrdering(Arrays.asList(names));
  }

  // Child builder factory methods (inherit parent's mapper)
  @Override
  public IStringSchemaBuilder string() {
    return new StringBuilderImpl(this.mapper);
  }

  @Override
  public INumberSchemaBuilder number() {
    return new NumberBuilderImpl(this.mapper);
  }

  @Override
  public IIntegerSchemaBuilder integer() {
    return new IntegerBuilderImpl(this.mapper);
  }

  @Override
  public IBooleanSchemaBuilder bool() {
    return new BooleanBuilderImpl(this.mapper);
  }

  @Override
  public IArraySchemaBuilder array() {
    return new ArrayBuilderImpl(this.mapper);
  }

  @Override
  public IObjectSchemaBuilder object() {
    return new ObjectBuilderImpl(this.mapper);
  }

  @Override
  public INullSchemaBuilder nul() {
    return new NullBuilderImpl(this.mapper);
  }
}
