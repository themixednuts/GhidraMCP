package com.themixednuts.utils.jsonschema.draft7;

import static org.junit.jupiter.api.Assertions.*;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Tests for Draft 7 SchemaBuilder API and JSON serialization. These tests verify that schemas are
 * built correctly and generate the right JSON structure. For data validation tests, see
 * ValidationTest.java.
 */
class SchemaBuilderTest {

  private ObjectMapper mapper;

  @BeforeEach
  void setUp() {
    mapper = new ObjectMapper();
  }

  // ========== Basic Type Tests ==========

  @Test
  void string_buildsCorrectly() {
    var schema = SchemaBuilder.string().build();
    assertEquals("string", schema.getNode().get("type").asText());
  }

  @Test
  void integer_buildsCorrectly() {
    var schema = SchemaBuilder.integer().build();
    assertEquals("integer", schema.getNode().get("type").asText());
  }

  @Test
  void number_buildsCorrectly() {
    var schema = SchemaBuilder.number().build();
    assertEquals("number", schema.getNode().get("type").asText());
  }

  @Test
  void boolean_buildsCorrectly() {
    var schema = SchemaBuilder.bool().build();
    assertEquals("boolean", schema.getNode().get("type").asText());
  }

  @Test
  void array_buildsCorrectly() {
    var schema = SchemaBuilder.array().build();
    assertEquals("array", schema.getNode().get("type").asText());
  }

  @Test
  void object_buildsCorrectly() {
    var schema = SchemaBuilder.object().build();
    assertEquals("object", schema.getNode().get("type").asText());
  }

  @Test
  void null_buildsCorrectly() {
    var schema = SchemaBuilder.nul().build();
    assertEquals("null", schema.getNode().get("type").asText());
  }

  // ========== Composition Tests ==========

  @Test
  void allOf_withMultipleSchemas_buildsCorrectly() {
    var schema =
        SchemaBuilder.string()
            .allOf(SchemaBuilder.string().minLength(5), SchemaBuilder.string().pattern("^[A-Z]"))
            .build();

    JsonNode node = schema.getNode();
    assertEquals("string", node.get("type").asText());
    assertTrue(node.has("allOf"));
    assertEquals(2, node.get("allOf").size());
  }

  @Test
  void oneOf_withSameType_hasBaseType() {
    var schema =
        SchemaBuilder.string()
            .oneOf(SchemaBuilder.string().minLength(5), SchemaBuilder.string().maxLength(100))
            .build();

    JsonNode node = schema.getNode();
    assertEquals("string", node.get("type").asText());
    assertTrue(node.has("oneOf"));
  }

  @Test
  void oneOf_staticMethod_noBaseType() {
    var schema =
        SchemaBuilder.oneOf(
                SchemaBuilder.string().minLength(10), SchemaBuilder.integer().minimum(0))
            .build();

    JsonNode node = schema.getNode();
    assertFalse(node.has("type"), "Static oneOf should not have base type");
    assertTrue(node.has("oneOf"));
    assertEquals(2, node.get("oneOf").size());
  }

  @Test
  void anyOf_staticMethod_noBaseType() {
    var schema = SchemaBuilder.anyOf(SchemaBuilder.string(), SchemaBuilder.integer()).build();

    JsonNode node = schema.getNode();
    assertFalse(node.has("type"));
    assertTrue(node.has("anyOf"));
  }

  @Test
  void allOf_staticMethod_noBaseType() {
    var schema =
        SchemaBuilder.allOf(
                SchemaBuilder.string().minLength(1), SchemaBuilder.string().maxLength(100))
            .build();

    JsonNode node = schema.getNode();
    assertFalse(node.has("type"));
    assertTrue(node.has("allOf"));
  }

  @Test
  void not_schema_buildsCorrectly() {
    var schema = SchemaBuilder.integer().not(SchemaBuilder.integer().multipleOf(13)).build();

    JsonNode node = schema.getNode();
    assertEquals("integer", node.get("type").asText());
    assertTrue(node.has("not"));
    assertEquals(13, node.get("not").get("multipleOf").asInt());
  }

  @Test
  void not_staticMethod_noBaseType() {
    var schema = SchemaBuilder.not(SchemaBuilder.string().pattern("password")).build();

    JsonNode node = schema.getNode();
    assertFalse(node.has("type"));
    assertTrue(node.has("not"));
  }

  // ========== Conditional Tests ==========

  @Test
  void ifThen_buildsCorrectly() {
    var schema =
        SchemaBuilder.object()
            .property("type", SchemaBuilder.string())
            .ifThen(
                SchemaBuilder.object().property("type", SchemaBuilder.string().constValue("admin")),
                SchemaBuilder.object().requiredProperty("password"))
            .build();

    JsonNode node = schema.getNode();
    assertTrue(node.has("if"));
    assertTrue(node.has("then"));
    assertFalse(node.has("else"));
  }

  @Test
  void ifThenElse_buildsCorrectly() {
    var schema =
        SchemaBuilder.object()
            .ifThenElse(
                SchemaBuilder.object().property("type", SchemaBuilder.string().constValue("text")),
                SchemaBuilder.object().property("value", SchemaBuilder.string()),
                SchemaBuilder.object().property("value", SchemaBuilder.integer()))
            .build();

    JsonNode node = schema.getNode();
    assertTrue(node.has("if"));
    assertTrue(node.has("then"));
    assertTrue(node.has("else"));
  }

  // ========== String Constraints ==========

  @Test
  void string_withAllConstraints_buildsCorrectly() {
    var schema = SchemaBuilder.string().minLength(5).maxLength(100).pattern("^[A-Z]").build();

    JsonNode node = schema.getNode();
    assertEquals(5, node.get("minLength").asInt());
    assertEquals(100, node.get("maxLength").asInt());
    assertEquals("^[A-Z]", node.get("pattern").asText());
  }

  @Test
  void string_enum_buildsCorrectly() {
    var schema = SchemaBuilder.string().enumValues("active", "inactive", "pending").build();

    JsonNode node = schema.getNode();
    assertTrue(node.has("enum"));
    assertEquals(3, node.get("enum").size());
    assertEquals("active", node.get("enum").get(0).asText());
  }

  @Test
  void string_constValue_buildsCorrectly() {
    var schema = SchemaBuilder.string().constValue("admin").build();

    JsonNode node = schema.getNode();
    assertEquals("admin", node.get("const").asText());
  }

  // ========== Numeric Constraints ==========

  @Test
  void integer_withBounds_buildsCorrectly() {
    var schema = SchemaBuilder.integer().minimum(0).maximum(100).build();

    JsonNode node = schema.getNode();
    assertEquals(0, node.get("minimum").asInt());
    assertEquals(100, node.get("maximum").asInt());
  }

  @Test
  void integer_exclusiveBounds_buildsCorrectly() {
    var schema = SchemaBuilder.integer().exclusiveMinimum(0).exclusiveMaximum(100).build();

    JsonNode node = schema.getNode();
    assertEquals(0, node.get("exclusiveMinimum").asInt());
    assertEquals(100, node.get("exclusiveMaximum").asInt());
  }

  @Test
  void integer_multipleOf_buildsCorrectly() {
    var schema = SchemaBuilder.integer().multipleOf(10).build();

    JsonNode node = schema.getNode();
    assertEquals(10, node.get("multipleOf").asInt());
  }

  @Test
  void number_multipleOf_buildsCorrectly() {
    var schema = SchemaBuilder.number().multipleOf(0.1).build();

    JsonNode node = schema.getNode();
    assertEquals(0.1, node.get("multipleOf").asDouble(), 0.001);
  }

  // ========== Array Constraints ==========

  @Test
  void array_withConstraints_buildsCorrectly() {
    var schema =
        SchemaBuilder.array()
            .items(SchemaBuilder.string())
            .minItems(1)
            .maxItems(10)
            .uniqueItems(true)
            .build();

    JsonNode node = schema.getNode();
    assertTrue(node.has("items"));
    assertEquals(1, node.get("minItems").asInt());
    assertEquals(10, node.get("maxItems").asInt());
    assertTrue(node.get("uniqueItems").asBoolean());
  }

  @Test
  void array_contains_buildsCorrectly() {
    var schema =
        SchemaBuilder.array()
            .items(SchemaBuilder.string())
            .contains(SchemaBuilder.string().constValue("admin"))
            .build();

    JsonNode node = schema.getNode();
    assertTrue(node.has("contains"));
    assertEquals("admin", node.get("contains").get("const").asText());
  }

  // ========== Object Constraints ==========

  @Test
  void object_withProperties_buildsCorrectly() {
    var schema =
        SchemaBuilder.object()
            .property("id", SchemaBuilder.integer())
            .property("name", SchemaBuilder.string())
            .requiredProperty("id")
            .build();

    JsonNode node = schema.getNode();
    assertTrue(node.has("properties"));
    assertEquals(2, node.get("properties").size());
    assertTrue(node.has("required"));
    assertEquals("id", node.get("required").get(0).asText());
  }

  @Test
  void object_withPropertyConstraints_buildsCorrectly() {
    var schema = SchemaBuilder.object().minProperties(1).maxProperties(10).build();

    JsonNode node = schema.getNode();
    assertEquals(1, node.get("minProperties").asInt());
    assertEquals(10, node.get("maxProperties").asInt());
  }

  @Test
  void object_additionalProperties_false_buildsCorrectly() {
    var schema =
        SchemaBuilder.object()
            .property("name", SchemaBuilder.string())
            .additionalProperties(false)
            .build();

    JsonNode node = schema.getNode();
    assertFalse(node.get("additionalProperties").asBoolean());
  }

  @Test
  void object_additionalProperties_schema_buildsCorrectly() {
    var schema =
        SchemaBuilder.object()
            .property("name", SchemaBuilder.string())
            .additionalProperties(SchemaBuilder.string())
            .build();

    JsonNode node = schema.getNode();
    assertTrue(node.get("additionalProperties").isObject());
    assertEquals("string", node.get("additionalProperties").get("type").asText());
  }

  // ========== Metadata ==========

  @Test
  void schema_withMetadata_buildsCorrectly() {
    var schema =
        SchemaBuilder.string()
            .title("Username")
            .description("The user's username")
            .defaultValue("guest")
            .build();

    JsonNode node = schema.getNode();
    assertEquals("Username", node.get("title").asText());
    assertEquals("The user's username", node.get("description").asText());
    assertEquals("guest", node.get("default").asText());
  }

  // ========== Error Cases ==========

  @Test
  void allOf_emptyArray_throwsException() {
    assertThrows(IllegalArgumentException.class, () -> SchemaBuilder.string().allOf().build());
  }

  @Test
  void oneOf_emptyArray_throwsException() {
    assertThrows(IllegalArgumentException.class, () -> SchemaBuilder.string().oneOf().build());
  }

  @Test
  void anyOf_emptyArray_throwsException() {
    assertThrows(
        IllegalArgumentException.class,
        () ->
            SchemaBuilder.string()
                .anyOf(new com.themixednuts.utils.jsonschema.IBuildableSchemaType[0])
                .build());
  }

  @Test
  void string_negativeMinLength_throwsException() {
    assertThrows(IllegalArgumentException.class, () -> SchemaBuilder.string().minLength(-1));
  }

  @Test
  void string_negativeMaxLength_throwsException() {
    assertThrows(IllegalArgumentException.class, () -> SchemaBuilder.string().maxLength(-1));
  }

  @Test
  void array_negativeMinItems_throwsException() {
    assertThrows(IllegalArgumentException.class, () -> SchemaBuilder.array().minItems(-1));
  }

  @Test
  void array_negativeMaxItems_throwsException() {
    assertThrows(IllegalArgumentException.class, () -> SchemaBuilder.array().maxItems(-1));
  }

  @Test
  void object_negativeMinProperties_throwsException() {
    assertThrows(IllegalArgumentException.class, () -> SchemaBuilder.object().minProperties(-1));
  }

  @Test
  void object_negativeMaxProperties_throwsException() {
    assertThrows(IllegalArgumentException.class, () -> SchemaBuilder.object().maxProperties(-1));
  }
}
