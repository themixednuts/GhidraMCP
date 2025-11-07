package com.themixednuts.utils.jsonschema.google;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for Google AI API SchemaBuilder API and JSON serialization.
 * These tests verify that schemas are built correctly and generate the right JSON per Google AI API specification.
 * 
 * Note: Google AI API format is NOT standard JSON Schema - it has specific requirements:
 * - Numeric constraints (minLength, maxItems, etc.) as STRINGS (int64 format)
 * - Min/max bounds (minimum, maximum) as NUMBERS
 * - nullable boolean on all types
 * - example (singular value)
 * - propertyOrdering array
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

    // ========== String Constraints (STRINGS per Google spec) ==========

    @Test
    void string_withConstraints_serializesAsStrings() {
        var schema = SchemaBuilder.string()
                .minLength(5)
                .maxLength(100)
                .pattern("^[A-Z]")
                .build();

        JsonNode node = schema.getNode();
        
        assertEquals("string", node.get("type").asText());
        // Per Google spec: minLength/maxLength are STRINGS (int64 format)
        assertEquals("5", node.get("minLength").asText(), "minLength should be string per Google spec");
        assertEquals("100", node.get("maxLength").asText(), "maxLength should be string per Google spec");
        assertEquals("^[A-Z]", node.get("pattern").asText());
    }

    @Test
    void string_enum_autoSetsFormatEnum() {
        var schema = SchemaBuilder.string()
                .enumValues("EAST", "NORTH", "SOUTH", "WEST")
                .build();

        JsonNode node = schema.getNode();
        
        assertEquals("string", node.get("type").asText());
        // Per Google spec: enum format must be set automatically
        assertEquals("enum", node.get("format").asText(), "format should be 'enum' for string enums");
        assertTrue(node.has("enum"));
        assertEquals(4, node.get("enum").size());
        assertEquals("EAST", node.get("enum").get(0).asText());
    }

    @Test
    void string_formatType_serializesCorrectly() {
        var schema = SchemaBuilder.string()
                .format(StringFormatType.EMAIL)
                .build();

        JsonNode node = schema.getNode();
        assertEquals("email", node.get("format").asText());
    }

    // ========== Number/Integer Constraints (NUMBERS per Google spec) ==========

    @Test
    void number_withBounds_serializesAsNumbers() {
        var schema = SchemaBuilder.number()
                .minimum(0.0)
                .maximum(100.0)
                .build();

        JsonNode node = schema.getNode();
        
        assertEquals("number", node.get("type").asText());
        // Per Google spec: minimum/maximum are NUMBERS (not strings!)
        assertEquals(0.0, node.get("minimum").asDouble(), "minimum should be number per Google spec");
        assertEquals(100.0, node.get("maximum").asDouble(), "maximum should be number per Google spec");
    }

    @Test
    void integer_withBounds_serializesAsNumbers() {
        var schema = SchemaBuilder.integer()
                .minimum(0)
                .maximum(100)
                .build();

        JsonNode node = schema.getNode();
        
        assertEquals("integer", node.get("type").asText());
        // Per Google spec: minimum/maximum are NUMBERS
        assertEquals(0, node.get("minimum").asInt());
        assertEquals(100, node.get("maximum").asInt());
    }

    @Test
    void integer_formatType_serializesCorrectly() {
        var schema = SchemaBuilder.integer()
                .format(IntegerFormatType.INT64)
                .build();

        JsonNode node = schema.getNode();
        assertEquals("int64", node.get("format").asText());
    }

    @Test
    void number_formatType_serializesCorrectly() {
        var schema = SchemaBuilder.number()
                .format(NumberFormatType.DOUBLE)
                .build();

        JsonNode node = schema.getNode();
        assertEquals("double", node.get("format").asText());
    }

    // ========== Array Constraints (STRINGS per Google spec) ==========

    @Test
    void array_withConstraints_serializesCorrectly() {
        var schema = SchemaBuilder.array()
                .items(SchemaBuilder.string())
                .minItems(1)
                .maxItems(10)
                .build();

        JsonNode node = schema.getNode();
        
        assertEquals("array", node.get("type").asText());
        // Per Google spec: minItems/maxItems are STRINGS (int64 format)
        assertEquals("1", node.get("minItems").asText(), "minItems should be string per Google spec");
        assertEquals("10", node.get("maxItems").asText(), "maxItems should be string per Google spec");
        assertTrue(node.has("items"));
    }

    // ========== Object Constraints (STRINGS per Google spec) ==========

    @Test
    void object_withProperties_serializesCorrectly() {
        var schema = SchemaBuilder.object()
                .property("id", SchemaBuilder.integer())
                .property("name", SchemaBuilder.string())
                .requiredProperty("id")
                .minProperties(1)
                .maxProperties(10)
                .build();

        JsonNode node = schema.getNode();
        
        assertEquals("object", node.get("type").asText());
        // Per Google spec: minProperties/maxProperties are STRINGS (int64 format)
        assertEquals("1", node.get("minProperties").asText(), "minProperties should be string per Google spec");
        assertEquals("10", node.get("maxProperties").asText(), "maxProperties should be string per Google spec");
        assertTrue(node.has("properties"));
        assertTrue(node.has("required"));
        assertEquals("id", node.get("required").get(0).asText());
    }

    @Test
    void object_propertyOrdering_serializesCorrectly() {
        var schema = SchemaBuilder.object()
                .property("id", SchemaBuilder.integer())
                .property("name", SchemaBuilder.string())
                .property("email", SchemaBuilder.string())
                .propertyOrdering("id", "name", "email")
                .build();

        JsonNode node = schema.getNode();
        
        assertTrue(node.has("propertyOrdering"), "propertyOrdering should be present");
        assertEquals(3, node.get("propertyOrdering").size());
        assertEquals("id", node.get("propertyOrdering").get(0).asText());
        assertEquals("name", node.get("propertyOrdering").get(1).asText());
        assertEquals("email", node.get("propertyOrdering").get(2).asText());
    }

    // ========== Google-Specific Fields ==========

    @Test
    void nullable_serializesCorrectly() {
        var schema = SchemaBuilder.string()
                .nullable(true)
                .build();

        JsonNode node = schema.getNode();
        assertTrue(node.get("nullable").asBoolean(), "nullable should be true");
    }

    @Test
    void example_serializesCorrectly() {
        var schema = SchemaBuilder.string()
                .example("test@example.com")
                .build();

        JsonNode node = schema.getNode();
        assertEquals("test@example.com", node.get("example").asText());
    }

    @Test
    void metadata_serializesCorrectly() {
        var schema = SchemaBuilder.string()
                .title("Email")
                .description("User email address")
                .defaultValue("user@example.com")
                .build();

        JsonNode node = schema.getNode();
        assertEquals("Email", node.get("title").asText());
        assertEquals("User email address", node.get("description").asText());
        assertEquals("user@example.com", node.get("default").asText());
    }

    // ========== anyOf Tests ==========

    @Test
    void anyOf_withBaseType_hasType() {
        // Using SchemaBuilder.string().anyOf() - has base type constraint
        var schema = SchemaBuilder.string()
                .anyOf(
                        SchemaBuilder.string().minLength(1),
                        SchemaBuilder.string().maxLength(100))
                .build();

        JsonNode node = schema.getNode();

        assertEquals("string", node.get("type").asText(), "Should have base type when using typed builder");
        assertTrue(node.has("anyOf"));
        assertEquals(2, node.get("anyOf").size());
    }

    @Test
    void anyOf_staticMethod_noBaseType() {
        // Using static SchemaBuilder.anyOf() - NO base type for union of different types
        var schema = SchemaBuilder.anyOf(
                        SchemaBuilder.string().minLength(1),
                        SchemaBuilder.integer().minimum(0))
                .build();

        JsonNode node = schema.getNode();

        assertFalse(node.has("type"), "Should NOT have base type for anyOf union");
        assertTrue(node.has("anyOf"));
        assertEquals(2, node.get("anyOf").size());
        assertEquals("string", node.get("anyOf").get(0).get("type").asText());
        assertEquals("1", node.get("anyOf").get(0).get("minLength").asText());
        assertEquals("integer", node.get("anyOf").get(1).get("type").asText());
        assertEquals(0, node.get("anyOf").get(1).get("minimum").asInt());
    }

    // ========== Complex Schemas ==========

    @Test
    void complexSchema_allGoogleFeatures() {
        var schema = SchemaBuilder.object()
                .title("User")
                .description("A user object")
                .nullable(true)
                .example(mapper.createObjectNode().put("id", 1).put("name", "Test"))
                .property("id", SchemaBuilder.integer()
                        .format(IntegerFormatType.INT64)
                        .minimum(1))
                .property("name", SchemaBuilder.string()
                        .minLength(1)
                        .maxLength(100))
                .property("status", SchemaBuilder.string()
                        .enumValues("active", "inactive"))  // Auto-sets format:enum
                .requiredProperty("id")
                .requiredProperty("name")
                .minProperties(2)
                .maxProperties(10)
                .propertyOrdering("id", "name", "status")
                .build();

        JsonNode node = schema.getNode();
        
        // Verify Google-specific features
        assertEquals("object", node.get("type").asText());
        assertEquals("User", node.get("title").asText());
        assertTrue(node.get("nullable").asBoolean());
        assertTrue(node.has("example"));
        assertTrue(node.has("propertyOrdering"));
        
        // Verify string constraints are strings
        JsonNode nameSchema = node.get("properties").get("name");
        assertEquals("1", nameSchema.get("minLength").asText());
        assertEquals("100", nameSchema.get("maxLength").asText());
        
        // Verify numeric bounds are numbers
        JsonNode idSchema = node.get("properties").get("id");
        assertEquals(1, idSchema.get("minimum").asInt());
        
        // Verify auto format:enum
        JsonNode statusSchema = node.get("properties").get("status");
        assertEquals("enum", statusSchema.get("format").asText());
        
        // Verify object constraints are strings
        assertEquals("2", node.get("minProperties").asText());
        assertEquals("10", node.get("maxProperties").asText());
    }

    @Test
    void nestedSchema_serializesCorrectly() {
        var schema = SchemaBuilder.object()
                .property("users", SchemaBuilder.array()
                        .items(SchemaBuilder.object()
                                .property("id", SchemaBuilder.integer())
                                .property("name", SchemaBuilder.string())
                                .requiredProperty("id"))
                        .minItems(1))
                .build();

        JsonNode node = schema.getNode();
        assertTrue(node.has("properties"));
        assertTrue(node.get("properties").has("users"));
        assertEquals("array", node.get("properties").get("users").get("type").asText());
    }

    // ========== Error Cases ==========

    @Test
    void string_negativeMinLength_throwsException() {
        assertThrows(IllegalArgumentException.class, () ->
                SchemaBuilder.string().minLength(-1));
    }

    @Test
    void string_negativeMaxLength_throwsException() {
        assertThrows(IllegalArgumentException.class, () ->
                SchemaBuilder.string().maxLength(-1));
    }

    @Test
    void array_negativeMinItems_throwsException() {
        assertThrows(IllegalArgumentException.class, () ->
                SchemaBuilder.array().minItems(-1));
    }

    @Test
    void array_negativeMaxItems_throwsException() {
        assertThrows(IllegalArgumentException.class, () ->
                SchemaBuilder.array().maxItems(-1));
    }

    @Test
    void object_negativeMinProperties_throwsException() {
        assertThrows(IllegalArgumentException.class, () ->
                SchemaBuilder.object().minProperties(-1));
    }

    @Test
    void object_negativeMaxProperties_throwsException() {
        assertThrows(IllegalArgumentException.class, () ->
                SchemaBuilder.object().maxProperties(-1));
    }

    @Test
    void anyOf_emptyArray_throwsException() {
        assertThrows(IllegalArgumentException.class, () ->
                SchemaBuilder.string().anyOf(new com.themixednuts.utils.jsonschema.IBuildableSchemaType[0]).build());
    }

    @Test
    void object_nullPropertyName_throwsException() {
        assertThrows(NullPointerException.class, () ->
                SchemaBuilder.object().property(null, SchemaBuilder.string().build().getNode()));
    }

    @Test
    void object_nullPropertySchema_throwsException() {
        assertThrows(NullPointerException.class, () ->
                SchemaBuilder.object().property("name", (com.fasterxml.jackson.databind.node.ObjectNode) null));
    }

    @Test
    void array_nullItemSchema_throwsException() {
        assertThrows(NullPointerException.class, () ->
                SchemaBuilder.array().items((com.fasterxml.jackson.databind.node.ObjectNode) null));
    }

    // ========== Additional Constraint Violation Tests ==========

    @Test
    void string_emptyEnumArray_throwsException() {
        assertThrows(IllegalArgumentException.class, () ->
                SchemaBuilder.string().enumValues());
    }

    @Test
    void string_nullPattern_throwsException() {
        assertThrows(NullPointerException.class, () ->
                SchemaBuilder.string().pattern(null));
    }

    @Test
    void integer_negativeMinimum_allowed() {
        // Negative minimum is valid - just checking it doesn't throw
        var schema = SchemaBuilder.integer().minimum(-100).build();
        assertEquals(-100, schema.getNode().get("minimum").asInt());
    }

    @Test
    void number_negativeMinimum_allowed() {
        // Negative minimum is valid - just checking it doesn't throw
        var schema = SchemaBuilder.number().minimum(-100.5).build();
        assertEquals(-100.5, schema.getNode().get("minimum").asDouble(), 0.001);
    }

    @Test
    void object_requiredProperty_addsToRequired() {
        var schema = SchemaBuilder.object()
                .property("id", SchemaBuilder.integer())
                .requiredProperty("id")
                .build();
        
        JsonNode node = schema.getNode();
        assertTrue(node.has("required"));
        assertEquals(1, node.get("required").size());
        assertEquals("id", node.get("required").get(0).asText());
    }

    @Test
    void object_duplicateProperty_overwritesPrevious() {
        // Last one wins when same property defined twice
        var schema = SchemaBuilder.object()
                .property("name", SchemaBuilder.string())
                .property("name", SchemaBuilder.integer())  // Overwrites
                .build();

        JsonNode nameSchema = schema.getNode().get("properties").get("name");
        assertEquals("integer", nameSchema.get("type").asText(), "Second property definition should overwrite first");
    }

    @Test
    void propertyOrdering_withNonExistentProperties_allowed() {
        // Property ordering can list properties that don't exist (spec doesn't forbid it)
        var schema = SchemaBuilder.object()
                .property("id", SchemaBuilder.integer())
                .propertyOrdering("id", "name", "email")  // name and email don't exist
                .build();

        JsonNode node = schema.getNode();
        assertEquals(3, node.get("propertyOrdering").size());
    }

    @Test
    void nullable_false_serializesCorrectly() {
        var schema = SchemaBuilder.string().nullable(false).build();
        JsonNode node = schema.getNode();
        assertFalse(node.get("nullable").asBoolean());
    }

    @Test
    void example_complexObject_serializesCorrectly() {
        var exampleValue = mapper.createObjectNode()
                .put("id", 123)
                .put("name", "Test User")
                .set("tags", mapper.createArrayNode().add("admin").add("user"));

        var schema = SchemaBuilder.object().example(exampleValue).build();
        
        JsonNode node = schema.getNode();
        assertTrue(node.has("example"));
        assertEquals(123, node.get("example").get("id").asInt());
        assertEquals("Test User", node.get("example").get("name").asText());
    }

    @Test
    void format_customString_allowed() {
        // Google spec says "Any value is allowed" for format
        var schema = SchemaBuilder.string().format("my-custom-format").build();
        assertEquals("my-custom-format", schema.getNode().get("format").asText());
    }

    @Test
    void title_veryLong_allowed() {
        // No length limit on title per spec
        String longTitle = "A".repeat(1000);
        var schema = SchemaBuilder.string().title(longTitle).build();
        assertEquals(longTitle, schema.getNode().get("title").asText());
    }
}


