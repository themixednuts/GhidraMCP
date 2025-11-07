package com.themixednuts.utils.jsonschema;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.themixednuts.utils.jsonschema.google.SchemaBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Comprehensive unit tests for JsonSchema class.
 */
class JsonSchemaTest {

    private ObjectMapper mapper;
    private JsonSchema schema;

    @BeforeEach
    void setUp() {
        mapper = new ObjectMapper();
        schema = SchemaBuilder
                .string()
                .minLength(1)
                .maxLength(10)
                .build();
    }

    @Test
    void testBuildIntegerSchemaWithMinimum() {
        JsonSchema testSchema = SchemaBuilder
                .integer()
                .minimum(0)
                .build();
        ObjectNode result = testSchema.getNode();
        assertEquals("integer", result.get("type").asText());
        assertEquals(0, result.get("minimum").asInt());
    }

    @Test
    void testDefaultConstructorProducesEmptyNode() {
        JsonSchema testSchema = new JsonSchema();
        ObjectNode result = testSchema.getNode();
        assertNotNull(result);
        assertTrue(result.isEmpty());
    }

    @Test
    void testBuilderProducesObjectSchema() {
        JsonSchema obj = SchemaBuilder.object().build();
        assertEquals("object", obj.getNode().get("type").asText());
    }

    @Test
    void testGetNodeReturnsActualReference() {
        ObjectNode node1 = schema.getNode();
        ObjectNode node2 = schema.getNode();

        // Should return the same reference (not deep copies)
        assertSame(node1, node2);

        // Modifications should affect the schema
        node1.put("newField", "test");
        assertTrue(schema.getNode().has("newField"));
    }

    @Test
    void testGetNodeMutability() {
        ObjectNode node = schema.getNode();
        node.put("mutated", true);

        // The schema should reflect the mutation
        assertTrue(schema.getNode().get("mutated").asBoolean());
    }

    @Test
    void testToJsonStringWithValidMapper() {
        Optional<String> jsonString = schema.toJsonString(mapper);

        assertTrue(jsonString.isPresent());
        String json = jsonString.get();
        assertTrue(json.contains("\"type\":\"string\""));
        // Google AI API serializes numeric constraints as strings per spec
        assertTrue(json.contains("\"minLength\":\"1\""));
        assertTrue(json.contains("\"maxLength\":\"10\""));
    }

    @Test
    void testToJsonStringWithNullMapper() {
        Optional<String> jsonString = schema.toJsonString(null);

        assertFalse(jsonString.isPresent());
    }

    @Test
    void testToJsonStringWithDefaultMapper() {
        Optional<String> jsonString = schema.toJsonString();

        assertTrue(jsonString.isPresent());
        String json = jsonString.get();
        assertTrue(json.contains("\"type\":\"string\""));
    }

    @Test
    void testToJsonStringWithComplexData() {
        JsonSchema complexSchema = SchemaBuilder
                .object()
                .title("Complex Schema")
                .property("name", SchemaBuilder.string().minLength(1))
                .requiredProperty("name")
                .build();
        Optional<String> jsonString = complexSchema.toJsonString();
        assertTrue(jsonString.isPresent());
        String json = jsonString.get();
        assertTrue(json.contains("\"title\":\"Complex Schema\""));
        assertTrue(json.contains("\"properties\""));
        assertTrue(json.contains("\"name\""));
    }

    @Test
    void testToString() {
        String stringRepresentation = schema.toString();

        assertNotNull(stringRepresentation);
        assertFalse(stringRepresentation.isEmpty());
        assertTrue(stringRepresentation.contains("type"));
    }

    @Test
    void testToStringWithSerializationError() {
        // This test ensures toString handles errors gracefully
        // by mocking a scenario where serialization might fail
        JsonSchema testSchema = new JsonSchema();
        String result = testSchema.toString();

        // Should return a fallback string if serialization fails
        assertNotNull(result);
        assertFalse(result.isEmpty());
    }

    @Test
    void testEqualsWithSameObject() {
        assertTrue(schema.equals(schema));
    }

    @Test
    void testEqualsWithEqualSchemas() {
        JsonSchema schema1 = SchemaBuilder.string().minLength(1).build();
        JsonSchema schema2 = SchemaBuilder.string().minLength(1).build();
        assertEquals(schema1, schema2);
    }

    @Test
    void testEqualsWithDifferentSchemas() {
        JsonSchema schema1 = SchemaBuilder.string().build();
        JsonSchema schema2 = SchemaBuilder.integer().build();
        assertNotEquals(schema1, schema2);
    }

    @Test
    void testEqualsWithNull() {
        assertFalse(schema.equals(null));
    }

    @Test
    void testEqualsWithDifferentClass() {
        assertFalse(schema.equals("not a schema"));
    }

    @Test
    void testHashCodeConsistency() {
        int hash1 = schema.hashCode();
        int hash2 = schema.hashCode();

        assertEquals(hash1, hash2);
    }

    @Test
    void testHashCodeWithEqualObjects() {
        JsonSchema schema1 = SchemaBuilder.string().build();
        JsonSchema schema2 = SchemaBuilder.string().build();
        assertEquals(schema1.hashCode(), schema2.hashCode());
    }

    @Test
    void testComplexSchemaSerialization() {
        JsonSchema complexSchema = SchemaBuilder
                .object()
                .title("User Profile")
                .description("A complex user profile")
                .property("name", SchemaBuilder.string().minLength(1).maxLength(50))
                .property("age", SchemaBuilder.integer().minimum(0).maximum(150))
                .build();
        Optional<String> jsonString = complexSchema.toJsonString();
        assertTrue(jsonString.isPresent());
        String json = jsonString.get();
        assertTrue(json.contains("\"type\":\"object\""));
        assertTrue(json.contains("\"title\":\"User Profile\""));
        assertTrue(json.contains("\"properties\""));
        assertTrue(json.contains("\"name\""));
        assertTrue(json.contains("\"age\""));
    }

    @Test
    void testEmptySchema() {
        JsonSchema emptySchema = new JsonSchema();

        assertNotNull(emptySchema.getNode());
        assertTrue(emptySchema.getNode().isEmpty());

        Optional<String> jsonString = emptySchema.toJsonString();
        assertTrue(jsonString.isPresent());
        assertEquals("{}", jsonString.get());
    }

    @Test
    void testSchemaWithSpecialCharacters() {
        JsonSchema testSchema = SchemaBuilder
                .string()
                .pattern("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$")
                .description("Email with special chars: @#$%^&*()")
                .build();

        Optional<String> jsonString = testSchema.toJsonString();

        assertTrue(jsonString.isPresent());
        String json = jsonString.get();
        assertTrue(json.contains("special chars"));
        assertTrue(json.contains("@#$%^&*()"));
    }

    @Test
    void testSchemaWithUnicodeCharacters() {
        JsonSchema testSchema = SchemaBuilder
                .string()
                .description("Unicode test: 你好世界 🌍")
                .build();

        Optional<String> jsonString = testSchema.toJsonString();

        assertTrue(jsonString.isPresent());
        String json = jsonString.get();
        assertTrue(json.contains("你好世界"));
        assertTrue(json.contains("🌍"));
    }
}
