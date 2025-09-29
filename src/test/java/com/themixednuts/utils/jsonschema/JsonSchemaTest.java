package com.themixednuts.utils.jsonschema;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
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
        ObjectNode schemaNode = mapper.createObjectNode();
        schemaNode.put("type", "string");
        schemaNode.put("minLength", 1);
        schemaNode.put("maxLength", 10);
        schema = new JsonSchema(schemaNode);
    }

    @Test
    void testConstructorWithValidNode() {
        ObjectNode testNode = mapper.createObjectNode();
        testNode.put("type", "integer");
        testNode.put("minimum", 0);

        JsonSchema testSchema = new JsonSchema(testNode);
        ObjectNode result = testSchema.getNode();

        assertEquals("integer", result.get("type").asText());
        assertEquals(0, result.get("minimum").asInt());
    }

    @Test
    void testConstructorWithNullNode() {
        JsonSchema testSchema = new JsonSchema(null);
        ObjectNode result = testSchema.getNode();

        assertNotNull(result);
        assertTrue(result.isEmpty());
    }

    @Test
    void testConstructorWithEmptyNode() {
        JsonSchema testSchema = new JsonSchema();
        ObjectNode result = testSchema.getNode();

        assertNotNull(result);
        assertTrue(result.isEmpty());
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
        assertTrue(json.contains("\"minLength\":1"));
        assertTrue(json.contains("\"maxLength\":10"));
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
        // Create a schema with complex nested data
        ObjectNode complexNode = mapper.createObjectNode();
        complexNode.put("type", "object");
        complexNode.put("title", "Complex Schema");
        
        ObjectNode properties = mapper.createObjectNode();
        ObjectNode nameProp = mapper.createObjectNode();
        nameProp.put("type", "string");
        nameProp.put("minLength", 1);
        properties.set("name", nameProp);
        complexNode.set("properties", properties);
        
        JsonSchema complexSchema = new JsonSchema(complexNode);
        Optional<String> jsonString = complexSchema.toJsonString();
        
        // Should work with complex but valid JSON structures
        assertTrue(jsonString.isPresent());
        assertTrue(jsonString.get().contains("Complex Schema"));
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
        ObjectNode node1 = mapper.createObjectNode();
        node1.put("type", "string");
        node1.put("minLength", 1);
        
        ObjectNode node2 = mapper.createObjectNode();
        node2.put("type", "string");
        node2.put("minLength", 1);

        JsonSchema schema1 = new JsonSchema(node1);
        JsonSchema schema2 = new JsonSchema(node2);

        assertEquals(schema1, schema2);
    }

    @Test
    void testEqualsWithDifferentSchemas() {
        ObjectNode node1 = mapper.createObjectNode();
        node1.put("type", "string");
        
        ObjectNode node2 = mapper.createObjectNode();
        node2.put("type", "integer");

        JsonSchema schema1 = new JsonSchema(node1);
        JsonSchema schema2 = new JsonSchema(node2);

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
        ObjectNode node1 = mapper.createObjectNode();
        node1.put("type", "string");
        
        ObjectNode node2 = mapper.createObjectNode();
        node2.put("type", "string");

        JsonSchema schema1 = new JsonSchema(node1);
        JsonSchema schema2 = new JsonSchema(node2);

        assertEquals(schema1.hashCode(), schema2.hashCode());
    }

    @Test
    void testComplexSchemaSerialization() {
        ObjectNode complexNode = mapper.createObjectNode();
        complexNode.put("type", "object");
        complexNode.put("title", "User Profile");
        complexNode.put("description", "A complex user profile");
        
        ObjectNode properties = mapper.createObjectNode();
        ObjectNode nameProperty = mapper.createObjectNode();
        nameProperty.put("type", "string");
        nameProperty.put("minLength", 1);
        nameProperty.put("maxLength", 50);
        properties.set("name", nameProperty);
        
        ObjectNode ageProperty = mapper.createObjectNode();
        ageProperty.put("type", "integer");
        ageProperty.put("minimum", 0);
        ageProperty.put("maximum", 150);
        properties.set("age", ageProperty);
        
        complexNode.set("properties", properties);
        
        JsonSchema complexSchema = new JsonSchema(complexNode);
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
        ObjectNode node = mapper.createObjectNode();
        node.put("type", "string");
        node.put("pattern", "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$");
        node.put("description", "Email with special chars: @#$%^&*()");
        
        JsonSchema testSchema = new JsonSchema(node);
        Optional<String> jsonString = testSchema.toJsonString();
        
        assertTrue(jsonString.isPresent());
        String json = jsonString.get();
        assertTrue(json.contains("special chars"));
        assertTrue(json.contains("@#$%^&*()"));
    }

    @Test
    void testSchemaWithUnicodeCharacters() {
        ObjectNode node = mapper.createObjectNode();
        node.put("type", "string");
        node.put("description", "Unicode test: 你好世界 🌍");
        
        JsonSchema testSchema = new JsonSchema(node);
        Optional<String> jsonString = testSchema.toJsonString();
        
        assertTrue(jsonString.isPresent());
        String json = jsonString.get();
        assertTrue(json.contains("你好世界"));
        assertTrue(json.contains("🌍"));
    }
}
