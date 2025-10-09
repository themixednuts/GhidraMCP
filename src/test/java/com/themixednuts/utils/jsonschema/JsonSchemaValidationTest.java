package com.themixednuts.utils.jsonschema;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.networknt.schema.JsonSchema;
import com.networknt.schema.JsonSchemaFactory;
import com.networknt.schema.SpecVersion;
import com.networknt.schema.ValidationMessage;
import com.themixednuts.utils.jsonschema.google.SchemaBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests that validate actual data against schemas built with SchemaBuilder.
 * Uses NetworkNT JSON Schema Validator to ensure our schemas work correctly.
 */
class JsonSchemaValidationTest {

    private ObjectMapper mapper;
    private JsonSchemaFactory schemaFactory;

    @BeforeEach
    void setUp() {
        mapper = new ObjectMapper();
        schemaFactory = JsonSchemaFactory.getInstance(SpecVersion.VersionFlag.V202012);
    }

    /**
     * Helper method to validate data against a schema.
     */
    private Set<ValidationMessage> validateData(JsonSchema schema, Object data) {
        JsonNode dataNode = mapper.valueToTree(data);
        return schema.validate(dataNode);
    }

    /**
     * Helper method to create a NetworkNT schema from our JsonSchema.
     */
    private JsonSchema createNetworkNTSchema(com.themixednuts.utils.jsonschema.JsonSchema ourSchema) {
        JsonNode schemaNode = ourSchema.getNode();
        return schemaFactory.getSchema(schemaNode);
    }

    // String Validation Tests

    @Test
    void testStringValidationSuccess() {
        com.themixednuts.utils.jsonschema.JsonSchema ourSchema = SchemaBuilder.string()
                .minLength(3)
                .maxLength(10)
                .pattern("^[a-zA-Z]+$")
                .build();

        JsonSchema networkNTSchema = createNetworkNTSchema(ourSchema);
        Set<ValidationMessage> errors = validateData(networkNTSchema, "Hello");

        assertTrue(errors.isEmpty(), "Valid string should pass validation");
    }

    @Test
    void testStringValidationMinLengthFailure() {
        com.themixednuts.utils.jsonschema.JsonSchema ourSchema = SchemaBuilder.string()
                .minLength(5)
                .build();

        JsonSchema networkNTSchema = createNetworkNTSchema(ourSchema);
        Set<ValidationMessage> errors = validateData(networkNTSchema, "Hi");

        assertFalse(errors.isEmpty(), "String below minLength should fail validation");
        assertTrue(errors.stream().anyMatch(error -> error.getMessage().contains("characters long")));
    }

    @Test
    void testStringValidationMaxLengthFailure() {
        com.themixednuts.utils.jsonschema.JsonSchema ourSchema = SchemaBuilder.string()
                .maxLength(3)
                .build();

        JsonSchema networkNTSchema = createNetworkNTSchema(ourSchema);
        Set<ValidationMessage> errors = validateData(networkNTSchema, "Hello");

        assertFalse(errors.isEmpty(), "String above maxLength should fail validation");
        assertTrue(errors.stream().anyMatch(error -> error.getMessage().contains("characters long")));
    }

    @Test
    void testStringValidationPatternFailure() {
        com.themixednuts.utils.jsonschema.JsonSchema ourSchema = SchemaBuilder.string()
                .pattern("^[a-zA-Z]+$")
                .build();

        JsonSchema networkNTSchema = createNetworkNTSchema(ourSchema);
        Set<ValidationMessage> errors = validateData(networkNTSchema, "Hello123");

        assertFalse(errors.isEmpty(), "String not matching pattern should fail validation");
        assertTrue(errors.stream().anyMatch(error -> error.getMessage().contains("pattern")));
    }

    @Test
    void testStringValidationEnumSuccess() {
        com.themixednuts.utils.jsonschema.JsonSchema ourSchema = SchemaBuilder.string()
                .enumValues("red", "green", "blue")
                .build();

        JsonSchema networkNTSchema = createNetworkNTSchema(ourSchema);
        Set<ValidationMessage> errors = validateData(networkNTSchema, "red");

        assertTrue(errors.isEmpty(), "Valid enum value should pass validation");
    }

    @Test
    void testStringValidationEnumFailure() {
        com.themixednuts.utils.jsonschema.JsonSchema ourSchema = SchemaBuilder.string()
                .enumValues("red", "green", "blue")
                .build();

        JsonSchema networkNTSchema = createNetworkNTSchema(ourSchema);
        Set<ValidationMessage> errors = validateData(networkNTSchema, "yellow");

        assertFalse(errors.isEmpty(), "Invalid enum value should fail validation");
        assertTrue(errors.stream().anyMatch(error -> error.getMessage().contains("enum")));
    }

    // Number Validation Tests

    @Test
    void testNumberValidationSuccess() {
        com.themixednuts.utils.jsonschema.JsonSchema ourSchema = SchemaBuilder.number()
                .minimum(1.0)
                .maximum(10.0)
                .build();

        JsonSchema networkNTSchema = createNetworkNTSchema(ourSchema);
        Set<ValidationMessage> errors = validateData(networkNTSchema, 5.5);

        assertTrue(errors.isEmpty(), "Valid number should pass validation");
    }

    @Test
    void testNumberValidationMinimumFailure() {
        com.themixednuts.utils.jsonschema.JsonSchema ourSchema = SchemaBuilder.number()
                .minimum(5.0)
                .build();

        JsonSchema networkNTSchema = createNetworkNTSchema(ourSchema);
        Set<ValidationMessage> errors = validateData(networkNTSchema, 2.5);

        assertFalse(errors.isEmpty(), "Number below minimum should fail validation");
        assertTrue(errors.stream().anyMatch(error -> error.getMessage().contains("minimum")));
    }

    @Test
    void testNumberValidationMaximumFailure() {
        com.themixednuts.utils.jsonschema.JsonSchema ourSchema = SchemaBuilder.number()
                .maximum(5.0)
                .build();

        JsonSchema networkNTSchema = createNetworkNTSchema(ourSchema);
        Set<ValidationMessage> errors = validateData(networkNTSchema, 7.5);

        assertFalse(errors.isEmpty(), "Number above maximum should fail validation");
        assertTrue(errors.stream().anyMatch(error -> error.getMessage().contains("maximum")));
    }

    // Integer Validation Tests

    @Test
    void testIntegerValidationSuccess() {
        com.themixednuts.utils.jsonschema.JsonSchema ourSchema = SchemaBuilder.integer()
                .minimum(1)
                .maximum(100)
                .build();

        JsonSchema networkNTSchema = createNetworkNTSchema(ourSchema);
        Set<ValidationMessage> errors = validateData(networkNTSchema, 50);

        assertTrue(errors.isEmpty(), "Valid integer should pass validation");
    }

    @Test
    void testIntegerValidationFailure() {
        com.themixednuts.utils.jsonschema.JsonSchema ourSchema = SchemaBuilder.integer()
                .build();

        JsonSchema networkNTSchema = createNetworkNTSchema(ourSchema);
        Set<ValidationMessage> errors = validateData(networkNTSchema, 3.14);

        assertFalse(errors.isEmpty(), "Non-integer number should fail integer validation");
    }

    // Boolean Validation Tests

    @Test
    void testBooleanValidationSuccess() {
        com.themixednuts.utils.jsonschema.JsonSchema ourSchema = SchemaBuilder.bool().build();

        JsonSchema networkNTSchema = createNetworkNTSchema(ourSchema);
        Set<ValidationMessage> errors1 = validateData(networkNTSchema, true);
        Set<ValidationMessage> errors2 = validateData(networkNTSchema, false);

        assertTrue(errors1.isEmpty(), "true should pass boolean validation");
        assertTrue(errors2.isEmpty(), "false should pass boolean validation");
    }

    @Test
    void testBooleanValidationFailure() {
        com.themixednuts.utils.jsonschema.JsonSchema ourSchema = SchemaBuilder.bool().build();

        JsonSchema networkNTSchema = createNetworkNTSchema(ourSchema);
        Set<ValidationMessage> errors = validateData(networkNTSchema, "true");

        assertFalse(errors.isEmpty(), "String should fail boolean validation");
    }

    // Array Validation Tests

    @Test
    void testArrayValidationSuccess() {
        com.themixednuts.utils.jsonschema.JsonSchema ourSchema = SchemaBuilder.array()
                .minItems(2)
                .maxItems(5)
                .build();

        JsonSchema networkNTSchema = createNetworkNTSchema(ourSchema);
        Set<ValidationMessage> errors = validateData(networkNTSchema, java.util.List.of("a", "b", "c"));

        assertTrue(errors.isEmpty(), "Valid array should pass validation");
    }

    @Test
    void testArrayValidationMinItemsFailure() {
        com.themixednuts.utils.jsonschema.JsonSchema ourSchema = SchemaBuilder.array()
                .minItems(3)
                .build();

        JsonSchema networkNTSchema = createNetworkNTSchema(ourSchema);
        Set<ValidationMessage> errors = validateData(networkNTSchema, java.util.List.of("a", "b"));

        assertFalse(errors.isEmpty(), "Array below minItems should fail validation");
        assertTrue(errors.stream().anyMatch(error -> error.getMessage().contains("at least 3 items")));
    }

    @Test
    void testArrayValidationMaxItemsFailure() {
        com.themixednuts.utils.jsonschema.JsonSchema ourSchema = SchemaBuilder.array()
                .maxItems(2)
                .build();

        JsonSchema networkNTSchema = createNetworkNTSchema(ourSchema);
        Set<ValidationMessage> errors = validateData(networkNTSchema, java.util.List.of("a", "b", "c", "d"));

        assertFalse(errors.isEmpty(), "Array above maxItems should fail validation");
        assertTrue(errors.stream().anyMatch(error -> error.getMessage().contains("at most 2 items")));
    }

    // Object Validation Tests

    @Test
    void testObjectValidationSuccess() {
        com.themixednuts.utils.jsonschema.JsonSchema ourSchema = SchemaBuilder.object()
                .property("name", SchemaBuilder.string(), true)
                .property("age", SchemaBuilder.integer(), false)
                .minProperties(1)
                .maxProperties(3)
                .build();

        java.util.Map<String, Object> validData = java.util.Map.of(
                "name", "John",
                "age", 30
        );

        JsonSchema networkNTSchema = createNetworkNTSchema(ourSchema);
        Set<ValidationMessage> errors = validateData(networkNTSchema, validData);

        assertTrue(errors.isEmpty(), "Valid object should pass validation");
    }

    @Test
    void testObjectValidationRequiredPropertyFailure() {
        com.themixednuts.utils.jsonschema.JsonSchema ourSchema = SchemaBuilder.object()
                .property("name", SchemaBuilder.string(), true)
                .property("age", SchemaBuilder.integer(), true)
                .build();

        java.util.Map<String, Object> invalidData = java.util.Map.of(
                "name", "John"
                // Missing required "age" property
        );

        JsonSchema networkNTSchema = createNetworkNTSchema(ourSchema);
        Set<ValidationMessage> errors = validateData(networkNTSchema, invalidData);

        assertFalse(errors.isEmpty(), "Object missing required property should fail validation");
        assertTrue(errors.stream().anyMatch(error -> error.getMessage().contains("required")));
    }

    @Test
    void testObjectValidationMinPropertiesFailure() {
        com.themixednuts.utils.jsonschema.JsonSchema ourSchema = SchemaBuilder.object()
                .minProperties(2)
                .build();

        java.util.Map<String, Object> invalidData = java.util.Map.of(
                "name", "John"
        );

        JsonSchema networkNTSchema = createNetworkNTSchema(ourSchema);
        Set<ValidationMessage> errors = validateData(networkNTSchema, invalidData);

        assertFalse(errors.isEmpty(), "Object below minProperties should fail validation");
        assertTrue(errors.stream().anyMatch(error -> error.getMessage().contains("at least 2 properties")));
    }

    @Test
    void testObjectValidationMaxPropertiesFailure() {
        com.themixednuts.utils.jsonschema.JsonSchema ourSchema = SchemaBuilder.object()
                .maxProperties(2)
                .build();

        java.util.Map<String, Object> invalidData = java.util.Map.of(
                "name", "John",
                "age", 30,
                "email", "john@example.com"
        );

        JsonSchema networkNTSchema = createNetworkNTSchema(ourSchema);
        Set<ValidationMessage> errors = validateData(networkNTSchema, invalidData);

        assertFalse(errors.isEmpty(), "Object above maxProperties should fail validation");
        assertTrue(errors.stream().anyMatch(error -> error.getMessage().contains("at most 2 properties")));
    }

    // Null Validation Tests

    @Test
    void testNullValidationSuccess() {
        com.themixednuts.utils.jsonschema.JsonSchema ourSchema = SchemaBuilder.nul().build();

        JsonSchema networkNTSchema = createNetworkNTSchema(ourSchema);
        Set<ValidationMessage> errors = validateData(networkNTSchema, null);

        assertTrue(errors.isEmpty(), "null should pass null validation");
    }

    @Test
    void testNullValidationFailure() {
        com.themixednuts.utils.jsonschema.JsonSchema ourSchema = SchemaBuilder.nul().build();

        JsonSchema networkNTSchema = createNetworkNTSchema(ourSchema);
        Set<ValidationMessage> errors = validateData(networkNTSchema, "not null");

        assertFalse(errors.isEmpty(), "Non-null value should fail null validation");
    }

    // Nullable Validation Tests

    @Test
    void testNullableValidationSuccess() {
        com.themixednuts.utils.jsonschema.JsonSchema ourSchema = SchemaBuilder.string()
                .nullable(true)
                .build();

        JsonSchema networkNTSchema = createNetworkNTSchema(ourSchema);
        Set<ValidationMessage> errors1 = validateData(networkNTSchema, "Hello");
        Set<ValidationMessage> errors2 = validateData(networkNTSchema, null);

        assertTrue(errors1.isEmpty(), "String should pass nullable validation");
        assertTrue(errors2.isEmpty(), "null should pass nullable validation");
    }

    @Test
    void testNullableValidationFailure() {
        com.themixednuts.utils.jsonschema.JsonSchema ourSchema = SchemaBuilder.string()
                .nullable(false)
                .build();

        JsonSchema networkNTSchema = createNetworkNTSchema(ourSchema);
        Set<ValidationMessage> errors = validateData(networkNTSchema, null);

        assertFalse(errors.isEmpty(), "null should fail non-nullable validation");
    }

    // Complex Schema Tests

    @Test
    void testComplexNestedSchemaValidation() {
        com.themixednuts.utils.jsonschema.JsonSchema ourSchema = SchemaBuilder.object()
                .property("user", SchemaBuilder.object()
                        .property("name", SchemaBuilder.string().minLength(1), true)
                        .property("age", SchemaBuilder.integer().minimum(0), false)
                        .build().getNode(), true)
                .property("tags", SchemaBuilder.array()
                        .items(SchemaBuilder.string())
                        .maxItems(5)
                        .build().getNode(), false)
                .build();

        java.util.Map<String, Object> validData = java.util.Map.of(
                "user", java.util.Map.of(
                        "name", "John Doe",
                        "age", 30
                ),
                "tags", java.util.List.of("developer", "java")
        );

        JsonSchema networkNTSchema = createNetworkNTSchema(ourSchema);
        Set<ValidationMessage> errors = validateData(networkNTSchema, validData);

        assertTrue(errors.isEmpty(), "Complex nested object should pass validation");
    }

    @Test
    void testComplexNestedSchemaValidationFailure() {
        com.themixednuts.utils.jsonschema.JsonSchema ourSchema = SchemaBuilder.object()
                .property("user", SchemaBuilder.object()
                        .property("name", SchemaBuilder.string().minLength(1), true)
                        .build().getNode(), true)
                .property("tags", SchemaBuilder.array()
                        .maxItems(2)
                        .build().getNode(), false)
                .build();

        java.util.Map<String, Object> invalidData = java.util.Map.of(
                "user", java.util.Map.of(
                        "name", "" // Empty name should fail minLength
                ),
                "tags", java.util.List.of("a", "b", "c", "d") // Too many tags should fail maxItems
        );

        JsonSchema networkNTSchema = createNetworkNTSchema(ourSchema);
        Set<ValidationMessage> errors = validateData(networkNTSchema, invalidData);

        assertFalse(errors.isEmpty(), "Invalid nested object should fail validation");
        assertTrue(errors.size() >= 2, "Should have multiple validation errors");
    }
}
