package com.themixednuts.utils.jsonschema.google;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.themixednuts.utils.jsonschema.google.validation.Validator;
import com.themixednuts.utils.jsonschema.google.validation.ValidationMessage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Validation tests for Google AI API schemas using our custom Validator.
 * Tests that our generated schemas validate data correctly per Google AI API
 * specification.
 * For schema building/serialization tests, see SchemaBuilderTest.java.
 */
class ValidationTest {

    private ObjectMapper mapper;

    @BeforeEach
    void setUp() {
        mapper = new ObjectMapper();
    }

    private Set<ValidationMessage> validate(com.themixednuts.utils.jsonschema.JsonSchema ourSchema, Object data) {
        JsonNode dataNode = mapper.valueToTree(data);
        return Validator.validate((com.fasterxml.jackson.databind.node.ObjectNode) ourSchema.getNode(),
                dataNode);
    }

    // ========== String Validation ==========

    @Test
    void string_validValue_passes() {
        var schema = SchemaBuilder.string()
                .minLength(3)
                .maxLength(10)
                .pattern("^[a-zA-Z]+$")
                .build();

        var errors = validate(schema, "Hello");
        assertTrue(errors.isEmpty(), "Valid string should pass");
    }

    @Test
    void string_tooShort_fails() {
        var schema = SchemaBuilder.string().minLength(5).build();
        var errors = validate(schema, "Hi");
        assertFalse(errors.isEmpty(), "String below minLength should fail");
        assertTrue(errors.stream().anyMatch(e -> e.getKeyword().equals("minLength")));
    }

    @Test
    void string_tooLong_fails() {
        var schema = SchemaBuilder.string().maxLength(3).build();
        var errors = validate(schema, "Hello");
        assertFalse(errors.isEmpty(), "String above maxLength should fail");
        assertTrue(errors.stream().anyMatch(e -> e.getKeyword().equals("maxLength")));
    }

    @Test
    void string_patternMismatch_fails() {
        var schema = SchemaBuilder.string().pattern("^[a-zA-Z]+$").build();
        var errors = validate(schema, "Hello123");
        assertFalse(errors.isEmpty(), "String not matching pattern should fail");
        assertTrue(errors.stream().anyMatch(e -> e.getKeyword().equals("pattern")));
    }

    @Test
    void string_enum_validValue_passes() {
        var schema = SchemaBuilder.string()
                .enumValues("active", "inactive", "pending")
                .build();

        var errors = validate(schema, "active");
        assertTrue(errors.isEmpty(), "Valid enum value should pass");
    }

    @Test
    void string_enum_invalidValue_fails() {
        var schema = SchemaBuilder.string()
                .enumValues("active", "inactive")
                .build();

        var errors = validate(schema, "pending");
        assertFalse(errors.isEmpty(), "Invalid enum value should fail");
        assertTrue(errors.stream().anyMatch(e -> e.getKeyword().equals("enum")));
    }

    @Test
    void string_wrongType_fails() {
        var schema = SchemaBuilder.string().build();
        var errors = validate(schema, 123);
        assertFalse(errors.isEmpty(), "Integer should fail string validation");
        assertTrue(errors.stream().anyMatch(e -> e.getKeyword().equals("type")));
    }

    // ========== Integer Validation ==========

    @Test
    void integer_validValue_passes() {
        var schema = SchemaBuilder.integer()
                .minimum(0)
                .maximum(100)
                .build();

        var errors = validate(schema, 50);
        assertTrue(errors.isEmpty(), "Valid integer should pass");
    }

    @Test
    void integer_belowMinimum_fails() {
        var schema = SchemaBuilder.integer().minimum(10).build();
        var errors = validate(schema, 5);
        assertFalse(errors.isEmpty(), "Integer below minimum should fail");
        assertTrue(errors.stream().anyMatch(e -> e.getKeyword().equals("minimum")));
    }

    @Test
    void integer_aboveMaximum_fails() {
        var schema = SchemaBuilder.integer().maximum(10).build();
        var errors = validate(schema, 15);
        assertFalse(errors.isEmpty(), "Integer above maximum should fail");
        assertTrue(errors.stream().anyMatch(e -> e.getKeyword().equals("maximum")));
    }

    @Test
    void integer_wrongType_fails() {
        var schema = SchemaBuilder.integer().build();
        var errors = validate(schema, "not a number");
        assertFalse(errors.isEmpty(), "String should fail integer validation");
        assertTrue(errors.stream().anyMatch(e -> e.getKeyword().equals("type")));
    }

    @Test
    void integer_floatingPoint_fails() {
        var schema = SchemaBuilder.integer().build();
        var errors = validate(schema, 3.14);
        assertFalse(errors.isEmpty(), "Floating point should fail integer validation");
    }

    // ========== Number Validation ==========

    @Test
    void number_validValue_passes() {
        var schema = SchemaBuilder.number()
                .minimum(0.0)
                .maximum(100.0)
                .build();

        var errors = validate(schema, 50.5);
        assertTrue(errors.isEmpty(), "Valid number should pass");
    }

    @Test
    void number_integer_passes() {
        var schema = SchemaBuilder.number().build();
        var errors = validate(schema, 42);
        assertTrue(errors.isEmpty(), "Integer should pass number validation");
    }

    @Test
    void number_belowMinimum_fails() {
        var schema = SchemaBuilder.number().minimum(10.0).build();
        var errors = validate(schema, 5.0);
        assertFalse(errors.isEmpty(), "Number below minimum should fail");
        assertTrue(errors.stream().anyMatch(e -> e.getKeyword().equals("minimum")));
    }

    @Test
    void number_aboveMaximum_fails() {
        var schema = SchemaBuilder.number().maximum(10.0).build();
        var errors = validate(schema, 15.0);
        assertFalse(errors.isEmpty(), "Number above maximum should fail");
        assertTrue(errors.stream().anyMatch(e -> e.getKeyword().equals("maximum")));
    }

    @Test
    void number_wrongType_fails() {
        var schema = SchemaBuilder.number().build();
        var errors = validate(schema, "not a number");
        assertFalse(errors.isEmpty(), "String should fail number validation");
    }

    // ========== Boolean Validation ==========

    @Test
    void boolean_true_passes() {
        var schema = SchemaBuilder.bool().build();
        var errors = validate(schema, true);
        assertTrue(errors.isEmpty());
    }

    @Test
    void boolean_false_passes() {
        var schema = SchemaBuilder.bool().build();
        var errors = validate(schema, false);
        assertTrue(errors.isEmpty());
    }

    @Test
    void boolean_wrongType_fails() {
        var schema = SchemaBuilder.bool().build();
        var errors = validate(schema, "true");
        assertFalse(errors.isEmpty(), "String should fail boolean validation");
    }

    // ========== Null Validation ==========

    @Test
    void null_nullValue_passes() {
        var schema = SchemaBuilder.nul().build();
        var errors = validate(schema, null);
        assertTrue(errors.isEmpty());
    }

    @Test
    void null_nonNullValue_fails() {
        var schema = SchemaBuilder.nul().build();
        var errors = validate(schema, "not null");
        assertFalse(errors.isEmpty(), "Non-null value should fail null validation");
    }

    // ========== Array Validation ==========

    @Test
    void array_validSize_passes() {
        var schema = SchemaBuilder.array()
                .items(SchemaBuilder.string())
                .minItems(1)
                .maxItems(5)
                .build();

        var errors = validate(schema, java.util.List.of("one", "two"));
        assertTrue(errors.isEmpty(), "Valid array should pass");
    }

    @Test
    void array_tooFewItems_fails() {
        var schema = SchemaBuilder.array()
                .items(SchemaBuilder.string())
                .minItems(2)
                .build();

        var errors = validate(schema, java.util.List.of("one"));
        assertFalse(errors.isEmpty(), "Array below minItems should fail");
        assertTrue(errors.stream().anyMatch(e -> e.getKeyword().equals("minItems")));
    }

    @Test
    void array_tooManyItems_fails() {
        var schema = SchemaBuilder.array()
                .items(SchemaBuilder.string())
                .maxItems(2)
                .build();

        var errors = validate(schema, java.util.List.of("one", "two", "three"));
        assertFalse(errors.isEmpty(), "Array above maxItems should fail");
        assertTrue(errors.stream().anyMatch(e -> e.getKeyword().equals("maxItems")));
    }

    @Test
    void array_itemSchema_validItems_passes() {
        var schema = SchemaBuilder.array()
                .items(SchemaBuilder.integer().minimum(0))
                .build();

        var errors = validate(schema, java.util.List.of(1, 2, 3));
        assertTrue(errors.isEmpty(), "Array with valid items should pass");
    }

    @Test
    void array_itemSchema_invalidItem_fails() {
        var schema = SchemaBuilder.array()
                .items(SchemaBuilder.integer().minimum(0))
                .build();

        var errors = validate(schema, java.util.List.of(1, 2, -1));
        assertFalse(errors.isEmpty(), "Array with invalid item should fail");
        // Should have error at path $[2]
        assertTrue(errors.stream().anyMatch(e -> e.getPath().contains("[2]")));
    }

    @Test
    void array_wrongType_fails() {
        var schema = SchemaBuilder.array().build();
        var errors = validate(schema, "not an array");
        assertFalse(errors.isEmpty(), "String should fail array validation");
    }

    // ========== Object Validation ==========

    @Test
    void object_validProperties_passes() {
        var schema = SchemaBuilder.object()
                .property("name", SchemaBuilder.string())
                .property("age", SchemaBuilder.integer().minimum(0))
                .requiredProperty("name")
                .build();

        var errors = validate(schema, mapper.createObjectNode()
                .put("name", "John")
                .put("age", 30));
        assertTrue(errors.isEmpty(), "Valid object should pass");
    }

    @Test
    void object_missingRequiredProperty_fails() {
        var schema = SchemaBuilder.object()
                .property("name", SchemaBuilder.string())
                .requiredProperty("name")
                .build();

        var errors = validate(schema, mapper.createObjectNode().put("age", 30));
        assertFalse(errors.isEmpty(), "Object missing required property should fail");
        assertTrue(errors.stream().anyMatch(e -> e.getKeyword().equals("required")));
        assertTrue(errors.stream().anyMatch(e -> e.getMessage().contains("name")));
    }

    @Test
    void object_tooFewProperties_fails() {
        var schema = SchemaBuilder.object()
                .minProperties(2)
                .build();

        var errors = validate(schema, mapper.createObjectNode().put("a", 1));
        assertFalse(errors.isEmpty(), "Object below minProperties should fail");
        assertTrue(errors.stream().anyMatch(e -> e.getKeyword().equals("minProperties")));
    }

    @Test
    void object_tooManyProperties_fails() {
        var schema = SchemaBuilder.object()
                .maxProperties(2)
                .build();

        var errors = validate(schema, mapper.createObjectNode()
                .put("a", 1)
                .put("b", 2)
                .put("c", 3));
        assertFalse(errors.isEmpty(), "Object above maxProperties should fail");
        assertTrue(errors.stream().anyMatch(e -> e.getKeyword().equals("maxProperties")));
    }

    @Test
    void object_invalidPropertyValue_fails() {
        var schema = SchemaBuilder.object()
                .property("age", SchemaBuilder.integer().minimum(0))
                .build();

        var errors = validate(schema, mapper.createObjectNode().put("age", -5));
        assertFalse(errors.isEmpty(), "Object with invalid property value should fail");
        assertTrue(errors.stream().anyMatch(e -> e.getPath().contains(".age")));
    }

    @Test
    void object_wrongType_fails() {
        var schema = SchemaBuilder.object().build();
        var errors = validate(schema, "not an object");
        assertFalse(errors.isEmpty(), "String should fail object validation");
    }

    // ========== Nullable Validation ==========

    @Test
    void nullable_true_allowsNull() {
        var schema = SchemaBuilder.string().nullable(true).build();
        var errors = validate(schema, null);
        assertTrue(errors.isEmpty(), "Null should be allowed when nullable is true");
    }

    @Test
    void nullable_false_rejectsNull() {
        var schema = SchemaBuilder.string().nullable(false).build();
        var errors = validate(schema, null);
        assertFalse(errors.isEmpty(), "Null should fail when nullable is false");
        assertTrue(errors.stream().anyMatch(e -> e.getKeyword().equals("nullable")));
    }

    @Test
    void nullable_notSet_rejectsNull() {
        var schema = SchemaBuilder.string().build();
        var errors = validate(schema, null);
        assertFalse(errors.isEmpty(), "Null should fail when nullable is not set");
    }

    @Test
    void nullable_true_allowsNullForAllTypes() {
        // Test nullable on different types
        var stringSchema = SchemaBuilder.string().nullable(true).build();
        assertTrue(validate(stringSchema, null).isEmpty());

        var integerSchema = SchemaBuilder.integer().nullable(true).build();
        assertTrue(validate(integerSchema, null).isEmpty());

        var arraySchema = SchemaBuilder.array().nullable(true).build();
        assertTrue(validate(arraySchema, null).isEmpty());

        var objectSchema = SchemaBuilder.object().nullable(true).build();
        assertTrue(validate(objectSchema, null).isEmpty());
    }

    // ========== anyOf Validation ==========

    @Test
    void anyOf_matchesFirst_passes() {
        var schema = SchemaBuilder.anyOf(
                SchemaBuilder.string().minLength(10),
                SchemaBuilder.integer().minimum(0))
                .build();

        var errors = validate(schema, "HelloWorld!");
        assertTrue(errors.isEmpty(), "String matching first anyOf schema should pass");
    }

    @Test
    void anyOf_matchesSecond_passes() {
        var schema = SchemaBuilder.anyOf(
                SchemaBuilder.string().minLength(10),
                SchemaBuilder.integer().minimum(0))
                .build();

        var errors = validate(schema, 42);
        assertTrue(errors.isEmpty(), "Integer matching second anyOf schema should pass");
    }

    @Test
    void anyOf_matchesNone_fails() {
        var schema = SchemaBuilder.anyOf(
                SchemaBuilder.string().minLength(10),
                SchemaBuilder.integer().minimum(0))
                .build();

        var errors = validate(schema, "Hi"); // Too short for string, not an integer
        assertFalse(errors.isEmpty(), "Data matching no anyOf schemas should fail");
        assertTrue(errors.stream().anyMatch(e -> e.getKeyword().equals("anyOf")));
    }

    @Test
    void anyOf_matchesBoth_passes() {
        // anyOf allows matching multiple (unlike oneOf)
        var schema = SchemaBuilder.string()
                .anyOf(
                        SchemaBuilder.string().minLength(3),
                        SchemaBuilder.string().minLength(5))
                .build();

        var errors = validate(schema, "Hello"); // Matches both
        assertTrue(errors.isEmpty(), "anyOf allows matching multiple schemas");
    }

    @Test
    void anyOf_withNullable_allowsNull() {
        var schema = SchemaBuilder.anyOf(
                SchemaBuilder.string().minLength(1),
                SchemaBuilder.integer().minimum(0))
                .nullable(true)
                .build();

        var errors = validate(schema, null);
        assertTrue(errors.isEmpty(), "Null should be allowed with nullable true");
    }

    // ========== Nested Schema Validation ==========

    @Test
    void nested_arrayOfObjects_valid_passes() {
        var schema = SchemaBuilder.array()
                .items(SchemaBuilder.object()
                        .property("id", SchemaBuilder.integer().minimum(1))
                        .property("name", SchemaBuilder.string().minLength(1))
                        .requiredProperty("id")
                        .requiredProperty("name"))
                .minItems(1)
                .build();

        var errors = validate(schema, mapper.createArrayNode()
                .add(mapper.createObjectNode().put("id", 1).put("name", "Alice"))
                .add(mapper.createObjectNode().put("id", 2).put("name", "Bob")));

        assertTrue(errors.isEmpty(), "Valid nested array of objects should pass");
    }

    @Test
    void nested_arrayOfObjects_missingRequired_fails() {
        var schema = SchemaBuilder.array()
                .items(SchemaBuilder.object()
                        .property("id", SchemaBuilder.integer())
                        .requiredProperty("id"))
                .build();

        var errors = validate(schema, mapper.createArrayNode()
                .add(mapper.createObjectNode().put("id", 1))
                .add(mapper.createObjectNode().put("name", "Missing ID"))); // Missing id

        assertFalse(errors.isEmpty(), "Array with object missing required property should fail");
        assertTrue(errors.stream().anyMatch(e -> e.getPath().contains("[1]")));
        assertTrue(errors.stream().anyMatch(e -> e.getKeyword().equals("required")));
    }

    @Test
    void nested_objectWithNestedObject_valid_passes() {
        var schema = SchemaBuilder.object()
                .property("user", SchemaBuilder.object()
                        .property("name", SchemaBuilder.string())
                        .property("contact", SchemaBuilder.object()
                                .property("email", SchemaBuilder.string())
                                .property("phone", SchemaBuilder.string())))
                .build();

        var errors = validate(schema, mapper.createObjectNode()
                .set("user", mapper.createObjectNode()
                        .put("name", "John")
                        .set("contact", mapper.createObjectNode()
                                .put("email", "john@example.com")
                                .put("phone", "555-1234"))));

        assertTrue(errors.isEmpty(), "Valid deeply nested object should pass");
    }

    @Test
    void nested_objectWithNestedObject_invalidValue_fails() {
        var schema = SchemaBuilder.object()
                .property("user", SchemaBuilder.object()
                        .property("age", SchemaBuilder.integer().minimum(0)))
                .build();

        var errors = validate(schema, mapper.createObjectNode()
                .set("user", mapper.createObjectNode().put("age", -5)));

        assertFalse(errors.isEmpty(), "Nested object with invalid value should fail");
        assertTrue(errors.stream().anyMatch(e -> e.getPath().contains(".user.age")));
    }

    // ========== Complex Scenarios ==========

    @Test
    void complex_userSchema_valid_passes() {
        var schema = SchemaBuilder.object()
                .property("id", SchemaBuilder.integer()
                        .format(IntegerFormatType.INT64)
                        .minimum(1))
                .property("name", SchemaBuilder.string()
                        .minLength(1)
                        .maxLength(100))
                .property("email", SchemaBuilder.string()
                        .pattern("^[^@]+@[^@]+\\.[^@]+$"))
                .property("status", SchemaBuilder.string()
                        .enumValues("active", "inactive", "pending"))
                .property("tags", SchemaBuilder.array()
                        .items(SchemaBuilder.string())
                        .minItems(0)
                        .maxItems(10))
                .requiredProperty("id")
                .requiredProperty("name")
                .requiredProperty("email")
                .minProperties(3)
                .maxProperties(20)
                .build();

        var errors = validate(schema, mapper.createObjectNode()
                .put("id", 123)
                .put("name", "John Doe")
                .put("email", "john@example.com")
                .put("status", "active")
                .set("tags", mapper.createArrayNode().add("admin").add("user")));

        assertTrue(errors.isEmpty(), "Valid complex schema should pass");
    }

    @Test
    void complex_userSchema_multipleErrors_fails() {
        var schema = SchemaBuilder.object()
                .property("id", SchemaBuilder.integer().minimum(1))
                .property("name", SchemaBuilder.string().minLength(1))
                .property("email", SchemaBuilder.string().pattern("^[^@]+@[^@]+$"))
                .requiredProperty("id")
                .requiredProperty("name")
                .requiredProperty("email")
                .build();

        var errors = validate(schema, mapper.createObjectNode()
                .put("id", -1) // Below minimum
                .put("name", "") // Too short
                .put("email", "invalid")); // Pattern mismatch

        assertFalse(errors.isEmpty(), "Should have multiple validation errors");
        assertEquals(3, errors.size(), "Should have exactly 3 errors");
    }

    @Test
    void complex_withAnyOf_matchesOne_passes() {
        var schema = SchemaBuilder.object()
                .property("value", SchemaBuilder.anyOf(
                        SchemaBuilder.string().pattern("^[A-Z]"),
                        SchemaBuilder.integer().minimum(100)))
                .build();

        // String starting with uppercase
        var errors1 = validate(schema, mapper.createObjectNode().put("value", "Hello"));
        assertTrue(errors1.isEmpty());

        // Integer >= 100
        var errors2 = validate(schema, mapper.createObjectNode().put("value", 150));
        assertTrue(errors2.isEmpty());
    }

    @Test
    void complex_withAnyOf_matchesNone_fails() {
        var schema = SchemaBuilder.object()
                .property("value", SchemaBuilder.anyOf(
                        SchemaBuilder.string().pattern("^[A-Z]"),
                        SchemaBuilder.integer().minimum(100)))
                .build();

        // String not starting with uppercase AND not an integer
        var errors = validate(schema, mapper.createObjectNode().put("value", "hello"));
        assertFalse(errors.isEmpty());
    }

    // ========== Edge Cases ==========

    @Test
    void emptyString_passesMinLengthZero() {
        var schema = SchemaBuilder.string().minLength(0).build();
        var errors = validate(schema, "");
        assertTrue(errors.isEmpty(), "Empty string should pass minLength 0");
    }

    @Test
    void emptyArray_passesMinItemsZero() {
        var schema = SchemaBuilder.array()
                .items(SchemaBuilder.string())
                .minItems(0)
                .build();

        var errors = validate(schema, java.util.List.of());
        assertTrue(errors.isEmpty(), "Empty array should pass minItems 0");
    }

    @Test
    void emptyObject_passesMinPropertiesZero() {
        var schema = SchemaBuilder.object().minProperties(0).build();
        var errors = validate(schema, mapper.createObjectNode());
        assertTrue(errors.isEmpty(), "Empty object should pass minProperties 0");
    }

    @Test
    void largeNumbers_validateCorrectly() {
        var schema = SchemaBuilder.integer()
                .minimum(Long.MIN_VALUE)
                .maximum(Long.MAX_VALUE)
                .build();

        var errors = validate(schema, Long.MAX_VALUE);
        assertTrue(errors.isEmpty(), "Large number should validate correctly");
    }
}
