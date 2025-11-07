package com.themixednuts.utils.jsonschema.draft7;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.networknt.schema.JsonSchema;
import com.networknt.schema.JsonSchemaFactory;
import com.networknt.schema.SpecVersion;
import com.networknt.schema.ValidationMessage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Validation tests for Draft 7 schemas using NetworkNT JSON Schema Validator.
 * Tests that our generated schemas validate data correctly per JSON Schema
 * Draft 7 specification.
 * For schema building/serialization tests, see SchemaBuilderTest.java.
 */
class ValidationTest {

        private ObjectMapper mapper;
        private JsonSchemaFactory schemaFactory;

        @BeforeEach
        void setUp() {
                mapper = new ObjectMapper();
                schemaFactory = JsonSchemaFactory.getInstance(SpecVersion.VersionFlag.V7);
        }

        private Set<ValidationMessage> validate(com.themixednuts.utils.jsonschema.JsonSchema ourSchema, Object data) {
                JsonNode schemaNode = ourSchema.getNode();
                JsonSchema validator = schemaFactory.getSchema(schemaNode);
                JsonNode dataNode = mapper.valueToTree(data);
                return validator.validate(dataNode);
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
                assertTrue(errors.isEmpty());
        }

        @Test
        void string_tooShort_fails() {
                var schema = SchemaBuilder.string().minLength(5).build();
                var errors = validate(schema, "Hi");
                assertFalse(errors.isEmpty());
        }

        @Test
        void string_tooLong_fails() {
                var schema = SchemaBuilder.string().maxLength(3).build();
                var errors = validate(schema, "Hello");
                assertFalse(errors.isEmpty());
        }

        @Test
        void string_patternMismatch_fails() {
                var schema = SchemaBuilder.string().pattern("^[a-zA-Z]+$").build();
                var errors = validate(schema, "Hello123");
                assertFalse(errors.isEmpty());
        }

        @Test
        void string_enum_validValue_passes() {
                var schema = SchemaBuilder.string().enumValues("active", "inactive").build();
                var errors = validate(schema, "active");
                assertTrue(errors.isEmpty());
        }

        @Test
        void string_enum_invalidValue_fails() {
                var schema = SchemaBuilder.string().enumValues("active", "inactive").build();
                var errors = validate(schema, "pending");
                assertFalse(errors.isEmpty());
        }

        @Test
        void string_constValue_matches_passes() {
                var schema = SchemaBuilder.string().constValue("admin").build();
                var errors = validate(schema, "admin");
                assertTrue(errors.isEmpty());
        }

        @Test
        void string_constValue_mismatch_fails() {
                var schema = SchemaBuilder.string().constValue("admin").build();
                var errors = validate(schema, "user");
                assertFalse(errors.isEmpty());
        }

        // ========== Integer Validation ==========

        @Test
        void integer_inRange_passes() {
                var schema = SchemaBuilder.integer()
                                .minimum(0)
                                .maximum(100)
                                .build();

                var errors = validate(schema, 50);
                assertTrue(errors.isEmpty());
        }

        @Test
        void integer_belowMinimum_fails() {
                var schema = SchemaBuilder.integer().minimum(10).build();
                var errors = validate(schema, 5);
                assertFalse(errors.isEmpty());
        }

        @Test
        void integer_aboveMaximum_fails() {
                var schema = SchemaBuilder.integer().maximum(10).build();
                var errors = validate(schema, 15);
                assertFalse(errors.isEmpty());
        }

        @Test
        void integer_multipleOf_valid_passes() {
                var schema = SchemaBuilder.integer().multipleOf(10).build();
                var errors = validate(schema, 20);
                assertTrue(errors.isEmpty());
        }

        @Test
        void integer_multipleOf_invalid_fails() {
                var schema = SchemaBuilder.integer().multipleOf(10).build();
                var errors = validate(schema, 15);
                assertFalse(errors.isEmpty());
        }

        @Test
        void integer_exclusiveMinimum_atBoundary_fails() {
                var schema = SchemaBuilder.integer().exclusiveMinimum(0).build();
                var errors = validate(schema, 0);
                assertFalse(errors.isEmpty());
        }

        @Test
        void integer_exclusiveMinimum_aboveBoundary_passes() {
                var schema = SchemaBuilder.integer().exclusiveMinimum(0).build();
                var errors = validate(schema, 1);
                assertTrue(errors.isEmpty());
        }

        // ========== Number Validation ==========

        @Test
        void number_exclusiveMinimum_atBoundary_fails() {
                var schema = SchemaBuilder.number().exclusiveMinimum(0.0).build();
                var errors = validate(schema, 0.0);
                assertFalse(errors.isEmpty());
        }

        @Test
        void number_exclusiveMinimum_aboveBoundary_passes() {
                var schema = SchemaBuilder.number().exclusiveMinimum(0.0).build();
                var errors = validate(schema, 0.1);
                assertTrue(errors.isEmpty());
        }

        @Test
        void number_exclusiveMaximum_atBoundary_fails() {
                var schema = SchemaBuilder.number().exclusiveMaximum(100.0).build();
                var errors = validate(schema, 100.0);
                assertFalse(errors.isEmpty());
        }

        @Test
        void number_multipleOf_valid_passes() {
                var schema = SchemaBuilder.number().multipleOf(0.1).build();
                var errors = validate(schema, 0.5);
                assertTrue(errors.isEmpty());
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
                assertTrue(errors.isEmpty());
        }

        @Test
        void array_tooFewItems_fails() {
                var schema = SchemaBuilder.array().items(SchemaBuilder.string()).minItems(2).build();
                var errors = validate(schema, java.util.List.of("one"));
                assertFalse(errors.isEmpty());
        }

        @Test
        void array_tooManyItems_fails() {
                var schema = SchemaBuilder.array().items(SchemaBuilder.string()).maxItems(2).build();
                var errors = validate(schema, java.util.List.of("one", "two", "three"));
                assertFalse(errors.isEmpty());
        }

        @Test
        void array_uniqueItems_noDuplicates_passes() {
                var schema = SchemaBuilder.array()
                                .items(SchemaBuilder.string())
                                .uniqueItems(true)
                                .build();

                var errors = validate(schema, java.util.List.of("a", "b", "c"));
                assertTrue(errors.isEmpty());
        }

        @Test
        void array_uniqueItems_hasDuplicates_fails() {
                var schema = SchemaBuilder.array()
                                .items(SchemaBuilder.string())
                                .uniqueItems(true)
                                .build();

                var errors = validate(schema, java.util.List.of("a", "b", "a"));
                assertFalse(errors.isEmpty());
        }

        @Test
        void array_contains_hasRequiredValue_passes() {
                var schema = SchemaBuilder.array()
                                .items(SchemaBuilder.string())
                                .contains(SchemaBuilder.string().constValue("admin"))
                                .build();

                var errors = validate(schema, java.util.List.of("user", "admin", "guest"));
                assertTrue(errors.isEmpty());
        }

        @Test
        void array_contains_missingRequiredValue_fails() {
                var schema = SchemaBuilder.array()
                                .items(SchemaBuilder.string())
                                .contains(SchemaBuilder.string().constValue("admin"))
                                .build();

                var errors = validate(schema, java.util.List.of("user", "guest"));
                assertFalse(errors.isEmpty());
        }

        @Test
        void array_itemSchema_invalidItem_fails() {
                var schema = SchemaBuilder.array()
                                .items(SchemaBuilder.integer().minimum(0))
                                .build();

                var errors = validate(schema, java.util.List.of(1, 2, -1));
                assertFalse(errors.isEmpty());
        }

        // ========== Object Validation ==========

        @Test
        void object_validProperties_passes() {
                var schema = SchemaBuilder.object()
                                .property("name", SchemaBuilder.string())
                                .property("age", SchemaBuilder.integer().minimum(0))
                                .build();

                var errors = validate(schema, mapper.createObjectNode()
                                .put("name", "John")
                                .put("age", 30));
                assertTrue(errors.isEmpty());
        }

        @Test
        void object_missingRequiredProperty_fails() {
                var schema = SchemaBuilder.object()
                                .property("name", SchemaBuilder.string())
                                .requiredProperty("name")
                                .build();

                var errors = validate(schema, mapper.createObjectNode().put("age", 30));
                assertFalse(errors.isEmpty());
        }

        @Test
        void object_tooFewProperties_fails() {
                var schema = SchemaBuilder.object().minProperties(2).build();
                var errors = validate(schema, mapper.createObjectNode().put("a", 1));
                assertFalse(errors.isEmpty());
        }

        @Test
        void object_tooManyProperties_fails() {
                var schema = SchemaBuilder.object().maxProperties(2).build();
                var errors = validate(schema, mapper.createObjectNode()
                                .put("a", 1)
                                .put("b", 2)
                                .put("c", 3));
                assertFalse(errors.isEmpty());
        }

        @Test
        void object_additionalProperties_false_extraProperty_fails() {
                var schema = SchemaBuilder.object()
                                .property("name", SchemaBuilder.string())
                                .additionalProperties(false)
                                .build();

                var errors = validate(schema, mapper.createObjectNode()
                                .put("name", "test")
                                .put("extra", "not allowed"));
                assertFalse(errors.isEmpty());
        }

        @Test
        void object_additionalProperties_false_noExtra_passes() {
                var schema = SchemaBuilder.object()
                                .property("name", SchemaBuilder.string())
                                .additionalProperties(false)
                                .build();

                var errors = validate(schema, mapper.createObjectNode().put("name", "test"));
                assertTrue(errors.isEmpty());
        }

        @Test
        void object_additionalProperties_schema_validExtra_passes() {
                var schema = SchemaBuilder.object()
                                .property("name", SchemaBuilder.string())
                                .additionalProperties(SchemaBuilder.integer())
                                .build();

                var errors = validate(schema, mapper.createObjectNode()
                                .put("name", "test")
                                .put("count", 5));
                assertTrue(errors.isEmpty());
        }

        @Test
        void object_additionalProperties_schema_invalidExtra_fails() {
                var schema = SchemaBuilder.object()
                                .property("name", SchemaBuilder.string())
                                .additionalProperties(SchemaBuilder.integer())
                                .build();

                var errors = validate(schema, mapper.createObjectNode()
                                .put("name", "test")
                                .put("count", "not an integer"));
                assertFalse(errors.isEmpty());
        }

        // ========== Composition Validation ==========

        @Test
        void allOf_matchesAll_passes() {
                var schema = SchemaBuilder.string()
                                .allOf(
                                                SchemaBuilder.string().minLength(5),
                                                SchemaBuilder.string().pattern("^[A-Z]"))
                                .build();

                var errors = validate(schema, "Hello");
                assertTrue(errors.isEmpty());
        }

        @Test
        void allOf_failsOne_fails() {
                var schema = SchemaBuilder.string()
                                .allOf(
                                                SchemaBuilder.string().minLength(5),
                                                SchemaBuilder.string().pattern("^[A-Z]"))
                                .build();

                var errors = validate(schema, "Hi"); // Too short
                assertFalse(errors.isEmpty());
        }

        @Test
        void oneOf_matchesExactlyOne_passes() {
                var schema = SchemaBuilder.oneOf(
                                SchemaBuilder.string().minLength(10),
                                SchemaBuilder.integer().minimum(0))
                                .build();

                var errors = validate(schema, "HelloWorld"); // Matches first
                assertTrue(errors.isEmpty());

                var errors2 = validate(schema, 5); // Matches second
                assertTrue(errors2.isEmpty());
        }

        @Test
        void oneOf_matchesNone_fails() {
                var schema = SchemaBuilder.oneOf(
                                SchemaBuilder.string().minLength(10),
                                SchemaBuilder.integer().minimum(0))
                                .build();

                var errors = validate(schema, "Hi"); // Too short, not integer
                assertFalse(errors.isEmpty());
        }

        @Test
        void oneOf_matchesMultiple_fails() {
                var schema = SchemaBuilder.string()
                                .oneOf(
                                                SchemaBuilder.string().minLength(3),
                                                SchemaBuilder.string().minLength(5))
                                .build();

                var errors = validate(schema, "Hello"); // Matches both
                assertFalse(errors.isEmpty());
        }

        @Test
        void anyOf_matchesAtLeastOne_passes() {
                var schema = SchemaBuilder.anyOf(
                                SchemaBuilder.string().minLength(10),
                                SchemaBuilder.string().pattern("^admin"),
                                SchemaBuilder.integer().minimum(0))
                                .build();

                var errors1 = validate(schema, "HelloWorld!"); // Long string
                assertTrue(errors1.isEmpty());

                var errors2 = validate(schema, "admin"); // Starts with admin
                assertTrue(errors2.isEmpty());

                var errors3 = validate(schema, 5); // Valid integer
                assertTrue(errors3.isEmpty());
        }

        @Test
        void anyOf_matchesNone_fails() {
                var schema = SchemaBuilder.anyOf(
                                SchemaBuilder.string().minLength(10),
                                SchemaBuilder.string().pattern("^admin"))
                                .build();

                var errors = validate(schema, "Hi"); // Matches neither
                assertFalse(errors.isEmpty());
        }

        @Test
        void not_doesNotMatch_passes() {
                var schema = SchemaBuilder.integer()
                                .minimum(0)
                                .maximum(100)
                                .not(SchemaBuilder.integer().multipleOf(13))
                                .build();

                var errors = validate(schema, 50); // Not a multiple of 13
                assertTrue(errors.isEmpty());
        }

        @Test
        void not_matches_fails() {
                var schema = SchemaBuilder.integer()
                                .not(SchemaBuilder.integer().multipleOf(13))
                                .build();

                var errors = validate(schema, 13); // Is a multiple of 13
                assertFalse(errors.isEmpty());
        }

        // ========== Conditional Validation ==========

        @Test
        void ifThen_conditionTrue_thenApplies() {
                var schema = SchemaBuilder.object()
                                .property("type", SchemaBuilder.string())
                                .property("password", SchemaBuilder.string())
                                .ifThen(
                                                SchemaBuilder.object()
                                                                .property("type",
                                                                                SchemaBuilder.string()
                                                                                                .constValue("admin")),
                                                SchemaBuilder.object()
                                                                .requiredProperty("password"))
                                .build();

                // Admin with password - passes
                var errors1 = validate(schema, mapper.createObjectNode()
                                .put("type", "admin")
                                .put("password", "secret"));
                assertTrue(errors1.isEmpty());

                // Admin without password - fails
                var errors2 = validate(schema, mapper.createObjectNode()
                                .put("type", "admin"));
                assertFalse(errors2.isEmpty());
        }

        @Test
        void ifThen_conditionFalse_thenIgnored() {
                var schema = SchemaBuilder.object()
                                .property("type", SchemaBuilder.string())
                                .ifThen(
                                                SchemaBuilder.object()
                                                                .property("type",
                                                                                SchemaBuilder.string()
                                                                                                .constValue("admin")),
                                                SchemaBuilder.object()
                                                                .requiredProperty("password"))
                                .build();

                // User without password - passes (if doesn't match)
                var errors = validate(schema, mapper.createObjectNode()
                                .put("type", "user"));
                assertTrue(errors.isEmpty());
        }

        @Test
        void ifThenElse_conditionTrue_thenApplies() {
                var schema = SchemaBuilder.object()
                                .property("type", SchemaBuilder.string())
                                .ifThenElse(
                                                SchemaBuilder.object()
                                                                .property("type",
                                                                                SchemaBuilder.string()
                                                                                                .constValue("short")),
                                                SchemaBuilder.object()
                                                                .property("value",
                                                                                SchemaBuilder.string().maxLength(10)),
                                                SchemaBuilder.object()
                                                                .property("value",
                                                                                SchemaBuilder.string().minLength(20)))
                                .build();

                // Type "short" with short value - passes
                var errors1 = validate(schema, mapper.createObjectNode()
                                .put("type", "short")
                                .put("value", "hello"));
                assertTrue(errors1.isEmpty());

                // Type "short" with long value - fails
                var errors2 = validate(schema, mapper.createObjectNode()
                                .put("type", "short")
                                .put("value", "this is way too long for short type"));
                assertFalse(errors2.isEmpty());
        }

        @Test
        void ifThenElse_conditionFalse_elseApplies() {
                var schema = SchemaBuilder.object()
                                .property("type", SchemaBuilder.string())
                                .ifThenElse(
                                                SchemaBuilder.object()
                                                                .property("type",
                                                                                SchemaBuilder.string()
                                                                                                .constValue("short")),
                                                SchemaBuilder.object()
                                                                .property("value",
                                                                                SchemaBuilder.string().maxLength(10)),
                                                SchemaBuilder.object()
                                                                .property("value",
                                                                                SchemaBuilder.string().minLength(20)))
                                .build();

                // Type "long" with long value - passes
                var errors1 = validate(schema, mapper.createObjectNode()
                                .put("type", "long")
                                .put("value", "this is a very long string value"));
                assertTrue(errors1.isEmpty());

                // Type "long" with short value - fails
                var errors2 = validate(schema, mapper.createObjectNode()
                                .put("type", "long")
                                .put("value", "short"));
                assertFalse(errors2.isEmpty());
        }

        // ========== Complex Scenarios ==========

        @Test
        void complexNested_validData_passes() {
                var schema = SchemaBuilder.object()
                                .property("users", SchemaBuilder.array()
                                                .items(SchemaBuilder.object()
                                                                .property("id", SchemaBuilder.integer().minimum(1))
                                                                .property("name", SchemaBuilder.string().minLength(1))
                                                                .requiredProperty("id")
                                                                .requiredProperty("name"))
                                                .minItems(1))
                                .requiredProperty("users")
                                .build();

                var errors = validate(schema, mapper.createObjectNode()
                                .set("users", mapper.createArrayNode()
                                                .add(mapper.createObjectNode()
                                                                .put("id", 1)
                                                                .put("name", "Alice"))
                                                .add(mapper.createObjectNode()
                                                                .put("id", 2)
                                                                .put("name", "Bob"))));
                assertTrue(errors.isEmpty());
        }

        @Test
        void complexNested_invalidNestedData_fails() {
                var schema = SchemaBuilder.object()
                                .property("users", SchemaBuilder.array()
                                                .items(SchemaBuilder.object()
                                                                .property("id", SchemaBuilder.integer().minimum(1))
                                                                .requiredProperty("id")))
                                .build();

                // Nested object has invalid id
                var errors = validate(schema, mapper.createObjectNode()
                                .set("users", mapper.createArrayNode()
                                                .add(mapper.createObjectNode().put("id", -1))));
                assertFalse(errors.isEmpty());
        }
}
