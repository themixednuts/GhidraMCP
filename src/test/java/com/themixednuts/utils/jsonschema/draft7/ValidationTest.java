package com.themixednuts.utils.jsonschema.draft7;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.networknt.schema.Error;
import com.networknt.schema.InputFormat;
import com.networknt.schema.Schema;
import com.networknt.schema.SchemaRegistry;
import com.networknt.schema.dialect.Dialects;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Validation tests for Draft 7 schemas using NetworkNT JSON Schema Validator 2.0.
 * Tests that our generated schemas validate data correctly per JSON Schema
 * Draft 7 specification.
 * For schema building/serialization tests, see SchemaBuilderTest.java.
 */
class ValidationTest {

	private ObjectMapper mapper;
	private SchemaRegistry schemaRegistry;

	@BeforeEach
	void setUp() {
		mapper = new ObjectMapper();
		schemaRegistry = SchemaRegistry.withDialect(Dialects.getDraft7());
	}

	private List<Error> validate(com.themixednuts.utils.jsonschema.JsonSchema ourSchema, Object data) {
		String schemaJson = ourSchema.getNode().toString();
		Schema schema = schemaRegistry.getSchema(schemaJson, InputFormat.JSON);
		JsonNode dataNode = mapper.valueToTree(data);
		return schema.validate(dataNode);
	}

	private boolean isValid(com.themixednuts.utils.jsonschema.JsonSchema ourSchema, Object data) {
		return validate(ourSchema, data).isEmpty();
	}

        // ========== String Validation ==========

        @Test
        void string_validValue_passes() {
                var schema = SchemaBuilder.string()
                                .minLength(3)
                                .maxLength(10)
                                .pattern("^[a-zA-Z]+$")
                                .build();

                assertTrue(isValid(schema, "Hello"));
        }

        @Test
        void string_tooShort_fails() {
                var schema = SchemaBuilder.string().minLength(5).build();
                assertFalse(isValid(schema, "Hi"));
        }

        @Test
        void string_tooLong_fails() {
                var schema = SchemaBuilder.string().maxLength(3).build();
                assertFalse(isValid(schema, "Hello"));
        }

        @Test
        void string_patternMismatch_fails() {
                var schema = SchemaBuilder.string().pattern("^[a-zA-Z]+$").build();
                assertFalse(isValid(schema, "Hello123"));
        }

        @Test
        void string_enum_validValue_passes() {
                var schema = SchemaBuilder.string().enumValues("active", "inactive").build();
                assertTrue(isValid(schema, "active"));
        }

        @Test
        void string_enum_invalidValue_fails() {
                var schema = SchemaBuilder.string().enumValues("active", "inactive").build();
                assertFalse(isValid(schema, "pending"));
        }

        @Test
        void string_constValue_matches_passes() {
                var schema = SchemaBuilder.string().constValue("admin").build();
                assertTrue(isValid(schema, "admin"));
        }

        @Test
        void string_constValue_mismatch_fails() {
                var schema = SchemaBuilder.string().constValue("admin").build();
                assertFalse(isValid(schema, "user"));
        }

        // ========== Integer Validation ==========

        @Test
        void integer_inRange_passes() {
                var schema = SchemaBuilder.integer()
                                .minimum(0)
                                .maximum(100)
                                .build();

                assertTrue(isValid(schema, 50));
        }

        @Test
        void integer_belowMinimum_fails() {
                var schema = SchemaBuilder.integer().minimum(10).build();
                assertFalse(isValid(schema, 5));
        }

        @Test
        void integer_aboveMaximum_fails() {
                var schema = SchemaBuilder.integer().maximum(10).build();
                assertFalse(isValid(schema, 15));
        }

        @Test
        void integer_multipleOf_valid_passes() {
                var schema = SchemaBuilder.integer().multipleOf(10).build();
                assertTrue(isValid(schema, 20));
        }

        @Test
        void integer_multipleOf_invalid_fails() {
                var schema = SchemaBuilder.integer().multipleOf(10).build();
                assertFalse(isValid(schema, 15));
        }

        @Test
        void integer_exclusiveMinimum_atBoundary_fails() {
                var schema = SchemaBuilder.integer().exclusiveMinimum(0).build();
                assertFalse(isValid(schema, 0));
        }

        @Test
        void integer_exclusiveMinimum_aboveBoundary_passes() {
                var schema = SchemaBuilder.integer().exclusiveMinimum(0).build();
                assertTrue(isValid(schema, 1));
        }

        // ========== Number Validation ==========

        @Test
        void number_exclusiveMinimum_atBoundary_fails() {
                var schema = SchemaBuilder.number().exclusiveMinimum(0.0).build();
                assertFalse(isValid(schema, 0.0));
        }

        @Test
        void number_exclusiveMinimum_aboveBoundary_passes() {
                var schema = SchemaBuilder.number().exclusiveMinimum(0.0).build();
                assertTrue(isValid(schema, 0.1));
        }

        @Test
        void number_exclusiveMaximum_atBoundary_fails() {
                var schema = SchemaBuilder.number().exclusiveMaximum(100.0).build();
                assertFalse(isValid(schema, 100.0));
        }

        @Test
        void number_multipleOf_valid_passes() {
                var schema = SchemaBuilder.number().multipleOf(0.1).build();
                assertTrue(isValid(schema, 0.5));
        }

        // ========== Array Validation ==========

        @Test
        void array_validSize_passes() {
                var schema = SchemaBuilder.array()
                                .items(SchemaBuilder.string())
                                .minItems(1)
                                .maxItems(5)
                                .build();

                assertTrue(isValid(schema, java.util.List.of("one", "two")));
        }

        @Test
        void array_tooFewItems_fails() {
                var schema = SchemaBuilder.array().items(SchemaBuilder.string()).minItems(2).build();
                assertFalse(isValid(schema, java.util.List.of("one")));
        }

        @Test
        void array_tooManyItems_fails() {
                var schema = SchemaBuilder.array().items(SchemaBuilder.string()).maxItems(2).build();
                assertFalse(isValid(schema, java.util.List.of("one", "two", "three")));
        }

        @Test
        void array_uniqueItems_noDuplicates_passes() {
                var schema = SchemaBuilder.array()
                                .items(SchemaBuilder.string())
                                .uniqueItems(true)
                                .build();

                assertTrue(isValid(schema, java.util.List.of("a", "b", "c")));
        }

        @Test
        void array_uniqueItems_hasDuplicates_fails() {
                var schema = SchemaBuilder.array()
                                .items(SchemaBuilder.string())
                                .uniqueItems(true)
                                .build();

                assertFalse(isValid(schema, java.util.List.of("a", "b", "a")));
        }

        @Test
        void array_contains_hasRequiredValue_passes() {
                var schema = SchemaBuilder.array()
                                .items(SchemaBuilder.string())
                                .contains(SchemaBuilder.string().constValue("admin"))
                                .build();

                assertTrue(isValid(schema, java.util.List.of("user", "admin", "guest")));
        }

        @Test
        void array_contains_missingRequiredValue_fails() {
                var schema = SchemaBuilder.array()
                                .items(SchemaBuilder.string())
                                .contains(SchemaBuilder.string().constValue("admin"))
                                .build();

                assertFalse(isValid(schema, java.util.List.of("user", "guest")));
        }

        @Test
        void array_itemSchema_invalidItem_fails() {
                var schema = SchemaBuilder.array()
                                .items(SchemaBuilder.integer().minimum(0))
                                .build();

                assertFalse(isValid(schema, java.util.List.of(1, 2, -1)));
        }

        // ========== Object Validation ==========

        @Test
        void object_validProperties_passes() {
                var schema = SchemaBuilder.object()
                                .property("name", SchemaBuilder.string())
                                .property("age", SchemaBuilder.integer().minimum(0))
                                .build();

                assertTrue(isValid(schema, mapper.createObjectNode()
                                .put("name", "John")
                                .put("age", 30)));
        }

        @Test
        void object_missingRequiredProperty_fails() {
                var schema = SchemaBuilder.object()
                                .property("name", SchemaBuilder.string())
                                .requiredProperty("name")
                                .build();

                assertFalse(isValid(schema, mapper.createObjectNode().put("age", 30)));
        }

        @Test
        void object_tooFewProperties_fails() {
                var schema = SchemaBuilder.object().minProperties(2).build();
                assertFalse(isValid(schema, mapper.createObjectNode().put("a", 1)));
        }

        @Test
        void object_tooManyProperties_fails() {
                var schema = SchemaBuilder.object().maxProperties(2).build();
                assertFalse(isValid(schema, mapper.createObjectNode()
                                .put("a", 1)
                                .put("b", 2)
                                .put("c", 3)));
        }

        @Test
        void object_additionalProperties_false_extraProperty_fails() {
                var schema = SchemaBuilder.object()
                                .property("name", SchemaBuilder.string())
                                .additionalProperties(false)
                                .build();

                assertFalse(isValid(schema, mapper.createObjectNode()
                                .put("name", "test")
                                .put("extra", "not allowed")));
        }

        @Test
        void object_additionalProperties_false_noExtra_passes() {
                var schema = SchemaBuilder.object()
                                .property("name", SchemaBuilder.string())
                                .additionalProperties(false)
                                .build();

                assertTrue(isValid(schema, mapper.createObjectNode().put("name", "test")));
        }

        @Test
        void object_additionalProperties_schema_validExtra_passes() {
                var schema = SchemaBuilder.object()
                                .property("name", SchemaBuilder.string())
                                .additionalProperties(SchemaBuilder.integer())
                                .build();

                assertTrue(isValid(schema, mapper.createObjectNode()
                                .put("name", "test")
                                .put("count", 5)));
        }

        @Test
        void object_additionalProperties_schema_invalidExtra_fails() {
                var schema = SchemaBuilder.object()
                                .property("name", SchemaBuilder.string())
                                .additionalProperties(SchemaBuilder.integer())
                                .build();

                assertFalse(isValid(schema, mapper.createObjectNode()
                                .put("name", "test")
                                .put("count", "not an integer")));
        }

        // ========== Composition Validation ==========

        @Test
        void allOf_matchesAll_passes() {
                var schema = SchemaBuilder.string()
                                .allOf(
                                                SchemaBuilder.string().minLength(5),
                                                SchemaBuilder.string().pattern("^[A-Z]"))
                                .build();

                assertTrue(isValid(schema, "Hello"));
        }

        @Test
        void allOf_failsOne_fails() {
                var schema = SchemaBuilder.string()
                                .allOf(
                                                SchemaBuilder.string().minLength(5),
                                                SchemaBuilder.string().pattern("^[A-Z]"))
                                .build();

                assertFalse(isValid(schema, "Hi")); // Too short
        }

        @Test
        void oneOf_matchesExactlyOne_passes() {
                var schema = SchemaBuilder.oneOf(
                                SchemaBuilder.string().minLength(10),
                                SchemaBuilder.integer().minimum(0))
                                .build();

                assertTrue(isValid(schema, "HelloWorld")); // Matches first
                assertTrue(isValid(schema, 5)); // Matches second
        }

        @Test
        void oneOf_matchesNone_fails() {
                var schema = SchemaBuilder.oneOf(
                                SchemaBuilder.string().minLength(10),
                                SchemaBuilder.integer().minimum(0))
                                .build();

                assertFalse(isValid(schema, "Hi")); // Too short, not integer
        }

        @Test
        void oneOf_matchesMultiple_fails() {
                var schema = SchemaBuilder.string()
                                .oneOf(
                                                SchemaBuilder.string().minLength(3),
                                                SchemaBuilder.string().minLength(5))
                                .build();

                assertFalse(isValid(schema, "Hello")); // Matches both
        }

        @Test
        void anyOf_matchesAtLeastOne_passes() {
                var schema = SchemaBuilder.anyOf(
                                SchemaBuilder.string().minLength(10),
                                SchemaBuilder.string().pattern("^admin"),
                                SchemaBuilder.integer().minimum(0))
                                .build();

                assertTrue(isValid(schema, "HelloWorld!")); // Long string
                assertTrue(isValid(schema, "admin")); // Starts with admin
                assertTrue(isValid(schema, 5)); // Valid integer
        }

        @Test
        void anyOf_matchesNone_fails() {
                var schema = SchemaBuilder.anyOf(
                                SchemaBuilder.string().minLength(10),
                                SchemaBuilder.string().pattern("^admin"))
                                .build();

                assertFalse(isValid(schema, "Hi")); // Matches neither
        }

        @Test
        void not_doesNotMatch_passes() {
                var schema = SchemaBuilder.integer()
                                .minimum(0)
                                .maximum(100)
                                .not(SchemaBuilder.integer().multipleOf(13))
                                .build();

                assertTrue(isValid(schema, 50)); // Not a multiple of 13
        }

        @Test
        void not_matches_fails() {
                var schema = SchemaBuilder.integer()
                                .not(SchemaBuilder.integer().multipleOf(13))
                                .build();

                assertFalse(isValid(schema, 13)); // Is a multiple of 13
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
                assertTrue(isValid(schema, mapper.createObjectNode()
                                .put("type", "admin")
                                .put("password", "secret")));

                // Admin without password - fails
                assertFalse(isValid(schema, mapper.createObjectNode()
                                .put("type", "admin")));
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
                assertTrue(isValid(schema, mapper.createObjectNode()
                                .put("type", "user")));
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
                assertTrue(isValid(schema, mapper.createObjectNode()
                                .put("type", "short")
                                .put("value", "hello")));

                // Type "short" with long value - fails
                assertFalse(isValid(schema, mapper.createObjectNode()
                                .put("type", "short")
                                .put("value", "this is way too long for short type")));
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
                assertTrue(isValid(schema, mapper.createObjectNode()
                                .put("type", "long")
                                .put("value", "this is a very long string value")));

                // Type "long" with short value - fails
                assertFalse(isValid(schema, mapper.createObjectNode()
                                .put("type", "long")
                                .put("value", "short")));
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

                assertTrue(isValid(schema, mapper.createObjectNode()
                                .set("users", mapper.createArrayNode()
                                                .add(mapper.createObjectNode()
                                                                .put("id", 1)
                                                                .put("name", "Alice"))
                                                .add(mapper.createObjectNode()
                                                                .put("id", 2)
                                                                .put("name", "Bob")))));
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
                assertFalse(isValid(schema, mapper.createObjectNode()
                                .set("users", mapper.createArrayNode()
                                                .add(mapper.createObjectNode().put("id", -1)))));
        }
}
