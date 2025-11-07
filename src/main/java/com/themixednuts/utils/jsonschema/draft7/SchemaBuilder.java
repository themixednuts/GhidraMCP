package com.themixednuts.utils.jsonschema.draft7;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.themixednuts.utils.jsonschema.IBuildableSchemaType;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaType;
import com.themixednuts.utils.jsonschema.draft7.traits.IAnyOf;
import com.themixednuts.utils.jsonschema.draft7.traits.ICommonMetadata;
import com.themixednuts.utils.jsonschema.draft7.traits.IComposition;
import com.themixednuts.utils.jsonschema.draft7.traits.IConditionals;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Builder for JSON Schema Draft 7 (pure standard with conditional support).
 * 
 * <p>
 * This builder implements the JSON Schema Draft 7 specification without OpenAPI
 * extensions.
 * It supports conditionals (if/then/else) but does NOT support OpenAPI-specific
 * features like
 * nullable, example (singular), or propertyOrdering.
 * </p>
 * 
 * <p>
 * Example Usage:
 * </p>
 * 
 * <pre>{@code
 * JsonSchema userSchema = SchemaBuilder.object()
 * 		.title("User")
 * 		.description("Represents a user in the system")
 * 		.property("id", SchemaBuilder.integer().description("Unique identifier"), true)
 * 		.property("name", SchemaBuilder.string().minLength(1).description("User's full name"), true)
 * 		.property("email", SchemaBuilder.string().description("User's email address"))
 * 		.property("status", SchemaBuilder.string().enumValues("active", "inactive", "pending"))
 * 		.build();
 * }</pre>
 *
 * @see <a href=
 *      "https://json-schema.org/draft-07/json-schema-validation.html">JSON
 *      Schema Draft 7</a>
 */
public class SchemaBuilder {
	static final ObjectMapper DEFAULT_MAPPER = new ObjectMapper();
	private static final String TYPE = "type";
	private static final String TITLE = "title";
	private static final String DESCRIPTION = "description";
	private static final String ENUM = "enum";
	private static final String MAX_ITEMS = "maxItems";
	private static final String MIN_ITEMS = "minItems";
	private static final String PROPERTIES = "properties";
	private static final String REQUIRED = "required";
	private static final String MIN_PROPERTIES = "minProperties";
	private static final String MAX_PROPERTIES = "maxProperties";
	private static final String MIN_LENGTH = "minLength";
	private static final String MAX_LENGTH = "maxLength";
	private static final String PATTERN = "pattern";
	private static final String ANY_OF = "anyOf";
	private static final String DEFAULT = "default";
	private static final String ITEMS = "items";
	private static final String MINIMUM = "minimum";
	private static final String MAXIMUM = "maximum";
	private static final String EXCLUSIVE_MINIMUM = "exclusiveMinimum";
	private static final String EXCLUSIVE_MAXIMUM = "exclusiveMaximum";
	private static final String MULTIPLE_OF = "multipleOf";
	private static final String CONST = "const";
	private static final String UNIQUE_ITEMS = "uniqueItems";
	private static final String CONTAINS = "contains";
	private static final String ALL_OF = "allOf";
	private static final String ONE_OF = "oneOf";
	private static final String NOT = "not";
	private static final String IF = "if";
	private static final String THEN = "then";
	private static final String ELSE = "else";
	private static final String ADDITIONAL_PROPERTIES = "additionalProperties";

	private final ObjectNode schema;
	private final JsonSchemaType type;

	/**
	 * Private constructor for creating a SchemaBuilder instance.
	 *
	 * @param type The JSON schema type for this builder instance.
	 */
	private SchemaBuilder(JsonSchemaType type) {
		this.schema = DEFAULT_MAPPER.createObjectNode();
		this.type = Objects.requireNonNull(type, "Schema type cannot be null");
		this.schema.put(TYPE, type.toString());
	}

	// ========== Type-Specific Builder Interfaces ==========

	/** State interface for building a 'string' schema (JSON Schema Draft 7). */
	public interface IStringSchemaBuilder extends IBuildableSchemaType,
			ICommonMetadata<IStringSchemaBuilder>,
			IComposition<IStringSchemaBuilder>,
			IConditionals<IStringSchemaBuilder>,
			IAnyOf<IStringSchemaBuilder> {

		// String-specific overload for defaultValue
		IStringSchemaBuilder defaultValue(String value);

		// String-specific validation
		IStringSchemaBuilder constValue(String value);

		IStringSchemaBuilder minLength(int minLength);

		IStringSchemaBuilder maxLength(int maxLength);

		IStringSchemaBuilder pattern(String pattern);

		// String-specific enum methods
		IStringSchemaBuilder enumValues(List<?> values);

		IStringSchemaBuilder enumValues(String... values);

		IStringSchemaBuilder enumValues(Class<? extends Enum<?>> enumClass);

		IStringSchemaBuilder enumValues(Object... values);
	}

	/** State interface for building a 'number' schema (JSON Schema Draft 7). */
	public interface INumberSchemaBuilder extends IBuildableSchemaType,
			ICommonMetadata<INumberSchemaBuilder>,
			IComposition<INumberSchemaBuilder>,
			IConditionals<INumberSchemaBuilder>,
			IAnyOf<INumberSchemaBuilder> {

		// Number-specific overload for defaultValue
		INumberSchemaBuilder defaultValue(Number value);

		// Number-specific validation
		INumberSchemaBuilder constValue(BigDecimal value);

		INumberSchemaBuilder constValue(double value);

		INumberSchemaBuilder constValue(float value);

		INumberSchemaBuilder minimum(BigDecimal minimum);

		INumberSchemaBuilder maximum(BigDecimal maximum);

		INumberSchemaBuilder minimum(double minimum);

		INumberSchemaBuilder maximum(double maximum);

		INumberSchemaBuilder minimum(float minimum);

		INumberSchemaBuilder maximum(float maximum);

		INumberSchemaBuilder exclusiveMinimum(BigDecimal exclusiveMinimum);

		INumberSchemaBuilder exclusiveMaximum(BigDecimal exclusiveMaximum);

		INumberSchemaBuilder exclusiveMinimum(double exclusiveMinimum);

		INumberSchemaBuilder exclusiveMaximum(double exclusiveMaximum);

		INumberSchemaBuilder exclusiveMinimum(float exclusiveMinimum);

		INumberSchemaBuilder exclusiveMaximum(float exclusiveMaximum);

		INumberSchemaBuilder multipleOf(BigDecimal multipleOf);

		INumberSchemaBuilder multipleOf(double multipleOf);

		INumberSchemaBuilder multipleOf(float multipleOf);

		INumberSchemaBuilder enumValues(List<?> values);

		INumberSchemaBuilder enumValues(Object... values);
	}

	/** State interface for building an 'integer' schema (JSON Schema Draft 7). */
	public interface IIntegerSchemaBuilder extends IBuildableSchemaType,
			ICommonMetadata<IIntegerSchemaBuilder>,
			IComposition<IIntegerSchemaBuilder>,
			IConditionals<IIntegerSchemaBuilder>,
			IAnyOf<IIntegerSchemaBuilder> {

		// Integer-specific validation
		IIntegerSchemaBuilder constValue(long value);

		IIntegerSchemaBuilder constValue(int value);

		IIntegerSchemaBuilder minimum(long minimum);

		IIntegerSchemaBuilder maximum(long maximum);

		IIntegerSchemaBuilder minimum(int minimum);

		IIntegerSchemaBuilder maximum(int maximum);

		IIntegerSchemaBuilder exclusiveMinimum(long exclusiveMinimum);

		IIntegerSchemaBuilder exclusiveMaximum(long exclusiveMaximum);

		IIntegerSchemaBuilder exclusiveMinimum(int exclusiveMinimum);

		IIntegerSchemaBuilder exclusiveMaximum(int exclusiveMaximum);

		IIntegerSchemaBuilder multipleOf(long multipleOf);

		IIntegerSchemaBuilder multipleOf(int multipleOf);

		IIntegerSchemaBuilder enumValues(List<?> values);

		IIntegerSchemaBuilder enumValues(Object... values);
	}

	/** State interface for building a 'boolean' schema (JSON Schema Draft 7). */
	public interface IBooleanSchemaBuilder extends IBuildableSchemaType,
			ICommonMetadata<IBooleanSchemaBuilder>,
			IComposition<IBooleanSchemaBuilder>,
			IConditionals<IBooleanSchemaBuilder>,
			IAnyOf<IBooleanSchemaBuilder> {

		// Boolean-specific validation
		IBooleanSchemaBuilder constValue(boolean value);
	}

	/** State interface for building a 'null' schema (JSON Schema Draft 7). */
	public interface INullSchemaBuilder extends IBuildableSchemaType,
			ICommonMetadata<INullSchemaBuilder>,
			IComposition<INullSchemaBuilder>,
			IConditionals<INullSchemaBuilder>,
			IAnyOf<INullSchemaBuilder> {
		// Null type has no specific validation methods beyond common metadata
	}

	/** State interface for building an 'array' schema (JSON Schema Draft 7). */
	public interface IArraySchemaBuilder extends IBuildableSchemaType,
			ICommonMetadata<IArraySchemaBuilder>,
			IComposition<IArraySchemaBuilder>,
			IConditionals<IArraySchemaBuilder>,
			IAnyOf<IArraySchemaBuilder> {

		// Array-specific validation
		IArraySchemaBuilder minItems(int minItems);

		IArraySchemaBuilder maxItems(int maxItems);

		IArraySchemaBuilder uniqueItems(boolean uniqueItems);

		IArraySchemaBuilder items(ObjectNode itemSchema);

		IArraySchemaBuilder items(IBuildableSchemaType itemSchemaBuilder);

		IArraySchemaBuilder items(List<?> schemas);

		IArraySchemaBuilder contains(ObjectNode containsSchema);

		IArraySchemaBuilder contains(IBuildableSchemaType containsSchemaBuilder);
	}

	/**
	 * Object schema builder for JSON Schema Draft 7.
	 * Includes all Draft 7 features: if/then/else conditionals, allOf, oneOf, not,
	 * and additionalProperties.
	 */
	public interface IObjectSchemaBuilder extends IBuildableSchemaType,
			ICommonMetadata<IObjectSchemaBuilder>,
			IComposition<IObjectSchemaBuilder>,
			IConditionals<IObjectSchemaBuilder>,
			IAnyOf<IObjectSchemaBuilder> {

		// Object-specific property methods
		IObjectSchemaBuilder property(String name, ObjectNode propertySchema);

		IObjectSchemaBuilder property(String name, ObjectNode propertySchema, boolean required);

		IObjectSchemaBuilder property(String name, IBuildableSchemaType propertySchemaBuilder);

		IObjectSchemaBuilder property(String name, IBuildableSchemaType propertySchemaBuilder, boolean required);

		IObjectSchemaBuilder requiredProperty(String name);

		IObjectSchemaBuilder minProperties(int minProperties);

		IObjectSchemaBuilder maxProperties(int maxProperties);

		IObjectSchemaBuilder properties(Map<String, ?> propertiesMap);

		// Object-specific keywords
		IObjectSchemaBuilder additionalProperties(boolean allowed);

		IObjectSchemaBuilder additionalProperties(IBuildableSchemaType schema);

		// Child builder factory methods (inherit parent's mapper)
		IStringSchemaBuilder string();

		INumberSchemaBuilder number();

		IIntegerSchemaBuilder integer();

		IBooleanSchemaBuilder bool();

		IArraySchemaBuilder array();

		IObjectSchemaBuilder object();

		INullSchemaBuilder nul();
	}

	// ========== Factory Methods ==========

	public static IStringSchemaBuilder string() {
		return new StringBuilderImpl(DEFAULT_MAPPER);
	}

	public static INumberSchemaBuilder number() {
		return new NumberBuilderImpl(DEFAULT_MAPPER);
	}

	public static IIntegerSchemaBuilder integer() {
		return new IntegerBuilderImpl(DEFAULT_MAPPER);
	}

	public static IBooleanSchemaBuilder bool() {
		return new BooleanBuilderImpl(DEFAULT_MAPPER);
	}

	public static IArraySchemaBuilder array() {
		return new ArrayBuilderImpl(DEFAULT_MAPPER);
	}

	public static IObjectSchemaBuilder object() {
		return new ObjectBuilderImpl(DEFAULT_MAPPER);
	}

	public static INullSchemaBuilder nul() {
		return new NullBuilderImpl(DEFAULT_MAPPER);
	}

	// Factory methods with custom mapper
	public static IStringSchemaBuilder string(ObjectMapper customMapper) {
		return new StringBuilderImpl(customMapper);
	}

	public static INumberSchemaBuilder number(ObjectMapper customMapper) {
		return new NumberBuilderImpl(customMapper);
	}

	public static IIntegerSchemaBuilder integer(ObjectMapper customMapper) {
		return new IntegerBuilderImpl(customMapper);
	}

	public static IBooleanSchemaBuilder bool(ObjectMapper customMapper) {
		return new BooleanBuilderImpl(customMapper);
	}

	public static IArraySchemaBuilder array(ObjectMapper customMapper) {
		return new ArrayBuilderImpl(customMapper);
	}

	public static IObjectSchemaBuilder object(ObjectMapper customMapper) {
		return new ObjectBuilderImpl(customMapper);
	}

	/**
	 * Alias for object(ObjectMapper) - creates an object schema builder for Draft
	 * 7.
	 * This is just a semantic alias to emphasize Draft 7 compliance.
	 */
	public static IObjectSchemaBuilder objectDraft7(ObjectMapper customMapper) {
		return object(customMapper);
	}

	public static INullSchemaBuilder nul(ObjectMapper customMapper) {
		return new NullBuilderImpl(customMapper);
	}

	// ========== Composition-Only Factory Methods (No Base Type) ==========

	/**
	 * Creates a schema with ONLY oneOf constraint and NO base type.
	 * Use this for union types where data can be one of several different types.
	 * 
	 * <p>
	 * Example: String OR Integer
	 * </p>
	 * 
	 * <pre>{@code
	 * JsonSchema schema = SchemaBuilder.oneOf(
	 * 		SchemaBuilder.string().minLength(10),
	 * 		SchemaBuilder.integer().minimum(0)).build();
	 * // Generates: { "oneOf": [{ "type": "string", "minLength": 10 }, { "type":
	 * // "integer", "minimum": 0 }] }
	 * }</pre>
	 * 
	 * @param schemas Schemas where exactly one must match
	 * @return Untyped builder with oneOf constraint
	 */
	public static UntypedBuilderImpl oneOf(IBuildableSchemaType... schemas) {
		return new UntypedBuilderImpl(DEFAULT_MAPPER).oneOf(schemas);
	}

	/**
	 * Creates a schema with ONLY anyOf constraint and NO base type.
	 * Use this for union types where data can match one or more of several types.
	 * 
	 * @param schemas Schemas where at least one must match
	 * @return Untyped builder with anyOf constraint
	 */
	public static UntypedBuilderImpl anyOf(IBuildableSchemaType... schemas) {
		return new UntypedBuilderImpl(DEFAULT_MAPPER).anyOf(schemas);
	}

	/**
	 * Creates a schema with ONLY allOf constraint and NO base type.
	 * Use this for intersection types where data must match all schemas.
	 * 
	 * @param schemas Schemas that must all match
	 * @return Untyped builder with allOf constraint
	 */
	public static UntypedBuilderImpl allOf(IBuildableSchemaType... schemas) {
		return new UntypedBuilderImpl(DEFAULT_MAPPER).allOf(schemas);
	}

	/**
	 * Creates a schema with ONLY not constraint and NO base type.
	 * Use this to exclude a specific schema pattern.
	 * 
	 * @param schema Schema that must NOT match
	 * @return Untyped builder with not constraint
	 */
	public static UntypedBuilderImpl not(IBuildableSchemaType schema) {
		return new UntypedBuilderImpl(DEFAULT_MAPPER).not(schema);
	}

	/*
	 * Implementation Note:
	 * The old single BuilderStateImpl class has been replaced with separate
	 * implementation classes for proper type-state pattern:
	 * 
	 * - AbstractSchemaBuilderImpl: Base class with shared logic
	 * - StringBuilderImpl: Implements IStringSchemaBuilder only
	 * - NumberBuilderImpl: Implements INumberSchemaBuilder only
	 * - IntegerBuilderImpl: Implements IIntegerSchemaBuilder only
	 * - BooleanBuilderImpl: Implements IBooleanSchemaBuilder only
	 * - ArrayBuilderImpl: Implements IArraySchemaBuilder only
	 * - ObjectBuilderImpl: Implements IObjectSchemaBuilder only
	 * - NullBuilderImpl: Implements INullSchemaBuilder only
	 * - UntypedBuilderImpl: For composition-only schemas (no base type)
	 * 
	 * This provides true type-state pattern where casting between types won't
	 * compile,
	 * while the trait-style capability interfaces (ICommonMetadata, IComposition,
	 * IConditionals, IAnyOf) keep the code DRY.
	 */
}
