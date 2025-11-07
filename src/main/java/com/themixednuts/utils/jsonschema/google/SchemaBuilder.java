package com.themixednuts.utils.jsonschema.google;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.themixednuts.utils.jsonschema.IBuildableSchemaType;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaType;
import com.themixednuts.utils.jsonschema.google.traits.IAnyOf;
import com.themixednuts.utils.jsonschema.google.traits.ICommonMetadata;
import com.themixednuts.utils.jsonschema.google.traits.IFormat;
import com.themixednuts.utils.jsonschema.google.traits.IGoogleSpecific;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Builder for Google AI API JSON Schema.
 * 
 * <p>
 * This builder implements the Google AI API schema specification, which is a
 * subset
 * of OpenAPI 3.0 schema. It includes Google-specific extensions like:
 * <ul>
 * <li>nullable (boolean) - Indicates if value may be null</li>
 * <li>example (value) - Example value for documentation</li>
 * <li>propertyOrdering (array) - Google-specific property order control</li>
 * </ul>
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
 * 		.property("id", SchemaBuilder.integer().format(IntegerFormatType.INT64).description("Unique identifier"),
 * 				true)
 * 		.property("name", SchemaBuilder.string().minLength(1).description("User's full name"), true)
 * 		.property("email", SchemaBuilder.string().format(StringFormatType.EMAIL).description("User's email address"))
 * 		.property("tags", SchemaBuilder.array()
 * 				.items(SchemaBuilder.string().description("A tag string"))
 * 				.description("Optional tags for the user")
 * 				.minItems(1)
 * 				.nullable(true))
 * 		.requiredProperty("status")
 * 		.property("status", SchemaBuilder.string().enumValues("active", "inactive", "pending"))
 * 		.build();
 * }</pre>
 *
 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API
 *      Schema</a>
 */
public class SchemaBuilder {
	static final ObjectMapper DEFAULT_MAPPER = new ObjectMapper();

	// Constants moved to AbstractGoogleSchemaBuilderImpl and implementation classes
	// Kept here for backwards compatibility if needed
	private static final String TYPE = "type";

	private final ObjectNode schema;
	private final JsonSchemaType type;

	/**
	 * Private constructor for creating a SchemaBuilder instance.
	 * Only used internally; clients should use static factory methods.
	 *
	 * @param type The JSON schema type for this builder instance.
	 */
	private SchemaBuilder(JsonSchemaType type) {
		this.schema = DEFAULT_MAPPER.createObjectNode();
		this.type = Objects.requireNonNull(type, "Schema type cannot be null");
		this.schema.put(TYPE, type.toString());
	}

	// ========== Type-Specific Builder Interfaces ==========

	/**
	 * State interface for building a 'string' schema per Google AI API.
	 * 
	 * <p>
	 * String schemas support minLength, maxLength, pattern, format, and enum.
	 * Note: When enumValues() is called, format is automatically set to "enum" per
	 * Google spec.
	 * </p>
	 */
	public interface IStringSchemaBuilder extends IBuildableSchemaType,
			ICommonMetadata<IStringSchemaBuilder>,
			IGoogleSpecific<IStringSchemaBuilder>,
			IFormat<IStringSchemaBuilder>,
			IAnyOf<IStringSchemaBuilder> {

		// String-specific overloads
		IStringSchemaBuilder defaultValue(String value);

		IStringSchemaBuilder example(String value);

		// String-specific validation
		IStringSchemaBuilder minLength(int minLength);

		IStringSchemaBuilder maxLength(int maxLength);

		IStringSchemaBuilder pattern(String pattern);

		// Format (typed overload)
		IStringSchemaBuilder format(StringFormatType format);

		// Enum (auto-sets format:"enum" per Google spec)
		IStringSchemaBuilder enumValues(List<String> values);

		IStringSchemaBuilder enumValues(String... values);

		IStringSchemaBuilder enumValues(Class<? extends Enum<?>> enumClass);
	}

	/**
	 * State interface for building a 'number' schema per Google AI API.
	 * 
	 * <p>
	 * Number schemas support minimum, maximum, and format constraints.
	 * </p>
	 */
	public interface INumberSchemaBuilder extends IBuildableSchemaType,
			ICommonMetadata<INumberSchemaBuilder>,
			IGoogleSpecific<INumberSchemaBuilder>,
			IFormat<INumberSchemaBuilder>,
			IAnyOf<INumberSchemaBuilder> {

		// Number-specific overload
		INumberSchemaBuilder defaultValue(Number value);

		// Number-specific validation
		INumberSchemaBuilder minimum(BigDecimal minimum);

		INumberSchemaBuilder maximum(BigDecimal maximum);

		INumberSchemaBuilder minimum(double minimum);

		INumberSchemaBuilder maximum(double maximum);

		INumberSchemaBuilder minimum(float minimum);

		INumberSchemaBuilder maximum(float maximum);

		// Format (typed overload)
		INumberSchemaBuilder format(NumberFormatType format);
	}

	/**
	 * State interface for building an 'integer' schema per Google AI API.
	 * 
	 * <p>
	 * Integer schemas support minimum, maximum, and format constraints.
	 * </p>
	 */
	public interface IIntegerSchemaBuilder extends IBuildableSchemaType,
			ICommonMetadata<IIntegerSchemaBuilder>,
			IGoogleSpecific<IIntegerSchemaBuilder>,
			IFormat<IIntegerSchemaBuilder>,
			IAnyOf<IIntegerSchemaBuilder> {

		// Integer-specific validation
		IIntegerSchemaBuilder minimum(long minimum);

		IIntegerSchemaBuilder maximum(long maximum);

		IIntegerSchemaBuilder minimum(int minimum);

		IIntegerSchemaBuilder maximum(int maximum);

		// Format (typed overload)
		IIntegerSchemaBuilder format(IntegerFormatType format);
	}

	/**
	 * State interface for building a 'boolean' schema per Google AI API.
	 * 
	 * <p>
	 * Boolean schemas only support common metadata, nullable, example, and anyOf.
	 * </p>
	 */
	public interface IBooleanSchemaBuilder extends IBuildableSchemaType,
			ICommonMetadata<IBooleanSchemaBuilder>,
			IGoogleSpecific<IBooleanSchemaBuilder>,
			IAnyOf<IBooleanSchemaBuilder> {
		// No additional boolean-specific methods
	}

	/**
	 * State interface for building a 'null' schema per Google AI API.
	 * 
	 * <p>
	 * Null schemas only support common metadata, nullable, example, and anyOf.
	 * </p>
	 */
	public interface INullSchemaBuilder extends IBuildableSchemaType,
			ICommonMetadata<INullSchemaBuilder>,
			IGoogleSpecific<INullSchemaBuilder>,
			IAnyOf<INullSchemaBuilder> {
		// No additional null-specific methods
	}

	/**
	 * State interface for building an 'array' schema per Google AI API.
	 * 
	 * <p>
	 * Array schemas support items, minItems, and maxItems constraints.
	 * </p>
	 */
	public interface IArraySchemaBuilder extends IBuildableSchemaType,
			ICommonMetadata<IArraySchemaBuilder>,
			IGoogleSpecific<IArraySchemaBuilder>,
			IAnyOf<IArraySchemaBuilder> {

		// Array-specific validation
		IArraySchemaBuilder minItems(int minItems);

		IArraySchemaBuilder maxItems(int maxItems);

		IArraySchemaBuilder items(ObjectNode itemSchema);

		IArraySchemaBuilder items(IBuildableSchemaType itemSchemaBuilder);
	}

	/**
	 * State interface for building an 'object' schema per Google AI API.
	 * 
	 * <p>
	 * Object schemas support properties, required fields, min/maxProperties,
	 * and the Google-specific propertyOrdering field.
	 * </p>
	 */
	public interface IObjectSchemaBuilder extends IBuildableSchemaType,
			ICommonMetadata<IObjectSchemaBuilder>,
			IGoogleSpecific<IObjectSchemaBuilder>,
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

		// Google-specific: propertyOrdering
		IObjectSchemaBuilder propertyOrdering(List<String> names);

		IObjectSchemaBuilder propertyOrdering(String... names);

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

	public static INullSchemaBuilder nul(ObjectMapper customMapper) {
		return new NullBuilderImpl(customMapper);
	}

	// ========== Composition-Only Factory Method (No Base Type) ==========

	/**
	 * Creates a schema with ONLY anyOf constraint and NO base type.
	 * Use this for union types where data can match one or more of several
	 * different types.
	 * 
	 * <p>
	 * Note: Google AI API only supports anyOf (not allOf/oneOf/not per the
	 * specification).
	 * </p>
	 * 
	 * <p>
	 * Example: String OR Integer
	 * </p>
	 * 
	 * <pre>{@code
	 * JsonSchema schema = SchemaBuilder.anyOf(
	 * 		SchemaBuilder.string().minLength(10),
	 * 		SchemaBuilder.integer().minimum(0)).build();
	 * // Generates: { "anyOf": [{ "type": "string", "minLength": "10" }, { "type":
	 * // "integer", "minimum": 0 }] }
	 * }</pre>
	 * 
	 * @param schemas Schemas where at least one must match
	 * @return Untyped builder with anyOf constraint
	 */
	public static UntypedBuilderImpl anyOf(IBuildableSchemaType... schemas) {
		return new UntypedBuilderImpl(DEFAULT_MAPPER).anyOf(schemas);
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
	 * - UntypedBuilderImpl: For anyOf-only schemas (no base type)
	 * 
	 * This provides true type-state pattern where casting between types won't
	 * compile,
	 * while the trait-style capability interfaces (ICommonMetadata,
	 * IGoogleSpecific,
	 * IFormat, IAnyOf) keep the code DRY.
	 * 
	 * Google AI API-specific features:
	 * - nullable: boolean field on all types
	 * - example: singular example value (vs. Draft 7's examples array)
	 * - propertyOrdering: Google-specific array for controlling property order
	 * - format:"enum" auto-set when using string enumValues()
	 * - Numeric constraints serialized as strings per Google spec (int64 format)
	 */
}
