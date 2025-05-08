package com.themixednuts.utils.jsonschema;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * A type-safe builder for creating JSON Schema objects following the Google AI
 * API specification subset.
 * 
 * <p>
 * Example Usage:
 * </p>
 * 
 * <pre>{@code
 * ObjectNode userSchema = JsonSchemaBuilder.object()
 * 		.title("User")
 * 		.description("Represents a user in the system")
 * 		.property("id", JsonSchemaBuilder.integer().format("int64").description("Unique identifier"), true)
 * 		.property("name", JsonSchemaBuilder.string().minLength(1).description("User's full name"), true)
 * 		.property("email", JsonSchemaBuilder.string().format("email").description("User's email address"))
 * 		.property("tags", JsonSchemaBuilder.array()
 * 				.items(JsonSchemaBuilder.string().description("A tag string"))
 * 				.description("Optional tags for the user")
 * 				.minItems(1)
 * 				.nullable(true))
 * 		.requiredProperty("status") // Can mark required even if property not defined yet
 * 		.property("status", JsonSchemaBuilder.string().enumValues("active", "inactive", "pending"))
 * 		.build();
 * }</pre>
 *
 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API
 *      Schema</a>
 * @see <a href="https://spec.openapis.org/oas/v3.0.3#data-types">OpenAPI 3.0.3
 *      Data Types</a>
 */
public class JsonSchemaBuilder {
	// Reusable ObjectMapper instance for value conversions. Used as default.
	static final ObjectMapper DEFAULT_MAPPER = new ObjectMapper();
	private static final String TYPE = "type";
	private static final String FORMAT = "format";
	private static final String TITLE = "title";
	private static final String DESCRIPTION = "description";
	private static final String NULLABLE = "nullable";
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
	private static final String EXAMPLE = "example";
	private static final String ANY_OF = "anyOf";
	private static final String PROPERTY_ORDERING = "propertyOrdering";
	private static final String DEFAULT = "default";
	private static final String ITEMS = "items";
	private static final String MINIMUM = "minimum";
	private static final String MAXIMUM = "maximum";

	private final ObjectNode schema;
	private final JsonSchemaType type;

	// Private constructor enforces use of static factory methods to start the build
	// process.
	private JsonSchemaBuilder(JsonSchemaType type) {
		this.schema = DEFAULT_MAPPER.createObjectNode();
		this.type = Objects.requireNonNull(type, "Schema type cannot be null");
		this.schema.put(TYPE, type.toString());
	}

	// +++ NEW Base Buildable Interface +++
	/**
	 * A base interface for any builder state that can produce a final ObjectNode
	 * schema.
	 */
	public interface IBuildableSchemaType {
		JsonSchema build();
	}

	// --- State Interfaces --- //

	/** State interface for building a 'string' schema. */
	public interface IStringSchemaBuilder extends IBuildableSchemaType {
		/**
		 * Sets the title for this schema.
		 * Corresponds to the "title" keyword in the JSON Schema specification,
		 * as used by the Google AI API.
		 *
		 * @param title The title string.
		 * @return This builder instance for chaining.
		 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
		 *      (title)</a>
		 */
		IStringSchemaBuilder title(String title);

		/**
		 * Sets the description for this schema.
		 * Corresponds to the "description" keyword in the JSON Schema specification,
		 * as used by the Google AI API.
		 *
		 * @param description The description string.
		 * @return This builder instance for chaining.
		 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
		 *      (description)</a>
		 */
		IStringSchemaBuilder description(String description);

		/**
		 * Specifies if this schema can be null.
		 * Corresponds to the "nullable" keyword in the JSON Schema specification,
		 * as used by the Google AI API.
		 *
		 * @param nullable True if null is allowed, false otherwise.
		 * @return This builder instance for chaining.
		 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
		 *      (nullable)</a>
		 */
		IStringSchemaBuilder nullable(boolean nullable);

		/**
		 * Sets the default value for this schema.
		 * Corresponds to the "default" keyword in the JSON Schema specification,
		 * as used by the Google AI API.
		 *
		 * @param value The default value.
		 * @return This builder instance for chaining.
		 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
		 *      (default)</a>
		 */
		IStringSchemaBuilder defaultValue(Object value);

		/**
		 * Sets an example value for this schema.
		 * Corresponds to the "example" keyword in the JSON Schema specification,
		 * as used by the Google AI API.
		 *
		 * @param value The example value.
		 * @return This builder instance for chaining.
		 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
		 *      (example)</a>
		 */
		IStringSchemaBuilder example(Object value);

		/**
		 * Sets the minimum length for a string type.
		 * Corresponds to the "minLength" keyword in the JSON Schema specification,
		 * as used by the Google AI API.
		 *
		 * @param minLength The minimum length.
		 * @return This builder instance for chaining.
		 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
		 *      (minLength)</a>
		 */
		IStringSchemaBuilder minLength(int minLength);

		/**
		 * Sets the maximum length for a string type.
		 * Corresponds to the "maxLength" keyword in the JSON Schema specification,
		 * as used by the Google AI API.
		 *
		 * @param maxLength The maximum length.
		 * @return This builder instance for chaining.
		 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
		 *      (maxLength)</a>
		 */
		IStringSchemaBuilder maxLength(int maxLength);

		/**
		 * Sets a regex pattern for a string type.
		 * Corresponds to the "pattern" keyword in the JSON Schema specification,
		 * as used by the Google AI API.
		 *
		 * @param pattern The regex pattern.
		 * @return This builder instance for chaining.
		 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
		 *      (pattern)</a>
		 */
		IStringSchemaBuilder pattern(String pattern);

		/**
		 * Sets the format for a string type.
		 * Corresponds to the "format" keyword in the JSON Schema specification,
		 * as used by the Google AI API.
		 *
		 * @param format The string format type.
		 * @return This builder instance for chaining.
		 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
		 *      (format)</a>
		 */
		IStringSchemaBuilder format(StringFormatType format);

		/**
		 * Sets the allowed enum values for a string type.
		 * Corresponds to the "enum" keyword in the JSON Schema specification,
		 * as used by the Google AI API.
		 *
		 * @param values A list of allowed string values.
		 * @return This builder instance for chaining.
		 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
		 *      (enum)</a>
		 */
		IStringSchemaBuilder enumValues(List<String> values);

		/**
		 * Sets the allowed enum values for a string type.
		 * Corresponds to the "enum" keyword in the JSON Schema specification,
		 * as used by the Google AI API.
		 *
		 * @param values Varargs of allowed string values.
		 * @return This builder instance for chaining.
		 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
		 *      (enum)</a>
		 */
		IStringSchemaBuilder enumValues(String... values);

		/**
		 * Specifies that the data must be valid against any of the given schemas.
		 * Corresponds to the "anyOf" keyword in the JSON Schema specification,
		 * as used by the Google AI API.
		 *
		 * @param schemas An array of schema builders. The data must validate against
		 *                at least one of the schemas built by these builders.
		 * @return This builder instance for chaining.
		 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
		 *      (anyOf)</a>
		 */
		IStringSchemaBuilder anyOf(IBuildableSchemaType... schemas);

		/**
		 * Specifies that the data must be valid against any of the given schemas.
		 * Corresponds to the "anyOf" keyword in the JSON Schema specification,
		 * as used by the Google AI API.
		 *
		 * @param schemas An array of pre-built ObjectNode schemas. The data must
		 *                validate against
		 *                at least one of these schemas.
		 * @return This builder instance for chaining.
		 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
		 *      (anyOf)</a>
		 */
		IStringSchemaBuilder anyOf(ObjectNode... schemas);

		/**
		 * Specifies that the data must be valid against any of the given schemas.
		 * Corresponds to the "anyOf" keyword in the JSON Schema specification,
		 * as used by the Google AI API.
		 *
		 * @param schemas A list of schema builders. The data must validate against
		 *                at least one of the schemas built by these builders.
		 * @return This builder instance for chaining.
		 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
		 *      (anyOf)</a>
		 */
		IStringSchemaBuilder anyOf(List<? extends IBuildableSchemaType> schemas);
	}

	/** State interface for building a 'number' schema. */
	public interface INumberSchemaBuilder extends IBuildableSchemaType {
		/**
		 * Sets the title for this schema.
		 * Corresponds to the "title" keyword in the JSON Schema specification,
		 * as used by the Google AI API.
		 *
		 * @param title The title string.
		 * @return This builder instance for chaining.
		 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
		 *      (title)</a>
		 */
		INumberSchemaBuilder title(String title);

		/**
		 * Sets the description for this schema.
		 * Corresponds to the "description" keyword in the JSON Schema specification,
		 * as used by the Google AI API.
		 *
		 * @param description The description string.
		 * @return This builder instance for chaining.
		 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
		 *      (description)</a>
		 */
		INumberSchemaBuilder description(String description);

		/**
		 * Specifies if this schema can be null.
		 * Corresponds to the "nullable" keyword in the JSON Schema specification,
		 * as used by the Google AI API.
		 *
		 * @param nullable True if null is allowed, false otherwise.
		 * @return This builder instance for chaining.
		 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
		 *      (nullable)</a>
		 */
		INumberSchemaBuilder nullable(boolean nullable);

		/**
		 * Sets the default value for this schema.
		 * Corresponds to the "default" keyword in the JSON Schema specification,
		 * as used by the Google AI API.
		 *
		 * @param value The default value.
		 * @return This builder instance for chaining.
		 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
		 *      (default)</a>
		 */
		INumberSchemaBuilder defaultValue(Object value);

		/**
		 * Sets an example value for this schema.
		 * Corresponds to the "example" keyword in the JSON Schema specification,
		 * as used by the Google AI API.
		 *
		 * @param value The example value.
		 * @return This builder instance for chaining.
		 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
		 *      (example)</a>
		 */
		INumberSchemaBuilder example(Object value);

		/**
		 * Sets the minimum value for a number type.
		 * Corresponds to the "minimum" keyword in the JSON Schema specification,
		 * as used by the Google AI API.
		 *
		 * @param minimum The minimum value.
		 * @return This builder instance for chaining.
		 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
		 *      (minimum)</a>
		 */
		INumberSchemaBuilder minimum(BigDecimal minimum);

		/**
		 * Sets the maximum value for a number type.
		 * Corresponds to the "maximum" keyword in the JSON Schema specification,
		 * as used by the Google AI API.
		 *
		 * @param maximum The maximum value.
		 * @return This builder instance for chaining.
		 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
		 *      (maximum)</a>
		 */
		INumberSchemaBuilder maximum(BigDecimal maximum);

		/**
		 * Sets the minimum value for a number type.
		 * Corresponds to the "minimum" keyword in the JSON Schema specification,
		 * as used by the Google AI API.
		 *
		 * @param minimum The minimum value.
		 * @return This builder instance for chaining.
		 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
		 *      (minimum)</a>
		 */
		INumberSchemaBuilder minimum(double minimum);

		/**
		 * Sets the maximum value for a number type.
		 * Corresponds to the "maximum" keyword in the JSON Schema specification,
		 * as used by the Google AI API.
		 *
		 * @param maximum The maximum value.
		 * @return This builder instance for chaining.
		 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
		 *      (maximum)</a>
		 */
		INumberSchemaBuilder maximum(double maximum);

		/**
		 * Sets the format for a number type.
		 * Corresponds to the "format" keyword in the JSON Schema specification,
		 * as used by the Google AI API.
		 *
		 * @param format The number format type.
		 * @return This builder instance for chaining.
		 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
		 *      (format)</a>
		 */
		INumberSchemaBuilder format(NumberFormatType format);

		/**
		 * Specifies that the data must be valid against any of the given schemas.
		 * Corresponds to the "anyOf" keyword in the JSON Schema specification,
		 * as used by the Google AI API.
		 *
		 * @param schemas An array of schema builders. The data must validate against
		 *                at least one of the schemas built by these builders.
		 * @return This builder instance for chaining.
		 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
		 *      (anyOf)</a>
		 */
		INumberSchemaBuilder anyOf(IBuildableSchemaType... schemas);

		/**
		 * Specifies that the data must be valid against any of the given schemas.
		 * Corresponds to the "anyOf" keyword in the JSON Schema specification,
		 * as used by the Google AI API.
		 *
		 * @param schemas An array of pre-built ObjectNode schemas. The data must
		 *                validate against
		 *                at least one of these schemas.
		 * @return This builder instance for chaining.
		 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
		 *      (anyOf)</a>
		 */
		INumberSchemaBuilder anyOf(ObjectNode... schemas);

		/**
		 * Specifies that the data must be valid against any of the given schemas.
		 * Corresponds to the "anyOf" keyword in the JSON Schema specification,
		 * as used by the Google AI API.
		 *
		 * @param schemas A list of schema builders. The data must validate against
		 *                at least one of the schemas built by these builders.
		 * @return This builder instance for chaining.
		 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
		 *      (anyOf)</a>
		 */
		INumberSchemaBuilder anyOf(List<? extends IBuildableSchemaType> schemas);
	}

	/** State interface for building an 'integer' schema. */
	public interface IIntegerSchemaBuilder extends IBuildableSchemaType {
		/**
		 * Sets the title for this schema.
		 * Corresponds to the "title" keyword in the JSON Schema specification,
		 * as used by the Google AI API.
		 *
		 * @param title The title string.
		 * @return This builder instance for chaining.
		 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
		 *      (title)</a>
		 */
		IIntegerSchemaBuilder title(String title);

		/**
		 * Sets the description for this schema.
		 * Corresponds to the "description" keyword in the JSON Schema specification,
		 * as used by the Google AI API.
		 *
		 * @param description The description string.
		 * @return This builder instance for chaining.
		 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
		 *      (description)</a>
		 */
		IIntegerSchemaBuilder description(String description);

		/**
		 * Specifies if this schema can be null.
		 * Corresponds to the "nullable" keyword in the JSON Schema specification,
		 * as used by the Google AI API.
		 *
		 * @param nullable True if null is allowed, false otherwise.
		 * @return This builder instance for chaining.
		 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
		 *      (nullable)</a>
		 */
		IIntegerSchemaBuilder nullable(boolean nullable);

		/**
		 * Sets the default value for this schema.
		 * Corresponds to the "default" keyword in the JSON Schema specification,
		 * as used by the Google AI API.
		 *
		 * @param value The default value.
		 * @return This builder instance for chaining.
		 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
		 *      (default)</a>
		 */
		IIntegerSchemaBuilder defaultValue(Object value);

		/**
		 * Sets an example value for this schema.
		 * Corresponds to the "example" keyword in the JSON Schema specification,
		 * as used by the Google AI API.
		 *
		 * @param value The example value.
		 * @return This builder instance for chaining.
		 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
		 *      (example)</a>
		 */
		IIntegerSchemaBuilder example(Object value);

		/**
		 * Sets the minimum value for an integer type.
		 * Corresponds to the "minimum" keyword in the JSON Schema specification,
		 * as used by the Google AI API.
		 *
		 * @param minimum The minimum value.
		 * @return This builder instance for chaining.
		 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
		 *      (minimum)</a>
		 */
		IIntegerSchemaBuilder minimum(long minimum);

		/**
		 * Sets the maximum value for an integer type.
		 * Corresponds to the "maximum" keyword in the JSON Schema specification,
		 * as used by the Google AI API.
		 *
		 * @param maximum The maximum value.
		 * @return This builder instance for chaining.
		 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
		 *      (maximum)</a>
		 */
		IIntegerSchemaBuilder maximum(long maximum);

		/**
		 * Sets the format for an integer type.
		 * Corresponds to the "format" keyword in the JSON Schema specification,
		 * as used by the Google AI API.
		 *
		 * @param format The integer format type.
		 * @return This builder instance for chaining.
		 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
		 *      (format)</a>
		 */
		IIntegerSchemaBuilder format(IntegerFormatType format);

		/**
		 * Specifies that the data must be valid against any of the given schemas.
		 * Corresponds to the "anyOf" keyword in the JSON Schema specification,
		 * as used by the Google AI API.
		 *
		 * @param schemas An array of schema builders. The data must validate against
		 *                at least one of the schemas built by these builders.
		 * @return This builder instance for chaining.
		 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
		 *      (anyOf)</a>
		 */
		IIntegerSchemaBuilder anyOf(IBuildableSchemaType... schemas);

		/**
		 * Specifies that the data must be valid against any of the given schemas.
		 * Corresponds to the "anyOf" keyword in the JSON Schema specification,
		 * as used by the Google AI API.
		 *
		 * @param schemas An array of pre-built ObjectNode schemas. The data must
		 *                validate against
		 *                at least one of these schemas.
		 * @return This builder instance for chaining.
		 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
		 *      (anyOf)</a>
		 */
		IIntegerSchemaBuilder anyOf(ObjectNode... schemas);

		/**
		 * Specifies that the data must be valid against any of the given schemas.
		 * Corresponds to the "anyOf" keyword in the JSON Schema specification,
		 * as used by the Google AI API.
		 *
		 * @param schemas A list of schema builders. The data must validate against
		 *                at least one of the schemas built by these builders.
		 * @return This builder instance for chaining.
		 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
		 *      (anyOf)</a>
		 */
		IIntegerSchemaBuilder anyOf(List<? extends IBuildableSchemaType> schemas);
	}

	/** State interface for building a 'boolean' schema. */
	public interface IBooleanSchemaBuilder extends IBuildableSchemaType {
		/**
		 * Sets the title for this schema.
		 * Corresponds to the "title" keyword in the JSON Schema specification,
		 * as used by the Google AI API.
		 *
		 * @param title The title string.
		 * @return This builder instance for chaining.
		 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
		 *      (title)</a>
		 */
		IBooleanSchemaBuilder title(String title);

		/**
		 * Sets the description for this schema.
		 * Corresponds to the "description" keyword in the JSON Schema specification,
		 * as used by the Google AI API.
		 *
		 * @param description The description string.
		 * @return This builder instance for chaining.
		 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
		 *      (description)</a>
		 */
		IBooleanSchemaBuilder description(String description);

		/**
		 * Specifies if this schema can be null.
		 * Corresponds to the "nullable" keyword in the JSON Schema specification,
		 * as used by the Google AI API.
		 *
		 * @param nullable True if null is allowed, false otherwise.
		 * @return This builder instance for chaining.
		 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
		 *      (nullable)</a>
		 */
		IBooleanSchemaBuilder nullable(boolean nullable);

		/**
		 * Sets the default value for this schema.
		 * Corresponds to the "default" keyword in the JSON Schema specification,
		 * as used by the Google AI API.
		 *
		 * @param value The default value.
		 * @return This builder instance for chaining.
		 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
		 *      (default)</a>
		 */
		IBooleanSchemaBuilder defaultValue(Object value);

		/**
		 * Sets an example value for this schema.
		 * Corresponds to the "example" keyword in the JSON Schema specification,
		 * as used by the Google AI API.
		 *
		 * @param value The example value.
		 * @return This builder instance for chaining.
		 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
		 *      (example)</a>
		 */
		IBooleanSchemaBuilder example(Object value);

		/**
		 * Specifies that the data must be valid against any of the given schemas.
		 * Corresponds to the "anyOf" keyword in the JSON Schema specification,
		 * as used by the Google AI API.
		 *
		 * @param schemas An array of schema builders. The data must validate against
		 *                at least one of the schemas built by these builders.
		 * @return This builder instance for chaining.
		 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
		 *      (anyOf)</a>
		 */
		IBooleanSchemaBuilder anyOf(IBuildableSchemaType... schemas);

		/**
		 * Specifies that the data must be valid against any of the given schemas.
		 * Corresponds to the "anyOf" keyword in the JSON Schema specification,
		 * as used by the Google AI API.
		 *
		 * @param schemas An array of pre-built ObjectNode schemas. The data must
		 *                validate against
		 *                at least one of these schemas.
		 * @return This builder instance for chaining.
		 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
		 *      (anyOf)</a>
		 */
		IBooleanSchemaBuilder anyOf(ObjectNode... schemas);

		/**
		 * Specifies that the data must be valid against any of the given schemas.
		 * Corresponds to the "anyOf" keyword in the JSON Schema specification,
		 * as used by the Google AI API.
		 *
		 * @param schemas A list of schema builders. The data must validate against
		 *                at least one of the schemas built by these builders.
		 * @return This builder instance for chaining.
		 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
		 *      (anyOf)</a>
		 */
		IBooleanSchemaBuilder anyOf(List<? extends IBuildableSchemaType> schemas);
	}

	/** State interface for building a 'null' schema. */
	public interface INullSchemaBuilder extends IBuildableSchemaType {
		/**
		 * Sets the title for this schema.
		 * Corresponds to the "title" keyword in the JSON Schema specification,
		 * as used by the Google AI API.
		 *
		 * @param title The title string.
		 * @return This builder instance for chaining.
		 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
		 *      (title)</a>
		 */
		INullSchemaBuilder title(String title);

		/**
		 * Sets the description for this schema.
		 * Corresponds to the "description" keyword in the JSON Schema specification,
		 * as used by the Google AI API.
		 *
		 * @param description The description string.
		 * @return This builder instance for chaining.
		 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
		 *      (description)</a>
		 */
		INullSchemaBuilder description(String description);

		/**
		 * Specifies if this schema can be null.
		 * Corresponds to the "nullable" keyword in the JSON Schema specification,
		 * as used by the Google AI API.
		 * Note: For a 'null' type schema, this is typically true.
		 *
		 * @param nullable True if null is allowed, false otherwise.
		 * @return This builder instance for chaining.
		 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
		 *      (nullable)</a>
		 */
		INullSchemaBuilder nullable(boolean nullable);

		/**
		 * Sets the default value for this schema.
		 * Corresponds to the "default" keyword in the JSON Schema specification,
		 * as used by the Google AI API.
		 * Note: For a 'null' type schema, the default would typically be null if
		 * specified.
		 *
		 * @param value The default value (should be null for 'null' type).
		 * @return This builder instance for chaining.
		 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
		 *      (default)</a>
		 */
		INullSchemaBuilder defaultValue(Object value);

		/**
		 * Sets an example value for this schema.
		 * Corresponds to the "example" keyword in the JSON Schema specification,
		 * as used by the Google AI API.
		 * Note: For a 'null' type schema, the example would typically be null if
		 * specified.
		 *
		 * @param value The example value (should be null for 'null' type).
		 * @return This builder instance for chaining.
		 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
		 *      (example)</a>
		 */
		INullSchemaBuilder example(Object value);

		/**
		 * Specifies that the data must be valid against any of the given schemas.
		 * Corresponds to the "anyOf" keyword in the JSON Schema specification,
		 * as used by the Google AI API.
		 *
		 * @param schemas An array of schema builders. The data must validate against
		 *                at least one of the schemas built by these builders.
		 * @return This builder instance for chaining.
		 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
		 *      (anyOf)</a>
		 */
		INullSchemaBuilder anyOf(IBuildableSchemaType... schemas);

		/**
		 * Specifies that the data must be valid against any of the given schemas.
		 * Corresponds to the "anyOf" keyword in the JSON Schema specification,
		 * as used by the Google AI API.
		 *
		 * @param schemas An array of pre-built ObjectNode schemas. The data must
		 *                validate against
		 *                at least one of these schemas.
		 * @return This builder instance for chaining.
		 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
		 *      (anyOf)</a>
		 */
		INullSchemaBuilder anyOf(ObjectNode... schemas);

		/**
		 * Specifies that the data must be valid against any of the given schemas.
		 * Corresponds to the "anyOf" keyword in the JSON Schema specification,
		 * as used by the Google AI API.
		 *
		 * @param schemas A list of schema builders. The data must validate against
		 *                at least one of the schemas built by these builders.
		 * @return This builder instance for chaining.
		 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
		 *      (anyOf)</a>
		 */
		INullSchemaBuilder anyOf(List<? extends IBuildableSchemaType> schemas);
	}

	/** State interface for building an 'array' schema. */
	public interface IArraySchemaBuilder extends IBuildableSchemaType {
		/**
		 * Sets the title for this schema.
		 * Corresponds to the "title" keyword in the JSON Schema specification,
		 * as used by the Google AI API.
		 *
		 * @param title The title string.
		 * @return This builder instance for chaining.
		 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
		 *      (title)</a>
		 */
		IArraySchemaBuilder title(String title);

		/**
		 * Sets the description for this schema.
		 * Corresponds to the "description" keyword in the JSON Schema specification,
		 * as used by the Google AI API.
		 *
		 * @param description The description string.
		 * @return This builder instance for chaining.
		 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
		 *      (description)</a>
		 */
		IArraySchemaBuilder description(String description);

		/**
		 * Specifies if this schema can be null.
		 * Corresponds to the "nullable" keyword in the JSON Schema specification,
		 * as used by the Google AI API.
		 *
		 * @param nullable True if null is allowed, false otherwise.
		 * @return This builder instance for chaining.
		 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
		 *      (nullable)</a>
		 */
		IArraySchemaBuilder nullable(boolean nullable);

		/**
		 * Sets the default value for this schema.
		 * Corresponds to the "default" keyword in the JSON Schema specification,
		 * as used by the Google AI API.
		 *
		 * @param value The default value (e.g., an array).
		 * @return This builder instance for chaining.
		 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
		 *      (default)</a>
		 */
		IArraySchemaBuilder defaultValue(Object value);

		/**
		 * Sets an example value for this schema.
		 * Corresponds to the "example" keyword in the JSON Schema specification,
		 * as used by the Google AI API.
		 *
		 * @param value The example value (e.g., an array).
		 * @return This builder instance for chaining.
		 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
		 *      (example)</a>
		 */
		IArraySchemaBuilder example(Object value);

		/**
		 * Sets the minimum number of items for an array type.
		 * Corresponds to the "minItems" keyword in the JSON Schema specification,
		 * as used by the Google AI API.
		 *
		 * @param minItems The minimum number of items.
		 * @return This builder instance for chaining.
		 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
		 *      (minItems)</a>
		 */
		IArraySchemaBuilder minItems(int minItems);

		/**
		 * Sets the maximum number of items for an array type.
		 * Corresponds to the "maxItems" keyword in the JSON Schema specification,
		 * as used by the Google AI API.
		 *
		 * @param maxItems The maximum number of items.
		 * @return This builder instance for chaining.
		 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
		 *      (maxItems)</a>
		 */
		IArraySchemaBuilder maxItems(int maxItems);

		/**
		 * Specifies the schema for the items in this array.
		 * Corresponds to the "items" keyword in the JSON Schema specification,
		 * as used by the Google AI API.
		 *
		 * @param itemSchema The pre-built ObjectNode schema for the array items.
		 * @return This builder instance for chaining.
		 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
		 *      (items)</a>
		 */
		IArraySchemaBuilder items(ObjectNode itemSchema);

		/**
		 * Specifies the schema for the items in this array using a schema builder.
		 * Corresponds to the "items" keyword in the JSON Schema specification,
		 * as used by the Google AI API.
		 *
		 * @param itemSchemaBuilder A builder for the schema of the array items.
		 * @return This builder instance for chaining.
		 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
		 *      (items)</a>
		 */
		IArraySchemaBuilder items(IBuildableSchemaType itemSchemaBuilder);

		/**
		 * Specifies that the data must be valid against any of the given schemas.
		 * Corresponds to the "anyOf" keyword in the JSON Schema specification,
		 * as used by the Google AI API.
		 *
		 * @param schemas An array of schema builders. The data must validate against
		 *                at least one of the schemas built by these builders.
		 * @return This builder instance for chaining.
		 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
		 *      (anyOf)</a>
		 */
		IArraySchemaBuilder anyOf(IBuildableSchemaType... schemas);

		/**
		 * Specifies that the data must be valid against any of the given schemas.
		 * Corresponds to the "anyOf" keyword in the JSON Schema specification,
		 * as used by the Google AI API.
		 *
		 * @param schemas An array of pre-built ObjectNode schemas. The data must
		 *                validate against
		 *                at least one of these schemas.
		 * @return This builder instance for chaining.
		 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
		 *      (anyOf)</a>
		 */
		IArraySchemaBuilder anyOf(ObjectNode... schemas);

		/**
		 * Specifies that the data must be valid against any of the given schemas.
		 * Corresponds to the "anyOf" keyword in the JSON Schema specification,
		 * as used by the Google AI API.
		 *
		 * @param schemas A list of schema builders. The data must validate against
		 *                at least one of the schemas built by these builders.
		 * @return This builder instance for chaining.
		 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
		 *      (anyOf)</a>
		 */
		IArraySchemaBuilder anyOf(List<? extends IBuildableSchemaType> schemas);
	}

	/** State interface for building an 'object' schema. */
	public interface IObjectSchemaBuilder extends IBuildableSchemaType {
		/**
		 * Sets the title for this schema.
		 * Corresponds to the "title" keyword in the JSON Schema specification,
		 * as used by the Google AI API.
		 *
		 * @param title The title string.
		 * @return This builder instance for chaining.
		 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
		 *      (title)</a>
		 */
		IObjectSchemaBuilder title(String title);

		/**
		 * Sets the description for this schema.
		 * Corresponds to the "description" keyword in the JSON Schema specification,
		 * as used by the Google AI API.
		 *
		 * @param description The description string.
		 * @return This builder instance for chaining.
		 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
		 *      (description)</a>
		 */
		IObjectSchemaBuilder description(String description);

		/**
		 * Specifies if this schema can be null.
		 * Corresponds to the "nullable" keyword in the JSON Schema specification,
		 * as used by the Google AI API.
		 *
		 * @param nullable True if null is allowed, false otherwise.
		 * @return This builder instance for chaining.
		 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
		 *      (nullable)</a>
		 */
		IObjectSchemaBuilder nullable(boolean nullable);

		/**
		 * Sets the default value for this schema.
		 * Corresponds to the "default" keyword in the JSON Schema specification,
		 * as used by the Google AI API.
		 *
		 * @param value The default value (e.g., an object).
		 * @return This builder instance for chaining.
		 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
		 *      (default)</a>
		 */
		IObjectSchemaBuilder defaultValue(Object value);

		/**
		 * Adds a property to this object schema.
		 * Corresponds to the "properties" keyword in the JSON Schema specification,
		 * as used by the Google AI API. This version defaults to the property not being
		 * required.
		 *
		 * @param name           The name of the property.
		 * @param propertySchema The pre-built ObjectNode schema definition for this
		 *                       property.
		 * @return This builder instance for chaining.
		 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
		 *      (properties)</a>
		 */
		IObjectSchemaBuilder property(String name, ObjectNode propertySchema);

		/**
		 * Adds a property to this object schema and optionally marks it as required.
		 * Corresponds to the "properties" and "required" keywords in the JSON Schema
		 * specification,
		 * as used by the Google AI API.
		 *
		 * @param name           The name of the property.
		 * @param propertySchema The pre-built ObjectNode schema definition for this
		 *                       property.
		 * @param required       True if this property should be required, false
		 *                       otherwise.
		 * @return This builder instance for chaining.
		 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
		 *      (properties, required)</a>
		 */
		IObjectSchemaBuilder property(String name, ObjectNode propertySchema, boolean required);

		IObjectSchemaBuilder requiredProperty(String name);

		/**
		 * Sets the minimum number of properties for an object type.
		 * Corresponds to the "minProperties" keyword in the JSON Schema specification,
		 * as used by the Google AI API.
		 *
		 * @param minProperties The minimum number of properties.
		 * @return This builder instance for chaining.
		 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
		 *      (minProperties)</a>
		 */
		IObjectSchemaBuilder minProperties(int minProperties);

		/**
		 * Sets the maximum number of properties for an object type.
		 * Corresponds to the "maxProperties" keyword in the JSON Schema specification,
		 * as used by the Google AI API.
		 *
		 * @param maxProperties The maximum number of properties.
		 * @return This builder instance for chaining.
		 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
		 *      (maxProperties)</a>
		 */
		IObjectSchemaBuilder maxProperties(int maxProperties);

		/**
		 * Specifies the preferred order of properties for an object type.
		 * Corresponds to the "propertyOrdering" keyword in the JSON Schema
		 * specification,
		 * as used by the Google AI API.
		 *
		 * @param names A list of property names in the desired order.
		 * @return This builder instance for chaining.
		 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
		 *      (propertyOrdering)</a>
		 */
		IObjectSchemaBuilder propertyOrdering(List<String> names);

		/**
		 * Specifies the preferred order of properties for an object type.
		 * Corresponds to the "propertyOrdering" keyword in the JSON Schema
		 * specification,
		 * as used by the Google AI API.
		 *
		 * @param names Varargs of property names in the desired order.
		 * @return This builder instance for chaining.
		 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
		 *      (propertyOrdering)</a>
		 */
		IObjectSchemaBuilder propertyOrdering(String... names);

		/**
		 * Adds multiple properties to this object schema using a map of property names
		 * to pre-built ObjectNode schemas.
		 * Corresponds to the "properties" keyword in the JSON Schema specification,
		 * as used by the Google AI API.
		 *
		 * @param propertiesMap A map where keys are property names and values are their
		 *                      ObjectNode schema definitions.
		 * @return This builder instance for chaining.
		 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
		 *      (properties)</a>
		 */
		IObjectSchemaBuilder properties(Map<String, ObjectNode> propertiesMap);

		/**
		 * Specifies that the data must be valid against any of the given schemas.
		 * Corresponds to the "anyOf" keyword in the JSON Schema specification,
		 * as used by the Google AI API.
		 *
		 * @param schemas An array of schema builders. The data must validate against
		 *                at least one of the schemas built by these builders.
		 * @return This builder instance for chaining.
		 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
		 *      (anyOf)</a>
		 */
		IObjectSchemaBuilder anyOf(IBuildableSchemaType... schemas);

		/**
		 * Specifies that the data must be valid against any of the given schemas.
		 * Corresponds to the "anyOf" keyword in the JSON Schema specification,
		 * as used by the Google AI API.
		 *
		 * @param schemas An array of pre-built ObjectNode schemas. The data must
		 *                validate against
		 *                at least one of these schemas.
		 * @return This builder instance for chaining.
		 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
		 *      (anyOf)</a>
		 */
		IObjectSchemaBuilder anyOf(ObjectNode... schemas);

		/**
		 * Specifies that the data must be valid against any of the given schemas.
		 * Corresponds to the "anyOf" keyword in the JSON Schema specification,
		 * as used by the Google AI API.
		 *
		 * @param schemas A list of schema builders. The data must validate against
		 *                at least one of the schemas built by these builders.
		 * @return This builder instance for chaining.
		 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
		 *      (anyOf)</a>
		 */
		IObjectSchemaBuilder anyOf(List<? extends IBuildableSchemaType> schemas);

		/**
		 * Adds multiple properties to this object schema using a map of property names
		 * to schema builders.
		 * Corresponds to the "properties" keyword in the JSON Schema specification,
		 * as used by the Google AI API.
		 *
		 * @param propertiesSchemaBuilders A map where keys are property names and
		 *                                 values are builders
		 *                                 for the schema definitions of these
		 *                                 properties.
		 * @return This builder instance for chaining.
		 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
		 *      (properties)</a>
		 */
		IObjectSchemaBuilder propertiesBuilders(Map<String, IBuildableSchemaType> propertiesSchemaBuilders);

		/**
		 * Adds a property to this object schema using a schema builder.
		 * Corresponds to the "properties" keyword in the JSON Schema specification,
		 * as used by the Google AI API. This version defaults to the property not being
		 * required.
		 *
		 * @param name                  The name of the property.
		 * @param propertySchemaBuilder A builder for the schema definition of this
		 *                              property.
		 * @return This builder instance for chaining.
		 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
		 *      (properties)</a>
		 */
		IObjectSchemaBuilder property(String name, IBuildableSchemaType propertySchemaBuilder);

		/**
		 * Adds a property to this object schema using a schema builder and optionally
		 * marks it as required.
		 * Corresponds to the "properties" and "required" keywords in the JSON Schema
		 * specification,
		 * as used by the Google AI API.
		 *
		 * @param name                  The name of the property.
		 * @param propertySchemaBuilder A builder for the schema definition of this
		 *                              property.
		 * @param required              True if this property should be required, false
		 *                              otherwise.
		 * @return This builder instance for chaining.
		 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
		 *      (properties, required)</a>
		 */
		IObjectSchemaBuilder property(String name, IBuildableSchemaType propertySchemaBuilder, boolean required);
	}

	// --- Static Factory Methods (Entry Points) --- //

	/**
	 * Starts building a 'string' type JSON schema using the default ObjectMapper.
	 *
	 * @return A new {@link IStringSchemaBuilder} instance.
	 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
	 *      (type: string)</a>
	 */
	public static IStringSchemaBuilder string() {
		return new BuilderStateImpl(JsonSchemaType.STRING, DEFAULT_MAPPER);
	}

	/**
	 * Starts building a 'number' type JSON schema using the default ObjectMapper.
	 *
	 * @return A new {@link INumberSchemaBuilder} instance.
	 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
	 *      (type: number)</a>
	 */
	public static INumberSchemaBuilder number() {
		return new BuilderStateImpl(JsonSchemaType.NUMBER, DEFAULT_MAPPER);
	}

	/**
	 * Starts building an 'integer' type JSON schema using the default ObjectMapper.
	 *
	 * @return A new {@link IIntegerSchemaBuilder} instance.
	 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
	 *      (type: integer)</a>
	 */
	public static IIntegerSchemaBuilder integer() {
		return new BuilderStateImpl(JsonSchemaType.INTEGER, DEFAULT_MAPPER);
	}

	/**
	 * Starts building a 'boolean' type JSON schema using the default ObjectMapper.
	 *
	 * @return A new {@link IBooleanSchemaBuilder} instance.
	 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
	 *      (type: boolean)</a>
	 */
	public static IBooleanSchemaBuilder bool() { // 'boolean' is a Java keyword
		return new BuilderStateImpl(JsonSchemaType.BOOLEAN, DEFAULT_MAPPER);
	}

	/**
	 * Starts building an 'array' type JSON schema using the default ObjectMapper.
	 *
	 * @return A new {@link IArraySchemaBuilder} instance.
	 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
	 *      (type: array)</a>
	 */
	public static IArraySchemaBuilder array() {
		return new BuilderStateImpl(JsonSchemaType.ARRAY, DEFAULT_MAPPER);
	}

	/**
	 * Starts building an 'object' type JSON schema using the default ObjectMapper.
	 *
	 * @return A new {@link IObjectSchemaBuilder} instance.
	 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
	 *      (type: object)</a>
	 */
	public static IObjectSchemaBuilder object() {
		return new BuilderStateImpl(JsonSchemaType.OBJECT, DEFAULT_MAPPER);
	}

	/**
	 * Starts building a 'null' type JSON schema using the default ObjectMapper.
	 *
	 * @return A new {@link INullSchemaBuilder} instance.
	 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
	 *      (type: null)</a>
	 */
	public static INullSchemaBuilder nul() { // 'null' is a Java keyword
		return new BuilderStateImpl(JsonSchemaType.NULL, DEFAULT_MAPPER);
	}

	// NEW Overloads using custom mapper
	/**
	 * Starts building a 'string' type JSON schema using a custom ObjectMapper.
	 *
	 * @param customMapper The ObjectMapper to use for value conversions.
	 * @return A new {@link IStringSchemaBuilder} instance.
	 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
	 *      (type: string)</a>
	 */
	public static IStringSchemaBuilder string(ObjectMapper customMapper) {
		return new BuilderStateImpl(JsonSchemaType.STRING, customMapper);
	}

	/**
	 * Starts building a 'number' type JSON schema using a custom ObjectMapper.
	 *
	 * @param customMapper The ObjectMapper to use for value conversions.
	 * @return A new {@link INumberSchemaBuilder} instance.
	 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
	 *      (type: number)</a>
	 */
	public static INumberSchemaBuilder number(ObjectMapper customMapper) {
		return new BuilderStateImpl(JsonSchemaType.NUMBER, customMapper);
	}

	/**
	 * Starts building an 'integer' type JSON schema using a custom ObjectMapper.
	 *
	 * @param customMapper The ObjectMapper to use for value conversions.
	 * @return A new {@link IIntegerSchemaBuilder} instance.
	 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
	 *      (type: integer)</a>
	 */
	public static IIntegerSchemaBuilder integer(ObjectMapper customMapper) {
		return new BuilderStateImpl(JsonSchemaType.INTEGER, customMapper);
	}

	/**
	 * Starts building a 'boolean' type JSON schema using a custom ObjectMapper.
	 *
	 * @param customMapper The ObjectMapper to use for value conversions.
	 * @return A new {@link IBooleanSchemaBuilder} instance.
	 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
	 *      (type: boolean)</a>
	 */
	public static IBooleanSchemaBuilder bool(ObjectMapper customMapper) {
		return new BuilderStateImpl(JsonSchemaType.BOOLEAN, customMapper);
	}

	/**
	 * Starts building an 'array' type JSON schema using a custom ObjectMapper.
	 *
	 * @param customMapper The ObjectMapper to use for value conversions.
	 * @return A new {@link IArraySchemaBuilder} instance.
	 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
	 *      (type: array)</a>
	 */
	public static IArraySchemaBuilder array(ObjectMapper customMapper) {
		return new BuilderStateImpl(JsonSchemaType.ARRAY, customMapper);
	}

	/**
	 * Starts building an 'object' type JSON schema using a custom ObjectMapper.
	 *
	 * @param customMapper The ObjectMapper to use for value conversions.
	 * @return A new {@link IObjectSchemaBuilder} instance.
	 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
	 *      (type: object)</a>
	 */
	public static IObjectSchemaBuilder object(ObjectMapper customMapper) {
		return new BuilderStateImpl(JsonSchemaType.OBJECT, customMapper);
	}

	/**
	 * Starts building a 'null' type JSON schema using a custom ObjectMapper.
	 *
	 * @param customMapper The ObjectMapper to use for value conversions.
	 * @return A new {@link INullSchemaBuilder} instance.
	 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema
	 *      (type: null)</a>
	 */
	public static INullSchemaBuilder nul(ObjectMapper customMapper) {
		return new BuilderStateImpl(JsonSchemaType.NULL, customMapper);
	}

	// --- Implementation Class (Handles State Transitions) --- //

	private static class BuilderStateImpl implements
			IStringSchemaBuilder, INumberSchemaBuilder, IIntegerSchemaBuilder, IBooleanSchemaBuilder,
			IArraySchemaBuilder, IObjectSchemaBuilder, INullSchemaBuilder {

		private final JsonSchemaBuilder builder;
		private Map<String, ObjectNode> propertiesMap = null;
		private List<String> requiredPropertiesList = null;
		// Field to hold the mapper for this instance
		private final ObjectMapper mapper;

		BuilderStateImpl(JsonSchemaType type, ObjectMapper mapper) {
			this.builder = new JsonSchemaBuilder(type);
			this.mapper = mapper;
		}

		// --- Common Methods --- //

		@Override
		public BuilderStateImpl title(String title) {
			builder.schema.put(TITLE, title);
			return this;
		}

		@Override
		public BuilderStateImpl description(String description) {
			builder.schema.put(DESCRIPTION, description);
			return this;
		}

		@Override
		public BuilderStateImpl nullable(boolean nullable) {
			builder.schema.put(NULLABLE, nullable);
			return this;
		}

		private JsonNode toJsonNode(Object value) {
			// Use the instance mapper field
			return this.mapper.valueToTree(value);
		}

		@Override
		public BuilderStateImpl defaultValue(Object value) {
			builder.schema.set(DEFAULT, toJsonNode(value));
			return this;
		}

		@Override
		public BuilderStateImpl example(Object value) {
			builder.schema.set(EXAMPLE, toJsonNode(value));
			return this;
		}

		// --- Enum Methods (Now String Specific) --- //

		@Override
		public BuilderStateImpl enumValues(List<String> values) {
			assertType(JsonSchemaType.STRING);
			Objects.requireNonNull(values, "Enum values list cannot be null");
			ArrayNode enumNode = builder.schema.putArray(ENUM);
			values.forEach(v -> enumNode.add(Objects.requireNonNull(v, "Enum value cannot be null")));
			return this;
		}

		@Override
		public BuilderStateImpl enumValues(String... values) {
			assertType(JsonSchemaType.STRING);
			return enumValues(Arrays.asList(values));
		}

		// --- String Methods --- //

		@Override
		public IStringSchemaBuilder minLength(int minLength) {
			assertType(JsonSchemaType.STRING);
			builder.schema.put(MIN_LENGTH, minLength);
			return this;
		}

		@Override
		public IStringSchemaBuilder maxLength(int maxLength) {
			assertType(JsonSchemaType.STRING);
			builder.schema.put(MAX_LENGTH, maxLength);
			return this;
		}

		@Override
		public IStringSchemaBuilder pattern(String pattern) {
			assertType(JsonSchemaType.STRING);
			builder.schema.put(PATTERN, Objects.requireNonNull(pattern, "Pattern cannot be null"));
			return this;
		}

		// --- Number Methods --- //

		@Override
		public INumberSchemaBuilder minimum(BigDecimal minimum) {
			assertType(JsonSchemaType.NUMBER);
			builder.schema.put(MINIMUM, Objects.requireNonNull(minimum, "Minimum cannot be null"));
			return this;
		}

		@Override
		public INumberSchemaBuilder maximum(BigDecimal maximum) {
			assertType(JsonSchemaType.NUMBER);
			builder.schema.put(MAXIMUM, Objects.requireNonNull(maximum, "Maximum cannot be null"));
			return this;
		}

		@Override
		public INumberSchemaBuilder minimum(double minimum) {
			return minimum(BigDecimal.valueOf(minimum));
		}

		@Override
		public INumberSchemaBuilder maximum(double maximum) {
			return maximum(BigDecimal.valueOf(maximum));
		}

		// --- Integer Methods --- //

		@Override
		public IIntegerSchemaBuilder minimum(long minimum) {
			assertType(JsonSchemaType.INTEGER);
			builder.schema.put(MINIMUM, minimum);
			return this;
		}

		@Override
		public IIntegerSchemaBuilder maximum(long maximum) {
			assertType(JsonSchemaType.INTEGER);
			builder.schema.put(MAXIMUM, maximum);
			return this;
		}

		// +++ NEW format implementations +++
		@Override
		public IStringSchemaBuilder format(StringFormatType format) {
			assertType(JsonSchemaType.STRING);
			builder.schema.put(FORMAT, Objects.requireNonNull(format, "Format cannot be null").toString());
			return this;
		}

		@Override
		public INumberSchemaBuilder format(NumberFormatType format) {
			assertType(JsonSchemaType.NUMBER);
			builder.schema.put(FORMAT, Objects.requireNonNull(format, "Format cannot be null").toString());
			return this;
		}

		@Override
		public IIntegerSchemaBuilder format(IntegerFormatType format) {
			assertType(JsonSchemaType.INTEGER);
			builder.schema.put(FORMAT, Objects.requireNonNull(format, "Format cannot be null").toString());
			return this;
		}

		// --- Array Methods --- //

		@Override
		public IArraySchemaBuilder items(ObjectNode itemSchema) {
			assertType(JsonSchemaType.ARRAY);
			Objects.requireNonNull(itemSchema, "Item schema cannot be null for array type");
			builder.schema.set(ITEMS, itemSchema);
			return this;
		}

		@Override
		public IArraySchemaBuilder items(IBuildableSchemaType itemSchemaBuilder) {
			Objects.requireNonNull(itemSchemaBuilder, "Item schema builder cannot be null");
			// Build the schema and delegate to the original items method
			return items(itemSchemaBuilder.build().getNode());
		}

		@Override
		public IArraySchemaBuilder minItems(int minItems) {
			assertType(JsonSchemaType.ARRAY);
			builder.schema.put(MIN_ITEMS, minItems);
			return this;
		}

		@Override
		public IArraySchemaBuilder maxItems(int maxItems) {
			assertType(JsonSchemaType.ARRAY);
			builder.schema.put(MAX_ITEMS, maxItems);
			return this;
		}

		// --- Object Methods --- //

		@Override
		public IObjectSchemaBuilder property(String name, ObjectNode propertySchema) {
			return property(name, propertySchema, false); // Default to not required
		}

		@Override
		public IObjectSchemaBuilder property(String name, IBuildableSchemaType propertySchemaBuilder) {
			Objects.requireNonNull(propertySchemaBuilder, "Property schema builder cannot be null");
			return property(name, propertySchemaBuilder.build().getNode(), false);
		}

		@Override
		public IObjectSchemaBuilder property(String name, ObjectNode propertySchema, boolean required) {
			assertType(JsonSchemaType.OBJECT);
			Objects.requireNonNull(name, "Property name cannot be null");
			Objects.requireNonNull(propertySchema, "Property schema cannot be null");

			// Initialize properties structure if first property
			if (propertiesMap == null) {
				propertiesMap = new LinkedHashMap<>();
				builder.schema.set(PROPERTIES, JsonNodeFactory.instance.objectNode());
			}

			// Add/replace property in map and node
			propertiesMap.put(name, propertySchema);
			((ObjectNode) builder.schema.get(PROPERTIES)).set(name, propertySchema);

			if (required) {
				requiredProperty(name);
			}
			return this;
		}

		@Override
		public IObjectSchemaBuilder property(String name, IBuildableSchemaType propertySchemaBuilder, boolean required) {
			Objects.requireNonNull(propertySchemaBuilder, "Property schema builder cannot be null");
			return property(name, propertySchemaBuilder.build().getNode(), required);
		}

		@Override
		public IObjectSchemaBuilder requiredProperty(String name) {
			assertType(JsonSchemaType.OBJECT);
			Objects.requireNonNull(name, "Required property name cannot be null");

			// Initialize required structure if first required property
			if (requiredPropertiesList == null) {
				requiredPropertiesList = new ArrayList<>();
				builder.schema.set(REQUIRED, JsonNodeFactory.instance.arrayNode());
			}

			// Add to list and node if not already present
			if (!requiredPropertiesList.contains(name)) {
				requiredPropertiesList.add(name);
				((ArrayNode) builder.schema.get(REQUIRED)).add(name);
			}
			return this;
		}

		@Override
		public IObjectSchemaBuilder minProperties(int minProperties) {
			assertType(JsonSchemaType.OBJECT);
			builder.schema.put(MIN_PROPERTIES, minProperties);
			return this;
		}

		@Override
		public IObjectSchemaBuilder maxProperties(int maxProperties) {
			assertType(JsonSchemaType.OBJECT);
			builder.schema.put(MAX_PROPERTIES, maxProperties);
			return this;
		}

		@Override
		public IObjectSchemaBuilder propertyOrdering(List<String> names) {
			assertType(JsonSchemaType.OBJECT);
			Objects.requireNonNull(names, "Property ordering list cannot be null");
			ArrayNode orderingNode = builder.schema.putArray(PROPERTY_ORDERING);
			names.forEach(orderingNode::add);
			return this;
		}

		@Override
		public IObjectSchemaBuilder propertyOrdering(String... names) {
			return propertyOrdering(Arrays.asList(names));
		}

		// Add the implementation for the new properties map method
		@Override
		public IObjectSchemaBuilder properties(Map<String, ObjectNode> propertiesMap) {
			assertType(JsonSchemaType.OBJECT);
			Objects.requireNonNull(propertiesMap, "Properties map cannot be null");

			// Initialize properties structure if necessary
			if (this.propertiesMap == null) {
				this.propertiesMap = new LinkedHashMap<>();
				builder.schema.set(PROPERTIES, JsonNodeFactory.instance.objectNode());
			}

			ObjectNode propertiesNode = (ObjectNode) builder.schema.get(PROPERTIES);

			for (Map.Entry<String, ObjectNode> entry : propertiesMap.entrySet()) {
				String name = entry.getKey();
				ObjectNode propertySchema = entry.getValue();
				Objects.requireNonNull(name, "Property name in map cannot be null");
				Objects.requireNonNull(propertySchema, "Property schema for key '" + name + "' in map cannot be null");
				this.propertiesMap.put(name, propertySchema);
				propertiesNode.set(name, propertySchema);
			}
			return this;
		}

		// +++ NEW Implementation for propertiesBuilders +++
		@Override
		public IObjectSchemaBuilder propertiesBuilders(Map<String, IBuildableSchemaType> propertiesSchemaBuilders) {
			assertType(JsonSchemaType.OBJECT);
			Objects.requireNonNull(propertiesSchemaBuilders, "Properties builders map cannot be null");
			// Build each schema in the map
			Map<String, ObjectNode> builtProperties = new LinkedHashMap<>();
			for (Map.Entry<String, IBuildableSchemaType> entry : propertiesSchemaBuilders.entrySet()) {
				Objects.requireNonNull(entry.getValue(),
						"Property schema builder for key '" + entry.getKey() + "' cannot be null");
				builtProperties.put(entry.getKey(), entry.getValue().build().getNode());
			}
			// Delegate to the original properties method
			return properties(builtProperties);
		}

		// --- anyOf Implementation --- //

		@Override
		public BuilderStateImpl anyOf(IBuildableSchemaType... schemas) {
			Objects.requireNonNull(schemas, "anyOf schemas array cannot be null");
			ObjectNode[] builtSchemas = Arrays.stream(schemas)
					.map(s -> {
						Objects.requireNonNull(s, "Schema in anyOf array cannot be null");
						return s.build().getNode();
					})
					.toArray(ObjectNode[]::new);
			return anyOf(builtSchemas);
		}

		@Override
		public BuilderStateImpl anyOf(ObjectNode... schemas) {
			Objects.requireNonNull(schemas, "anyOf schemas array cannot be null");
			if (schemas.length == 0) {
				throw new IllegalArgumentException("anyOf array cannot be empty.");
			}
			ArrayNode anyOfNode = builder.schema.putArray(ANY_OF);
			for (ObjectNode schema : schemas) {
				Objects.requireNonNull(schema, "Schema in anyOf array cannot be null");
				anyOfNode.add(schema);
			}
			return this;
		}

		// Corrected implementation for List variant, now matching the interface
		// signature
		@Override
		public BuilderStateImpl anyOf(List<? extends IBuildableSchemaType> schemas) { // Matches interface
			Objects.requireNonNull(schemas, "anyOf schemas list cannot be null");
			if (schemas.isEmpty()) {
				throw new IllegalArgumentException("anyOf list cannot be empty.");
			}
			// Convert the list to an array of IBuildableSchemaType and delegate to varargs
			// version
			return anyOf(schemas.toArray(new IBuildableSchemaType[0]));
		}

		// --- Build Method --- //

		@Override
		public JsonSchema build() {
			// Return a new JsonSchema instance, which handles defensive copying internally.
			return new JsonSchema(builder.schema);
		}

		// --- Helper Methods --- //

		private void assertType(JsonSchemaType expectedType) {
			if (builder.type != expectedType) {
				throw new IllegalStateException(
						"Cannot call method for type " + expectedType + "; builder is for type " + builder.type);
			}
		}
	}
}