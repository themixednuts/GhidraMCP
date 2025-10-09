package com.themixednuts.utils.jsonschema.draft7;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.themixednuts.utils.jsonschema.IBuildableSchemaType;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaType;

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

	/** State interface for building a 'string' schema (JSON Schema Draft 7). */
	public interface IStringSchemaBuilder extends IBuildableSchemaType {
		IStringSchemaBuilder title(String title);

		IStringSchemaBuilder description(String description);

		IStringSchemaBuilder defaultValue(Object value);

		IStringSchemaBuilder defaultValue(String value);

		IStringSchemaBuilder minLength(int minLength);

		IStringSchemaBuilder maxLength(int maxLength);

		IStringSchemaBuilder pattern(String pattern);

		IStringSchemaBuilder enumValues(List<String> values);

		IStringSchemaBuilder enumValues(String... values);

		IStringSchemaBuilder enumValues(Class<? extends Enum<?>> enumClass);

		IStringSchemaBuilder anyOf(IBuildableSchemaType... schemas);

		IStringSchemaBuilder anyOf(ObjectNode... schemas);

		IStringSchemaBuilder anyOf(List<? extends IBuildableSchemaType> schemas);
	}

	/** State interface for building a 'number' schema (JSON Schema Draft 7). */
	public interface INumberSchemaBuilder extends IBuildableSchemaType {
		INumberSchemaBuilder title(String title);

		INumberSchemaBuilder description(String description);

		INumberSchemaBuilder defaultValue(Object value);

		INumberSchemaBuilder defaultValue(Number value);

		INumberSchemaBuilder minimum(BigDecimal minimum);

		INumberSchemaBuilder maximum(BigDecimal maximum);

		INumberSchemaBuilder minimum(double minimum);

		INumberSchemaBuilder maximum(double maximum);

		INumberSchemaBuilder minimum(float minimum);

		INumberSchemaBuilder maximum(float maximum);

		INumberSchemaBuilder anyOf(IBuildableSchemaType... schemas);

		INumberSchemaBuilder anyOf(ObjectNode... schemas);

		INumberSchemaBuilder anyOf(List<? extends IBuildableSchemaType> schemas);
	}

	/** State interface for building an 'integer' schema (JSON Schema Draft 7). */
	public interface IIntegerSchemaBuilder extends IBuildableSchemaType {
		IIntegerSchemaBuilder title(String title);

		IIntegerSchemaBuilder description(String description);

		IIntegerSchemaBuilder defaultValue(Object value);

		IIntegerSchemaBuilder minimum(long minimum);

		IIntegerSchemaBuilder maximum(long maximum);

		IIntegerSchemaBuilder minimum(int minimum);

		IIntegerSchemaBuilder maximum(int maximum);

		IIntegerSchemaBuilder anyOf(IBuildableSchemaType... schemas);

		IIntegerSchemaBuilder anyOf(ObjectNode... schemas);

		IIntegerSchemaBuilder anyOf(List<? extends IBuildableSchemaType> schemas);
	}

	/** State interface for building a 'boolean' schema (JSON Schema Draft 7). */
	public interface IBooleanSchemaBuilder extends IBuildableSchemaType {
		IBooleanSchemaBuilder title(String title);

		IBooleanSchemaBuilder description(String description);

		IBooleanSchemaBuilder defaultValue(Object value);

		IBooleanSchemaBuilder anyOf(IBuildableSchemaType... schemas);

		IBooleanSchemaBuilder anyOf(ObjectNode... schemas);

		IBooleanSchemaBuilder anyOf(List<? extends IBuildableSchemaType> schemas);
	}

	/** State interface for building a 'null' schema (JSON Schema Draft 7). */
	public interface INullSchemaBuilder extends IBuildableSchemaType {
		INullSchemaBuilder title(String title);

		INullSchemaBuilder description(String description);

		INullSchemaBuilder defaultValue(Object value);

		INullSchemaBuilder anyOf(IBuildableSchemaType... schemas);

		INullSchemaBuilder anyOf(ObjectNode... schemas);

		INullSchemaBuilder anyOf(List<? extends IBuildableSchemaType> schemas);
	}

	/** State interface for building an 'array' schema (JSON Schema Draft 7). */
	public interface IArraySchemaBuilder extends IBuildableSchemaType {
		IArraySchemaBuilder title(String title);

		IArraySchemaBuilder description(String description);

		IArraySchemaBuilder defaultValue(Object value);

		IArraySchemaBuilder minItems(int minItems);

		IArraySchemaBuilder maxItems(int maxItems);

		IArraySchemaBuilder items(ObjectNode itemSchema);

		IArraySchemaBuilder items(IBuildableSchemaType itemSchemaBuilder);

		IArraySchemaBuilder itemsAnyOf(List<? extends IBuildableSchemaType> schemas);

		IArraySchemaBuilder anyOf(IBuildableSchemaType... schemas);

		IArraySchemaBuilder anyOf(ObjectNode... schemas);

		IArraySchemaBuilder anyOf(List<? extends IBuildableSchemaType> schemas);
	}

	/**
	 * Base interface for building an 'object' schema (JSON Schema Draft 7).
	 */
	public interface IObjectSchemaBuilder extends IBuildableSchemaType {
		IObjectSchemaBuilder title(String title);

		IObjectSchemaBuilder description(String description);

		IObjectSchemaBuilder defaultValue(Object value);

		IObjectSchemaBuilder property(String name, ObjectNode propertySchema);

		IObjectSchemaBuilder property(String name, ObjectNode propertySchema, boolean required);

		IObjectSchemaBuilder property(String name, IBuildableSchemaType propertySchemaBuilder);

		IObjectSchemaBuilder property(String name, IBuildableSchemaType propertySchemaBuilder, boolean required);

		IObjectSchemaBuilder requiredProperty(String name);

		IObjectSchemaBuilder minProperties(int minProperties);

		IObjectSchemaBuilder maxProperties(int maxProperties);

		IObjectSchemaBuilder properties(Map<String, ObjectNode> propertiesMap);

		IObjectSchemaBuilder propertiesBuilders(Map<String, IBuildableSchemaType> propertiesSchemaBuilders);

		IObjectSchemaBuilder anyOf(IBuildableSchemaType... schemas);

		IObjectSchemaBuilder anyOf(ObjectNode... schemas);

		IObjectSchemaBuilder anyOf(List<? extends IBuildableSchemaType> schemas);
	}

	/**
	 * Extended object schema builder with JSON Schema Draft 7 conditional features.
	 * Adds support for if/then/else conditional validation.
	 */
	public interface IJsonSchemaDraft7ObjectSchemaBuilder extends IObjectSchemaBuilder {
		/**
		 * Adds multiple conditional requirements using JSON Schema Draft 7 if/then
		 * syntax.
		 * 
		 * @param conditionals Variable args of ConditionalSpec objects
		 * @return This builder instance for chaining
		 */
		IJsonSchemaDraft7ObjectSchemaBuilder addConditionals(ConditionalSpec... conditionals);
	}

	// Factory methods
	public static IStringSchemaBuilder string() {
		return new BuilderStateImpl(JsonSchemaType.STRING, DEFAULT_MAPPER);
	}

	public static INumberSchemaBuilder number() {
		return new BuilderStateImpl(JsonSchemaType.NUMBER, DEFAULT_MAPPER);
	}

	public static IIntegerSchemaBuilder integer() {
		return new BuilderStateImpl(JsonSchemaType.INTEGER, DEFAULT_MAPPER);
	}

	public static IBooleanSchemaBuilder bool() {
		return new BuilderStateImpl(JsonSchemaType.BOOLEAN, DEFAULT_MAPPER);
	}

	public static IArraySchemaBuilder array() {
		return new BuilderStateImpl(JsonSchemaType.ARRAY, DEFAULT_MAPPER);
	}

	public static IObjectSchemaBuilder object() {
		return new BuilderStateImpl(JsonSchemaType.OBJECT, DEFAULT_MAPPER);
	}

	public static INullSchemaBuilder nul() {
		return new BuilderStateImpl(JsonSchemaType.NULL, DEFAULT_MAPPER);
	}

	public static IStringSchemaBuilder string(ObjectMapper customMapper) {
		return new BuilderStateImpl(JsonSchemaType.STRING, customMapper);
	}

	public static INumberSchemaBuilder number(ObjectMapper customMapper) {
		return new BuilderStateImpl(JsonSchemaType.NUMBER, customMapper);
	}

	public static IIntegerSchemaBuilder integer(ObjectMapper customMapper) {
		return new BuilderStateImpl(JsonSchemaType.INTEGER, customMapper);
	}

	public static IBooleanSchemaBuilder bool(ObjectMapper customMapper) {
		return new BuilderStateImpl(JsonSchemaType.BOOLEAN, customMapper);
	}

	public static IArraySchemaBuilder array(ObjectMapper customMapper) {
		return new BuilderStateImpl(JsonSchemaType.ARRAY, customMapper);
	}

	public static IObjectSchemaBuilder object(ObjectMapper customMapper) {
		return new BuilderStateImpl(JsonSchemaType.OBJECT, customMapper);
	}

	/**
	 * Starts building an 'object' type JSON schema with JSON Schema Draft 7
	 * features.
	 * This builder supports conditional requirements via if/then/else clauses.
	 */
	public static IJsonSchemaDraft7ObjectSchemaBuilder objectDraft7() {
		return new BuilderStateImpl(JsonSchemaType.OBJECT, DEFAULT_MAPPER);
	}

	/**
	 * Starts building an 'object' type JSON schema with JSON Schema Draft 7
	 * features.
	 */
	public static IJsonSchemaDraft7ObjectSchemaBuilder objectDraft7(ObjectMapper customMapper) {
		return new BuilderStateImpl(JsonSchemaType.OBJECT, customMapper);
	}

	public static INullSchemaBuilder nul(ObjectMapper customMapper) {
		return new BuilderStateImpl(JsonSchemaType.NULL, customMapper);
	}

	private static class BuilderStateImpl implements
			IStringSchemaBuilder, INumberSchemaBuilder, IIntegerSchemaBuilder, IBooleanSchemaBuilder,
			IArraySchemaBuilder, IJsonSchemaDraft7ObjectSchemaBuilder, INullSchemaBuilder {

		private final SchemaBuilder builder;
		private Map<String, ObjectNode> propertiesMap = null;
		private List<String> requiredPropertiesList = null;
		private final ObjectMapper mapper;

		BuilderStateImpl(JsonSchemaType type, ObjectMapper mapper) {
			this.builder = new SchemaBuilder(type);
			this.mapper = mapper;
		}

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

		private JsonNode toJsonNode(Object value) {
			return this.mapper.valueToTree(value);
		}

		@Override
		public BuilderStateImpl defaultValue(Object value) {
			builder.schema.set(DEFAULT, toJsonNode(value));
			return this;
		}

		@Override
		public IStringSchemaBuilder defaultValue(String value) {
			return defaultValue((Object) value);
		}

		@Override
		public INumberSchemaBuilder defaultValue(Number value) {
			return defaultValue((Object) value);
		}

		@Override
		public BuilderStateImpl enumValues(List<String> values) {
			assertType(JsonSchemaType.STRING);
			Objects.requireNonNull(values, "Enum values list cannot be null");
			if (values.isEmpty()) {
				throw new IllegalArgumentException("Enum values list cannot be empty");
			}
			ArrayNode enumNode = builder.schema.putArray(ENUM);
			values.forEach(v -> enumNode.add(Objects.requireNonNull(v, "Enum value cannot be null")));
			return this;
		}

		@Override
		public BuilderStateImpl enumValues(String... values) {
			assertType(JsonSchemaType.STRING);
			Objects.requireNonNull(values, "Enum values array cannot be null");
			if (values.length == 0) {
				throw new IllegalArgumentException("Enum values array cannot be empty");
			}
			ArrayNode enumNode = builder.schema.putArray(ENUM);
			for (String value : values) {
				enumNode.add(Objects.requireNonNull(value, "Enum value cannot be null"));
			}
			return this;
		}

		@Override
		public IStringSchemaBuilder enumValues(Class<? extends Enum<?>> enumClass) {
			assertType(JsonSchemaType.STRING);
			Objects.requireNonNull(enumClass, "Enum class cannot be null");
			Enum<?>[] constants = enumClass.getEnumConstants();
			if (constants == null) {
				throw new IllegalArgumentException(enumClass.getName() + " is not an enum type or has no constants.");
			}
			if (constants.length == 0) {
				throw new IllegalArgumentException(enumClass.getName() + " has no enum constants.");
			}
			ArrayNode enumNode = builder.schema.putArray(ENUM);
			for (Enum<?> constant : constants) {
				enumNode.add(constant.name());
			}
			return this;
		}

		@Override
		public IStringSchemaBuilder minLength(int minLength) {
			assertType(JsonSchemaType.STRING);
			if (minLength < 0) {
				throw new IllegalArgumentException("minLength cannot be negative: " + minLength);
			}
			builder.schema.put(MIN_LENGTH, minLength);
			return this;
		}

		@Override
		public IStringSchemaBuilder maxLength(int maxLength) {
			assertType(JsonSchemaType.STRING);
			if (maxLength < 0) {
				throw new IllegalArgumentException("maxLength cannot be negative: " + maxLength);
			}
			builder.schema.put(MAX_LENGTH, maxLength);
			return this;
		}

		@Override
		public IStringSchemaBuilder pattern(String pattern) {
			assertType(JsonSchemaType.STRING);
			builder.schema.put(PATTERN, Objects.requireNonNull(pattern, "Pattern cannot be null"));
			return this;
		}

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

		@Override
		public INumberSchemaBuilder minimum(float minimum) {
			return minimum(BigDecimal.valueOf(minimum));
		}

		@Override
		public INumberSchemaBuilder maximum(float maximum) {
			return maximum(BigDecimal.valueOf(maximum));
		}

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

		@Override
		public IIntegerSchemaBuilder minimum(int minimum) {
			return minimum((long) minimum);
		}

		@Override
		public IIntegerSchemaBuilder maximum(int maximum) {
			return maximum((long) maximum);
		}

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
			return items(itemSchemaBuilder.build().getNode());
		}

		@Override
		public IArraySchemaBuilder minItems(int minItems) {
			assertType(JsonSchemaType.ARRAY);
			if (minItems < 0) {
				throw new IllegalArgumentException("minItems cannot be negative: " + minItems);
			}
			builder.schema.put(MIN_ITEMS, minItems);
			return this;
		}

		@Override
		public IArraySchemaBuilder maxItems(int maxItems) {
			assertType(JsonSchemaType.ARRAY);
			if (maxItems < 0) {
				throw new IllegalArgumentException("maxItems cannot be negative: " + maxItems);
			}
			builder.schema.put(MAX_ITEMS, maxItems);
			return this;
		}

		@Override
		public IArraySchemaBuilder itemsAnyOf(List<? extends IBuildableSchemaType> schemas) {
			assertType(JsonSchemaType.ARRAY);
			Objects.requireNonNull(schemas, "itemsAnyOf schemas list cannot be null");
			if (schemas.isEmpty()) {
				throw new IllegalArgumentException("itemsAnyOf schemas list cannot be empty.");
			}

			List<ObjectNode> subSchemaNodes = new ArrayList<>();
			for (IBuildableSchemaType schemaBuilder : schemas) {
				Objects.requireNonNull(schemaBuilder, "Schema builder in itemsAnyOf list cannot be null");
				subSchemaNodes.add(schemaBuilder.build().getNode());
			}

			IObjectSchemaBuilder itemsObjectSchemaBuilder = SchemaBuilder.object(this.mapper);
			itemsObjectSchemaBuilder.anyOf(subSchemaNodes.toArray(new ObjectNode[0]));

			builder.schema.set(ITEMS, itemsObjectSchemaBuilder.build().getNode());
			return this;
		}

		@Override
		public IObjectSchemaBuilder property(String name, ObjectNode propertySchema) {
			return property(name, propertySchema, false);
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

			if (propertiesMap == null) {
				propertiesMap = new LinkedHashMap<>();
				builder.schema.set(PROPERTIES, JsonNodeFactory.instance.objectNode());
			}

			propertiesMap.put(name, propertySchema);
			((ObjectNode) builder.schema.get(PROPERTIES)).set(name, propertySchema);

			if (required) {
				requiredProperty(name);
			}
			return this;
		}

		@Override
		public IObjectSchemaBuilder property(String name, IBuildableSchemaType propertySchemaBuilder,
				boolean required) {
			Objects.requireNonNull(propertySchemaBuilder, "Property schema builder cannot be null");
			return property(name, propertySchemaBuilder.build().getNode(), required);
		}

		@Override
		public IObjectSchemaBuilder requiredProperty(String name) {
			assertType(JsonSchemaType.OBJECT);
			Objects.requireNonNull(name, "Required property name cannot be null");

			if (requiredPropertiesList == null) {
				requiredPropertiesList = new ArrayList<>();
				builder.schema.set(REQUIRED, JsonNodeFactory.instance.arrayNode());
			}

			if (!requiredPropertiesList.contains(name)) {
				requiredPropertiesList.add(name);
				((ArrayNode) builder.schema.get(REQUIRED)).add(name);
			}
			return this;
		}

		@Override
		public IObjectSchemaBuilder minProperties(int minProperties) {
			assertType(JsonSchemaType.OBJECT);
			if (minProperties < 0) {
				throw new IllegalArgumentException("minProperties cannot be negative: " + minProperties);
			}
			builder.schema.put(MIN_PROPERTIES, minProperties);
			return this;
		}

		@Override
		public IObjectSchemaBuilder maxProperties(int maxProperties) {
			assertType(JsonSchemaType.OBJECT);
			if (maxProperties < 0) {
				throw new IllegalArgumentException("maxProperties cannot be negative: " + maxProperties);
			}
			builder.schema.put(MAX_PROPERTIES, maxProperties);
			return this;
		}

		@Override
		public IObjectSchemaBuilder properties(Map<String, ObjectNode> propertiesMap) {
			assertType(JsonSchemaType.OBJECT);
			Objects.requireNonNull(propertiesMap, "Properties map cannot be null");

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

		@Override
		public IObjectSchemaBuilder propertiesBuilders(Map<String, IBuildableSchemaType> propertiesSchemaBuilders) {
			assertType(JsonSchemaType.OBJECT);
			Objects.requireNonNull(propertiesSchemaBuilders, "Properties builders map cannot be null");
			Map<String, ObjectNode> builtProperties = new LinkedHashMap<>();
			for (Map.Entry<String, IBuildableSchemaType> entry : propertiesSchemaBuilders.entrySet()) {
				Objects.requireNonNull(entry.getValue(),
						"Property schema builder for key '" + entry.getKey() + "' cannot be null");
				builtProperties.put(entry.getKey(), entry.getValue().build().getNode());
			}
			return properties(builtProperties);
		}

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

		@Override
		public BuilderStateImpl anyOf(List<? extends IBuildableSchemaType> schemas) {
			Objects.requireNonNull(schemas, "anyOf schemas list cannot be null");
			if (schemas.isEmpty()) {
				throw new IllegalArgumentException("anyOf list cannot be empty.");
			}
			return anyOf(schemas.toArray(new IBuildableSchemaType[0]));
		}

		@Override
		public IJsonSchemaDraft7ObjectSchemaBuilder addConditionals(ConditionalSpec... conditionals) {
			assertType(JsonSchemaType.OBJECT);
			Objects.requireNonNull(conditionals, "Conditionals array cannot be null");

			if (conditionals.length == 0) {
				return this;
			}

			ArrayNode allOf = (ArrayNode) builder.schema.get("allOf");
			if (allOf == null) {
				allOf = builder.schema.putArray("allOf");
			}

			for (ConditionalSpec spec : conditionals) {
				Objects.requireNonNull(spec, "ConditionalSpec cannot be null");

				ObjectNode condition = allOf.addObject();

				condition.putObject("if")
						.putObject("properties")
						.putObject(spec.getIfProperty())
						.put("const", spec.getIfValue().toString());

				ArrayNode thenReq = condition.putObject("then").putArray("required");
				for (String field : spec.getThenRequired()) {
					thenReq.add(field);
				}
			}

			return this;
		}

		@Override
		public JsonSchema build() {
			return new JsonSchema(builder.schema);
		}

		private void assertType(JsonSchemaType expectedType) {
			if (builder.type != expectedType) {
				throw new IllegalStateException(
						"Cannot call method for type " + expectedType + "; builder is for type " + builder.type);
			}
		}
	}
}