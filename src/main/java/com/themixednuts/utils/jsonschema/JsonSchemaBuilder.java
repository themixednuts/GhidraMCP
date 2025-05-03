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

	private final ObjectNode schema;
	private final JsonSchemaType type;

	// Private constructor enforces use of static factory methods to start the build
	// process.
	private JsonSchemaBuilder(JsonSchemaType type) {
		this.schema = DEFAULT_MAPPER.createObjectNode();
		this.type = Objects.requireNonNull(type, "Schema type cannot be null");
		this.schema.put("type", type.toString());
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
		IStringSchemaBuilder title(String title);

		IStringSchemaBuilder description(String description);

		IStringSchemaBuilder nullable(boolean nullable);

		IStringSchemaBuilder defaultValue(Object value);

		IStringSchemaBuilder example(Object value);

		IStringSchemaBuilder minLength(int minLength);

		IStringSchemaBuilder maxLength(int maxLength);

		IStringSchemaBuilder pattern(String pattern);

		IStringSchemaBuilder format(StringFormatType format);

		IStringSchemaBuilder enumValues(List<String> values);

		IStringSchemaBuilder enumValues(String... values);

		IStringSchemaBuilder anyOf(IBuildableSchemaType... schemas);

		IStringSchemaBuilder anyOf(ObjectNode... schemas);
	}

	/** State interface for building a 'number' schema. */
	public interface INumberSchemaBuilder extends IBuildableSchemaType {
		INumberSchemaBuilder title(String title);

		INumberSchemaBuilder description(String description);

		INumberSchemaBuilder nullable(boolean nullable);

		INumberSchemaBuilder defaultValue(Object value);

		INumberSchemaBuilder example(Object value);

		INumberSchemaBuilder minimum(BigDecimal minimum);

		INumberSchemaBuilder maximum(BigDecimal maximum);

		INumberSchemaBuilder minimum(double minimum);

		INumberSchemaBuilder maximum(double maximum);

		INumberSchemaBuilder format(NumberFormatType format);

		INumberSchemaBuilder anyOf(IBuildableSchemaType... schemas);

		INumberSchemaBuilder anyOf(ObjectNode... schemas);
	}

	/** State interface for building an 'integer' schema. */
	public interface IIntegerSchemaBuilder extends IBuildableSchemaType {
		IIntegerSchemaBuilder title(String title);

		IIntegerSchemaBuilder description(String description);

		IIntegerSchemaBuilder nullable(boolean nullable);

		IIntegerSchemaBuilder defaultValue(Object value);

		IIntegerSchemaBuilder example(Object value);

		IIntegerSchemaBuilder minimum(long minimum);

		IIntegerSchemaBuilder maximum(long maximum);

		IIntegerSchemaBuilder format(IntegerFormatType format);

		IIntegerSchemaBuilder anyOf(IBuildableSchemaType... schemas);

		IIntegerSchemaBuilder anyOf(ObjectNode... schemas);
	}

	/** State interface for building a 'boolean' schema. */
	public interface IBooleanSchemaBuilder extends IBuildableSchemaType {
		IBooleanSchemaBuilder title(String title);

		IBooleanSchemaBuilder description(String description);

		IBooleanSchemaBuilder nullable(boolean nullable);

		IBooleanSchemaBuilder defaultValue(Object value);

		IBooleanSchemaBuilder example(Object value);

		IBooleanSchemaBuilder anyOf(IBuildableSchemaType... schemas);

		IBooleanSchemaBuilder anyOf(ObjectNode... schemas);
	}

	/** State interface for building a 'null' schema. */
	public interface INullSchemaBuilder extends IBuildableSchemaType {
		INullSchemaBuilder title(String title);

		INullSchemaBuilder description(String description);

		INullSchemaBuilder nullable(boolean nullable);

		INullSchemaBuilder defaultValue(Object value);

		INullSchemaBuilder example(Object value);

		INullSchemaBuilder anyOf(IBuildableSchemaType... schemas);

		INullSchemaBuilder anyOf(ObjectNode... schemas);
	}

	/** State interface for building an 'array' schema. */
	public interface IArraySchemaBuilder extends IBuildableSchemaType {
		IArraySchemaBuilder title(String title);

		IArraySchemaBuilder description(String description);

		IArraySchemaBuilder nullable(boolean nullable);

		IArraySchemaBuilder defaultValue(Object value);

		IArraySchemaBuilder example(Object value);

		IArraySchemaBuilder minItems(int minItems);

		IArraySchemaBuilder maxItems(int maxItems);

		IArraySchemaBuilder items(ObjectNode itemSchema);

		IArraySchemaBuilder items(IBuildableSchemaType itemSchemaBuilder);

		IArraySchemaBuilder anyOf(IBuildableSchemaType... schemas);

		IArraySchemaBuilder anyOf(ObjectNode... schemas);
	}

	/** State interface for building an 'object' schema. */
	public interface IObjectSchemaBuilder extends IBuildableSchemaType {
		IObjectSchemaBuilder title(String title);

		IObjectSchemaBuilder description(String description);

		IObjectSchemaBuilder nullable(boolean nullable);

		IObjectSchemaBuilder defaultValue(Object value);

		IObjectSchemaBuilder example(Object value);

		IObjectSchemaBuilder property(String name, ObjectNode propertySchema);

		IObjectSchemaBuilder property(String name, ObjectNode propertySchema, boolean required);

		IObjectSchemaBuilder requiredProperty(String name);

		IObjectSchemaBuilder minProperties(int minProperties);

		IObjectSchemaBuilder maxProperties(int maxProperties);

		IObjectSchemaBuilder propertyOrdering(List<String> names);

		IObjectSchemaBuilder propertyOrdering(String... names);

		IObjectSchemaBuilder properties(Map<String, ObjectNode> propertiesMap);

		IObjectSchemaBuilder propertiesBuilders(Map<String, IBuildableSchemaType> propertiesSchemaBuilders);

		IObjectSchemaBuilder property(String name, IBuildableSchemaType propertySchemaBuilder);

		IObjectSchemaBuilder property(String name, IBuildableSchemaType propertySchemaBuilder, boolean required);

		IObjectSchemaBuilder anyOf(IBuildableSchemaType... schemas);

		IObjectSchemaBuilder anyOf(ObjectNode... schemas);
	}

	// --- Static Factory Methods (Entry Points) --- //

	public static IStringSchemaBuilder string() {
		return new BuilderStateImpl(JsonSchemaType.STRING, DEFAULT_MAPPER);
	}

	public static INumberSchemaBuilder number() {
		return new BuilderStateImpl(JsonSchemaType.NUMBER, DEFAULT_MAPPER);
	}

	public static IIntegerSchemaBuilder integer() {
		return new BuilderStateImpl(JsonSchemaType.INTEGER, DEFAULT_MAPPER);
	}

	public static IBooleanSchemaBuilder bool() { // 'boolean' is a Java keyword
		return new BuilderStateImpl(JsonSchemaType.BOOLEAN, DEFAULT_MAPPER);
	}

	public static IArraySchemaBuilder array() {
		return new BuilderStateImpl(JsonSchemaType.ARRAY, DEFAULT_MAPPER);
	}

	public static IObjectSchemaBuilder object() {
		return new BuilderStateImpl(JsonSchemaType.OBJECT, DEFAULT_MAPPER);
	}

	public static INullSchemaBuilder nul() { // 'null' is a Java keyword
		return new BuilderStateImpl(JsonSchemaType.NULL, DEFAULT_MAPPER);
	}

	// NEW Overloads using custom mapper
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
			builder.schema.put("title", title);
			return this;
		}

		@Override
		public BuilderStateImpl description(String description) {
			builder.schema.put("description", description);
			return this;
		}

		@Override
		public BuilderStateImpl nullable(boolean nullable) {
			builder.schema.put("nullable", nullable);
			return this;
		}

		private JsonNode toJsonNode(Object value) {
			// Use the instance mapper field
			return this.mapper.valueToTree(value);
		}

		@Override
		public BuilderStateImpl defaultValue(Object value) {
			builder.schema.set("default", toJsonNode(value));
			return this;
		}

		@Override
		public BuilderStateImpl example(Object value) {
			builder.schema.set("example", toJsonNode(value));
			return this;
		}

		// --- Enum Methods (Now String Specific) --- //

		@Override
		public BuilderStateImpl enumValues(List<String> values) {
			assertType(JsonSchemaType.STRING);
			Objects.requireNonNull(values, "Enum values list cannot be null");
			ArrayNode enumNode = builder.schema.putArray("enum");
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
			builder.schema.put("minLength", minLength);
			return this;
		}

		@Override
		public IStringSchemaBuilder maxLength(int maxLength) {
			assertType(JsonSchemaType.STRING);
			builder.schema.put("maxLength", maxLength);
			return this;
		}

		@Override
		public IStringSchemaBuilder pattern(String pattern) {
			assertType(JsonSchemaType.STRING);
			builder.schema.put("pattern", Objects.requireNonNull(pattern, "Pattern cannot be null"));
			return this;
		}

		// --- Number Methods --- //

		@Override
		public INumberSchemaBuilder minimum(BigDecimal minimum) {
			assertType(JsonSchemaType.NUMBER);
			builder.schema.put("minimum", Objects.requireNonNull(minimum, "Minimum cannot be null"));
			return this;
		}

		@Override
		public INumberSchemaBuilder maximum(BigDecimal maximum) {
			assertType(JsonSchemaType.NUMBER);
			builder.schema.put("maximum", Objects.requireNonNull(maximum, "Maximum cannot be null"));
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
			builder.schema.put("minimum", minimum);
			return this;
		}

		@Override
		public IIntegerSchemaBuilder maximum(long maximum) {
			assertType(JsonSchemaType.INTEGER);
			builder.schema.put("maximum", maximum);
			return this;
		}

		// +++ NEW format implementations +++
		@Override
		public IStringSchemaBuilder format(StringFormatType format) {
			assertType(JsonSchemaType.STRING);
			builder.schema.put("format", Objects.requireNonNull(format, "Format cannot be null").toString());
			return this;
		}

		@Override
		public INumberSchemaBuilder format(NumberFormatType format) {
			assertType(JsonSchemaType.NUMBER);
			builder.schema.put("format", Objects.requireNonNull(format, "Format cannot be null").toString());
			return this;
		}

		@Override
		public IIntegerSchemaBuilder format(IntegerFormatType format) {
			assertType(JsonSchemaType.INTEGER);
			builder.schema.put("format", Objects.requireNonNull(format, "Format cannot be null").toString());
			return this;
		}

		// --- Array Methods --- //

		@Override
		public IArraySchemaBuilder items(ObjectNode itemSchema) {
			assertType(JsonSchemaType.ARRAY);
			Objects.requireNonNull(itemSchema, "Item schema cannot be null for array type");
			builder.schema.set("items", itemSchema);
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
			builder.schema.put("minItems", minItems);
			return this;
		}

		@Override
		public IArraySchemaBuilder maxItems(int maxItems) {
			assertType(JsonSchemaType.ARRAY);
			builder.schema.put("maxItems", maxItems);
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
				builder.schema.set("properties", JsonNodeFactory.instance.objectNode());
			}

			// Add/replace property in map and node
			propertiesMap.put(name, propertySchema);
			((ObjectNode) builder.schema.get("properties")).set(name, propertySchema);

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
				builder.schema.set("required", JsonNodeFactory.instance.arrayNode());
			}

			// Add to list and node if not already present
			if (!requiredPropertiesList.contains(name)) {
				requiredPropertiesList.add(name);
				((ArrayNode) builder.schema.get("required")).add(name);
			}
			return this;
		}

		@Override
		public IObjectSchemaBuilder minProperties(int minProperties) {
			assertType(JsonSchemaType.OBJECT);
			builder.schema.put("minProperties", minProperties);
			return this;
		}

		@Override
		public IObjectSchemaBuilder maxProperties(int maxProperties) {
			assertType(JsonSchemaType.OBJECT);
			builder.schema.put("maxProperties", maxProperties);
			return this;
		}

		@Override
		public IObjectSchemaBuilder propertyOrdering(List<String> names) {
			assertType(JsonSchemaType.OBJECT);
			Objects.requireNonNull(names, "Property ordering list cannot be null");
			ArrayNode orderingNode = builder.schema.putArray("propertyOrdering");
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
				builder.schema.set("properties", JsonNodeFactory.instance.objectNode());
			}

			ObjectNode propertiesNode = (ObjectNode) builder.schema.get("properties");

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
			// anyOf can technically apply to any type, so no assertType needed
			Objects.requireNonNull(schemas, "anyOf schemas array cannot be null");
			if (schemas.length == 0) {
				throw new IllegalArgumentException("anyOf array cannot be empty.");
			}
			ArrayNode anyOfNode = builder.schema.putArray("anyOf");
			for (ObjectNode schema : schemas) {
				Objects.requireNonNull(schema, "Schema in anyOf array cannot be null");
				anyOfNode.add(schema);
			}
			return this;
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
						"Cannot call method for type " + expectedType + "; builder is in state " + builder.type);
			}
		}
	}
}