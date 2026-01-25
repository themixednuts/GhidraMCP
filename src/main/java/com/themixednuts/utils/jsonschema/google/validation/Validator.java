package com.themixednuts.utils.jsonschema.google.validation;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * Validator for Google AI API schemas.
 *
 * <p>Validates JSON data against Google AI API schema format, which differs from standard JSON
 * Schema:
 *
 * <ul>
 *   <li>Numeric constraints (minLength, maxItems, etc.) are STRINGS with int64 format
 *   <li>Min/max bounds (minimum, maximum) are NUMBERS
 *   <li>nullable boolean indicates if value may be null
 *   <li>Only anyOf composition keyword (no allOf/oneOf/not)
 *   <li>No conditional keywords (no if/then/else)
 * </ul>
 *
 * <p>Example usage:
 *
 * <pre>{@code
 * ObjectNode schema = ...; // Google AI API schema
 * JsonNode data = ...;     // Data to validate
 *
 * Set<ValidationMessage> errors = Validator.validate(schema, data);
 * if (errors.isEmpty()) {
 *     // Data is valid!
 * } else {
 *     // Handle validation errors
 *     errors.forEach(System.out::println);
 * }
 * }</pre>
 */
public class Validator {

  /**
   * Validates data against a Google AI API schema.
   *
   * @param schema The Google AI API schema to validate against
   * @param data The data to validate
   * @return Set of validation messages (empty if valid)
   */
  public static Set<ValidationMessage> validate(ObjectNode schema, JsonNode data) {
    return validate(schema, data, "$");
  }

  /** Internal validation method with path tracking. */
  private static Set<ValidationMessage> validate(ObjectNode schema, JsonNode data, String path) {
    Set<ValidationMessage> errors = new HashSet<>();

    // Get schema type first
    String type = schema.has("type") ? schema.get("type").asText() : null;

    // Check nullable (except for null type where null is expected)
    if (data == null || data.isNull()) {
      // If type is "null", null values are expected to pass
      if ("null".equals(type)) {
        return errors; // Valid null value for null type
      }

      // For other types, check nullable field
      if (schema.has("nullable") && schema.get("nullable").asBoolean()) {
        return errors; // null is allowed
      }
      errors.add(
          ValidationMessage.error(path, "nullable", "Value is null but nullable is not true"));
      return errors;
    }

    // No type - check anyOf
    if (type == null) {
      if (schema.has("anyOf")) {
        return validateAnyOf(schema.get("anyOf"), data, path);
      }
      // Schema without type or anyOf - always valid
      return errors;
    }

    // Validate based on type
    switch (type) {
      case "string":
        validateString(schema, data, path, errors);
        break;
      case "integer":
        validateInteger(schema, data, path, errors);
        break;
      case "number":
        validateNumber(schema, data, path, errors);
        break;
      case "boolean":
        validateBoolean(schema, data, path, errors);
        break;
      case "array":
        validateArray(schema, data, path, errors);
        break;
      case "object":
        validateObject(schema, data, path, errors);
        break;
      case "null":
        if (!data.isNull()) {
          errors.add(
              ValidationMessage.error(path, "type", "Expected null but got " + data.getNodeType()));
        }
        break;
      default:
        errors.add(ValidationMessage.error(path, "type", "Unknown type: " + type));
    }

    // Check anyOf if present (can be combined with type)
    if (schema.has("anyOf")) {
      // If anyOf is present WITH a type, data must match type AND at least one anyOf
      // schema
      Set<ValidationMessage> anyOfErrors = validateAnyOf(schema.get("anyOf"), data, path);
      errors.addAll(anyOfErrors);
    }

    return errors;
  }

  // ========== String Validation ==========

  private static void validateString(
      ObjectNode schema, JsonNode data, String path, Set<ValidationMessage> errors) {
    if (!data.isTextual()) {
      errors.add(
          ValidationMessage.error(path, "type", "Expected string but got " + data.getNodeType()));
      return;
    }

    String value = data.asText();

    // minLength (string containing int64)
    if (schema.has("minLength")) {
      try {
        long minLength = Long.parseLong(schema.get("minLength").asText());
        if (value.length() < minLength) {
          errors.add(
              ValidationMessage.error(
                  path,
                  "minLength",
                  String.format(
                      "String length %d is less than minLength %d", value.length(), minLength)));
        }
      } catch (NumberFormatException e) {
        errors.add(
            ValidationMessage.error(
                path,
                "minLength",
                "Invalid minLength format: " + schema.get("minLength").asText()));
      }
    }

    // maxLength (string containing int64)
    if (schema.has("maxLength")) {
      try {
        long maxLength = Long.parseLong(schema.get("maxLength").asText());
        if (value.length() > maxLength) {
          errors.add(
              ValidationMessage.error(
                  path,
                  "maxLength",
                  String.format(
                      "String length %d is greater than maxLength %d", value.length(), maxLength)));
        }
      } catch (NumberFormatException e) {
        errors.add(
            ValidationMessage.error(
                path,
                "maxLength",
                "Invalid maxLength format: " + schema.get("maxLength").asText()));
      }
    }

    // pattern
    if (schema.has("pattern")) {
      String patternStr = schema.get("pattern").asText();
      try {
        Pattern pattern = Pattern.compile(patternStr);
        if (!pattern.matcher(value).find()) {
          errors.add(
              ValidationMessage.error(
                  path,
                  "pattern",
                  String.format("String '%s' does not match pattern '%s'", value, patternStr)));
        }
      } catch (PatternSyntaxException e) {
        errors.add(
            ValidationMessage.error(path, "pattern", "Invalid regex pattern: " + patternStr));
      }
    }

    // enum
    if (schema.has("enum")) {
      ArrayNode enumValues = (ArrayNode) schema.get("enum");
      boolean found = false;
      for (JsonNode enumValue : enumValues) {
        if (enumValue.isTextual() && enumValue.asText().equals(value)) {
          found = true;
          break;
        }
      }
      if (!found) {
        errors.add(
            ValidationMessage.error(
                path, "enum", String.format("String '%s' is not in enum values", value)));
      }
    }
  }

  // ========== Integer Validation ==========

  private static void validateInteger(
      ObjectNode schema, JsonNode data, String path, Set<ValidationMessage> errors) {
    if (!data.isIntegralNumber()) {
      errors.add(
          ValidationMessage.error(path, "type", "Expected integer but got " + data.getNodeType()));
      return;
    }

    long value = data.asLong();

    // minimum (number)
    if (schema.has("minimum")) {
      long minimum = schema.get("minimum").asLong();
      if (value < minimum) {
        errors.add(
            ValidationMessage.error(
                path,
                "minimum",
                String.format("Integer %d is less than minimum %d", value, minimum)));
      }
    }

    // maximum (number)
    if (schema.has("maximum")) {
      long maximum = schema.get("maximum").asLong();
      if (value > maximum) {
        errors.add(
            ValidationMessage.error(
                path,
                "maximum",
                String.format("Integer %d is greater than maximum %d", value, maximum)));
      }
    }
  }

  // ========== Number Validation ==========

  private static void validateNumber(
      ObjectNode schema, JsonNode data, String path, Set<ValidationMessage> errors) {
    if (!data.isNumber()) {
      errors.add(
          ValidationMessage.error(path, "type", "Expected number but got " + data.getNodeType()));
      return;
    }

    double value = data.asDouble();

    // minimum (number)
    if (schema.has("minimum")) {
      double minimum = schema.get("minimum").asDouble();
      if (value < minimum) {
        errors.add(
            ValidationMessage.error(
                path,
                "minimum",
                String.format("Number %f is less than minimum %f", value, minimum)));
      }
    }

    // maximum (number)
    if (schema.has("maximum")) {
      double maximum = schema.get("maximum").asDouble();
      if (value > maximum) {
        errors.add(
            ValidationMessage.error(
                path,
                "maximum",
                String.format("Number %f is greater than maximum %f", value, maximum)));
      }
    }
  }

  // ========== Boolean Validation ==========

  private static void validateBoolean(
      ObjectNode schema, JsonNode data, String path, Set<ValidationMessage> errors) {
    if (!data.isBoolean()) {
      errors.add(
          ValidationMessage.error(path, "type", "Expected boolean but got " + data.getNodeType()));
    }
  }

  // ========== Array Validation ==========

  private static void validateArray(
      ObjectNode schema, JsonNode data, String path, Set<ValidationMessage> errors) {
    if (!data.isArray()) {
      errors.add(
          ValidationMessage.error(path, "type", "Expected array but got " + data.getNodeType()));
      return;
    }

    ArrayNode array = (ArrayNode) data;
    int size = array.size();

    // minItems (string containing int64)
    if (schema.has("minItems")) {
      try {
        long minItems = Long.parseLong(schema.get("minItems").asText());
        if (size < minItems) {
          errors.add(
              ValidationMessage.error(
                  path,
                  "minItems",
                  String.format("Array size %d is less than minItems %d", size, minItems)));
        }
      } catch (NumberFormatException e) {
        errors.add(
            ValidationMessage.error(
                path, "minItems", "Invalid minItems format: " + schema.get("minItems").asText()));
      }
    }

    // maxItems (string containing int64)
    if (schema.has("maxItems")) {
      try {
        long maxItems = Long.parseLong(schema.get("maxItems").asText());
        if (size > maxItems) {
          errors.add(
              ValidationMessage.error(
                  path,
                  "maxItems",
                  String.format("Array size %d is greater than maxItems %d", size, maxItems)));
        }
      } catch (NumberFormatException e) {
        errors.add(
            ValidationMessage.error(
                path, "maxItems", "Invalid maxItems format: " + schema.get("maxItems").asText()));
      }
    }

    // items - validate each item against item schema
    if (schema.has("items")) {
      ObjectNode itemSchema = (ObjectNode) schema.get("items");
      int index = 0;
      for (JsonNode item : array) {
        String itemPath = path + "[" + index + "]";
        Set<ValidationMessage> itemErrors = validate(itemSchema, item, itemPath);
        errors.addAll(itemErrors);
        index++;
      }
    }
  }

  // ========== Object Validation ==========

  private static void validateObject(
      ObjectNode schema, JsonNode data, String path, Set<ValidationMessage> errors) {
    if (!data.isObject()) {
      errors.add(
          ValidationMessage.error(path, "type", "Expected object but got " + data.getNodeType()));
      return;
    }

    ObjectNode object = (ObjectNode) data;
    int propertyCount = object.size();

    // minProperties (string containing int64)
    if (schema.has("minProperties")) {
      try {
        long minProperties = Long.parseLong(schema.get("minProperties").asText());
        if (propertyCount < minProperties) {
          errors.add(
              ValidationMessage.error(
                  path,
                  "minProperties",
                  String.format(
                      "Object has %d properties, less than minProperties %d",
                      propertyCount, minProperties)));
        }
      } catch (NumberFormatException e) {
        errors.add(
            ValidationMessage.error(
                path,
                "minProperties",
                "Invalid minProperties format: " + schema.get("minProperties").asText()));
      }
    }

    // maxProperties (string containing int64)
    if (schema.has("maxProperties")) {
      try {
        long maxProperties = Long.parseLong(schema.get("maxProperties").asText());
        if (propertyCount > maxProperties) {
          errors.add(
              ValidationMessage.error(
                  path,
                  "maxProperties",
                  String.format(
                      "Object has %d properties, greater than maxProperties %d",
                      propertyCount, maxProperties)));
        }
      } catch (NumberFormatException e) {
        errors.add(
            ValidationMessage.error(
                path,
                "maxProperties",
                "Invalid maxProperties format: " + schema.get("maxProperties").asText()));
      }
    }

    // required
    if (schema.has("required")) {
      ArrayNode required = (ArrayNode) schema.get("required");
      for (JsonNode requiredProp : required) {
        String propName = requiredProp.asText();
        if (!object.has(propName)) {
          errors.add(
              ValidationMessage.error(
                  path, "required", String.format("Required property '%s' is missing", propName)));
        }
      }
    }

    // properties - validate each property
    if (schema.has("properties")) {
      ObjectNode properties = (ObjectNode) schema.get("properties");
      Iterator<Map.Entry<String, JsonNode>> fields = object.fields();
      while (fields.hasNext()) {
        Map.Entry<String, JsonNode> field = fields.next();
        String propName = field.getKey();
        JsonNode propValue = field.getValue();

        if (properties.has(propName)) {
          ObjectNode propSchema = (ObjectNode) properties.get(propName);
          String propPath = path + "." + propName;
          Set<ValidationMessage> propErrors = validate(propSchema, propValue, propPath);
          errors.addAll(propErrors);
        }
      }
    }
  }

  // ========== anyOf Validation ==========

  private static Set<ValidationMessage> validateAnyOf(
      JsonNode anyOfNode, JsonNode data, String path) {
    Set<ValidationMessage> errors = new HashSet<>();

    if (!anyOfNode.isArray()) {
      errors.add(ValidationMessage.error(path, "anyOf", "anyOf must be an array"));
      return errors;
    }

    ArrayNode anyOfSchemas = (ArrayNode) anyOfNode;
    if (anyOfSchemas.size() == 0) {
      errors.add(ValidationMessage.error(path, "anyOf", "anyOf array cannot be empty"));
      return errors;
    }

    // Data must match at least ONE of the schemas
    boolean matched = false;
    for (JsonNode schemaNode : anyOfSchemas) {
      if (schemaNode.isObject()) {
        Set<ValidationMessage> schemaErrors = validate((ObjectNode) schemaNode, data, path);
        if (schemaErrors.isEmpty()) {
          matched = true;
          break;
        }
      }
    }

    if (!matched) {
      errors.add(
          ValidationMessage.error(path, "anyOf", "Data does not match any of the anyOf schemas"));
    }

    return errors;
  }
}
