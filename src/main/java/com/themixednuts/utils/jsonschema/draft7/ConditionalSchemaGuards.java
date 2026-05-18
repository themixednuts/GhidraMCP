package com.themixednuts.utils.jsonschema.draft7;

import java.util.ArrayList;
import java.util.List;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

final class ConditionalSchemaGuards {
  private static final String CONST = "const";
  private static final String PROPERTIES = "properties";
  private static final String REQUIRED = "required";

  private ConditionalSchemaGuards() {}

  static ObjectNode guardConstPropertyConditions(ObjectNode ifNode) {
    ObjectNode guarded = ifNode.deepCopy();
    JsonNode propertiesNode = guarded.get(PROPERTIES);
    if (!(propertiesNode instanceof ObjectNode properties)) {
      return guarded;
    }

    List<String> constProperties = constPropertyNames(properties);
    if (constProperties.isEmpty()) {
      return guarded;
    }

    ArrayNode required = requiredArray(guarded);
    constProperties.forEach(fieldName -> appendRequiredIfMissing(required, fieldName));

    return guarded;
  }

  private static List<String> constPropertyNames(ObjectNode properties) {
    List<String> names = new ArrayList<>();
    for (var property : properties.properties()) {
      JsonNode propertySchema = property.getValue();
      if (propertySchema != null && propertySchema.get(CONST) != null) {
        names.add(property.getKey());
      }
    }
    return names;
  }

  private static ArrayNode requiredArray(ObjectNode node) {
    JsonNode existing = node.get(REQUIRED);
    if (existing instanceof ArrayNode array) {
      return array;
    }
    return node.putArray(REQUIRED);
  }

  private static void appendRequiredIfMissing(ArrayNode required, String fieldName) {
    for (JsonNode requiredName : required) {
      if (fieldName.equals(requiredName.asText())) {
        return;
      }
    }
    required.add(fieldName);
  }
}
