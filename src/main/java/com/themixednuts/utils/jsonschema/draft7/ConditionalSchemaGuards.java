package com.themixednuts.utils.jsonschema.draft7;

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

    ArrayNode[] required = new ArrayNode[1];
    properties.forEachEntry(
        (fieldName, propertySchema) -> {
          if (propertySchema != null && propertySchema.get(CONST) != null) {
            if (required[0] == null) {
              required[0] = requiredArray(guarded);
            }
            appendRequiredIfMissing(required[0], fieldName);
          }
        });

    return guarded;
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
