// Schema-Driven Test Configuration Generator
// @category Testing

package com.themixednuts.headless;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.utils.jsonschema.JsonSchema;
import ghidra.program.model.address.Address;
import org.everit.json.schema.Schema;
import org.everit.json.schema.ValidationException;
import org.everit.json.schema.loader.SchemaLoader;
import org.json.JSONObject;
import org.json.JSONTokener;

import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Generates test configurations from JSON schemas with parameter combinations.
 * Focused on deterministic, schema-driven testing (not fuzzing).
 */
public class SchemaTestGenerator {

    private static final ObjectMapper mapper = new ObjectMapper();
    private static final AtomicInteger uniqueCounter = new AtomicInteger(0);
    private ghidra.app.script.GhidraScript debugScript; // For logging

    public void setDebugScript(ghidra.app.script.GhidraScript script) {
        this.debugScript = script;
    }

    private void log(String message) {
        if (debugScript != null) {
            debugScript.println("[DEBUG] " + message);
        } else {
            System.out.println("[DEBUG] " + message);
        }
    }

    /**
     * Test configuration with arguments and metadata.
     */
    public static class TestConfig {
        public final Map<String, Object> args;
        public final String description;

        public TestConfig(Map<String, Object> args, String description) {
            this.args = args;
            this.description = description;
        }
    }

    /**
     * Represents conditional requirements from if/then schema clauses.
     */
    private static class ConditionalRequirements {
        Set<String> additionalRequired = new HashSet<>();
        Set<String> forbidden = new HashSet<>();
    }

    /**
     * Check if args satisfy anyOf requirements from JSON Schema Draft 7.
     * Returns true if no anyOf exists, or if at least one anyOf sub-schema is
     * satisfied.
     */
    private boolean satisfiesAnyOf(Map<String, Object> args, JsonNode schemaNode) {
        JsonNode anyOfNode = schemaNode.get("anyOf");
        if (anyOfNode == null || !anyOfNode.isArray()) {
            return true; // No anyOf constraint, satisfied by default
        }

        // Check if at least one anyOf sub-schema is satisfied
        for (JsonNode subSchema : anyOfNode) {
            JsonNode requiredNode = subSchema.get("required");
            if (requiredNode != null && requiredNode.isArray()) {
                // Check if all required fields in this sub-schema are present in args
                boolean allPresent = true;
                for (JsonNode fieldNode : requiredNode) {
                    String fieldName = fieldNode.asText();
                    if (!args.containsKey(fieldName) || args.get(fieldName) == null) {
                        allPresent = false;
                        break;
                    }
                }
                if (allPresent) {
                    return true; // At least one sub-schema is satisfied
                }
            }
        }

        return false; // None of the anyOf sub-schemas are satisfied
    }

    /**
     * Generate test configurations for a tool based on its schema.
     * Creates configs for all actions/modes with all required parameters.
     */
    public List<TestConfig> generateConfigs(IGhidraMcpSpecification tool,
            TestDataFactory.TestDataContext testData) {
        List<TestConfig> configs = new ArrayList<>();

        try {
            String toolClassName = tool.getClass().getSimpleName();
            // log("Starting config generation for tool: " + toolClassName);

            JsonSchema jsonSchema = tool.schema();
            if (jsonSchema == null) {
                log("Schema is null, returning empty configs");
                return configs;
            }

            // Get the actual schema ObjectNode (not the wrapper)
            JsonNode schemaNode = jsonSchema.getNode();

            JsonNode properties = schemaNode.get("properties");
            JsonNode required = schemaNode.get("required");

            if (properties == null) {
                log("Schema has no properties, returning empty configs");
                return configs;
            }

            Set<String> requiredFields = extractRequired(required);
            // log("Required fields: " + requiredFields);
            // log("Total properties in schema: " + properties.size());

            // Parse conditional schemas to understand valid combinations
            Map<String, ConditionalRequirements> conditionalReqs = parseConditionalRequirements(schemaNode);
            // log("Parsed conditional requirements: " + conditionalReqs.size() + "
            // conditions");

            // Find the primary conditional field (e.g., "action" or "target_type")
            String primaryConditionalField = findPrimaryConditionalField(properties, conditionalReqs);

            if (primaryConditionalField != null) {
                // log("Conditional-based tool detected with primary field: " +
                // primaryConditionalField);
                JsonNode conditionalProp = properties.get(primaryConditionalField);
                JsonNode conditionalEnum = conditionalProp.get("enum");

                // Generate configs for ALL enum values with schema-valid combinations
                for (JsonNode enumValueNode : conditionalEnum) {
                    String enumValue = enumValueNode.asText();
                    // log("Generating configs for " + primaryConditionalField + "=" + enumValue);

                    // Start with base required fields
                    Set<String> valueRequiredFields = new HashSet<>(requiredFields);

                    // Add conditional requirements for this enum value
                    ConditionalRequirements valueCondReqs = conditionalReqs
                            .get(primaryConditionalField + "=" + enumValue);
                    if (valueCondReqs != null) {
                        valueRequiredFields.addAll(valueCondReqs.additionalRequired);
                        // log(" " + primaryConditionalField + "='" + enumValue + "' has additional
                        // requirements: "
                        // + valueCondReqs.additionalRequired);
                    }

                    // Check for nested conditionals (e.g., data_type_kind within an action)
                    // Exclude the primary field itself from being considered nested
                    Set<String> nestedConditionalFields = findNestedConditionalFields(properties, conditionalReqs,
                            valueRequiredFields, primaryConditionalField);

                    if (!nestedConditionalFields.isEmpty()) {
                        // log(" Found nested conditional fields: " + nestedConditionalFields);
                        // Generate configs for each nested conditional value
                        generateNestedConditionalConfigs(configs, enumValue, properties, valueRequiredFields,
                                nestedConditionalFields, conditionalReqs, testData, primaryConditionalField);
                    } else {
                        // No nested conditionals - generate simple power set
                        List<String> optionalParams = new ArrayList<>(
                                getOptionalParams(properties, valueRequiredFields));
                        List<Set<String>> combinations = powerSet(optionalParams);
                        // log(" Generating " + combinations.size() + " combinations for " +
                        // primaryConditionalField + "="
                        // + enumValue);

                        for (Set<String> combination : combinations) {
                            Map<String, Object> args = buildArgs(enumValue, properties, valueRequiredFields,
                                    combination, testData, primaryConditionalField);
                            // Skip if required fields couldn't be generated
                            if (args == null) {
                                continue;
                            }
                            // Skip if anyOf requirements are not met
                            if (!satisfiesAnyOf(args, schemaNode)) {
                                continue;
                            }
                            String description = buildDescription(enumValue, combination, args);
                            configs.add(new TestConfig(args, description));
                        }
                    }
                }
            } else {
                // Single configuration tool - test ALL combinations
                // log("Non-action tool detected");
                List<String> optionalParams = new ArrayList<>(getOptionalParams(properties, requiredFields));
                // log("Optional params: " + optionalParams);

                List<Set<String>> combinations = powerSet(optionalParams);
                // log("Generated " + combinations.size() + " combinations from power set");

                for (Set<String> combination : combinations) {
                    Map<String, Object> args = new LinkedHashMap<>();
                    boolean hasAllRequiredFields = true;

                    // Add all required params
                    for (String field : requiredFields) {
                        if (field.equals("fileName")) {
                            continue;
                        }
                        JsonNode prop = properties.get(field);
                        if (prop != null) {
                            Object value = generateValue(field, prop, testData, args, toolClassName);
                            if (value != null) {
                                args.put(field, value);
                            } else {
                                // Required field couldn't be generated (e.g., resource doesn't exist)
                                hasAllRequiredFields = false;
                                break;
                            }
                        }
                    }

                    // Skip this config if required fields are missing
                    if (!hasAllRequiredFields) {
                        continue;
                    }

                    // Add this combination of optional params
                    for (String optionalParam : combination) {
                        JsonNode prop = properties.get(optionalParam);
                        if (prop != null) {
                            Object value = generateValue(optionalParam, prop, testData, args, toolClassName);
                            if (value != null) {
                                args.put(optionalParam, value);
                            }
                        }
                    }

                    // Skip if anyOf requirements are not met
                    if (!satisfiesAnyOf(args, schemaNode)) {
                        continue;
                    }

                    // Generate descriptive name
                    String description = combination.isEmpty() ? "base" : "[" + String.join(", ", combination) + "]";

                    configs.add(new TestConfig(args, description));
                }
            }

        } catch (Exception e) {
            log("EXCEPTION during config generation: " + e.getMessage());
            if (debugScript != null) {
                e.printStackTrace();
            }
        }

        // log("Total configs generated: " + configs.size());

        // Debug: Always should have at least some configs
        if (configs.isEmpty()) {
            log("WARNING: No configs generated. Schema might be empty or invalid.");
        }

        return configs;
    }

    /**
     * Validate a config against a schema using org.everit validator.
     */
    public ValidationResult validate(TestConfig config, JsonSchema jsonSchema) {
        try {
            // Get the actual schema ObjectNode and serialize it
            String schemaJson = mapper.writeValueAsString(jsonSchema.getNode());
            String configJson = mapper.writeValueAsString(config.args);

            JSONObject schemaObj = new JSONObject(new JSONTokener(schemaJson));
            Schema schema = SchemaLoader.load(schemaObj);

            JSONObject configObj = new JSONObject(new JSONTokener(configJson));
            schema.validate(configObj);

            return ValidationResult.success();

        } catch (ValidationException ve) {
            List<String> errors = new ArrayList<>();
            errors.add(ve.getMessage());
            ve.getCausingExceptions().forEach(e -> errors.add("  - " + e.getMessage()));
            return ValidationResult.failure(String.join("\n", errors));

        } catch (Exception e) {
            return ValidationResult.failure("Validation error: " + e.getMessage());
        }
    }

    /**
     * Result of schema validation.
     */
    public static class ValidationResult {
        public final boolean isValid;
        public final String errorMessage;

        private ValidationResult(boolean isValid, String errorMessage) {
            this.isValid = isValid;
            this.errorMessage = errorMessage;
        }

        public static ValidationResult success() {
            return new ValidationResult(true, null);
        }

        public static ValidationResult failure(String message) {
            return new ValidationResult(false, message);
        }
    }

    // ========================================================================
    // HELPER METHODS
    // ========================================================================

    private Set<String> extractRequired(JsonNode required) {
        Set<String> requiredFields = new HashSet<>();
        if (required != null && required.isArray()) {
            required.forEach(node -> requiredFields.add(node.asText()));
        }
        return requiredFields;
    }

    /**
     * Parse conditional requirements from JSON Schema if/then/else structures
     * (Draft 7).
     * Handles both allOf array patterns and top-level conditionals.
     * Returns a map of condition -> requirements.
     * 
     * Example: {"action=create" ->
     * ConditionalRequirements(additionalRequired=[data_type_kind, members])}
     */
    private Map<String, ConditionalRequirements> parseConditionalRequirements(JsonNode schemaNode) {
        Map<String, ConditionalRequirements> result = new LinkedHashMap<>();

        try {
            // log("Parsing conditional requirements from schema");

            // Check for allOf array (JSON Schema Draft 7 pattern for multiple conditionals)
            JsonNode allOf = schemaNode.get("allOf");
            if (allOf != null && allOf.isArray()) {
                // log("Found allOf array with " + allOf.size() + " clauses");
                for (JsonNode condition : allOf) {
                    parseConditionalClause(condition, result);
                }
            }

            // Also check for top-level if/then (single conditional)
            if (schemaNode.has("if") && schemaNode.has("then")) {
                // log("Found top-level if/then clause");
                parseConditionalClause(schemaNode, result);
            }

            // log("Total conditionals parsed: " + result.size());
            // for (Map.Entry<String, ConditionalRequirements> entry : result.entrySet()) {
            // log(" " + entry.getKey() + " -> requires: " +
            // entry.getValue().additionalRequired);
            // }

        } catch (Exception e) {
            log("Error parsing conditionals: " + e.getMessage());
            if (debugScript != null) {
                e.printStackTrace();
            }
        }

        return result;
    }

    /**
     * Parse a single if/then/else clause (JSON Schema Draft 7).
     * Pattern: { "if": { "properties": { "prop": { "const": "value" } } }, "then":
     * { "required": [...] } }
     */
    private void parseConditionalClause(JsonNode clauseNode,
            Map<String, ConditionalRequirements> result) {

        JsonNode ifNode = clauseNode.get("if");
        JsonNode thenNode = clauseNode.get("then");

        if (ifNode == null || thenNode == null) {
            return;
        }

        // Extract condition (e.g., action=create or data_type_kind=typedef)
        String conditionKey = extractCondition(ifNode);
        if (conditionKey == null) {
            // log(" Could not extract condition from if clause");
            return;
        }

        // log(" Parsing condition: " + conditionKey);

        // Extract additional requirements from then clause
        ConditionalRequirements reqs = result.computeIfAbsent(conditionKey, k -> new ConditionalRequirements());

        JsonNode thenRequired = thenNode.get("required");
        if (thenRequired != null && thenRequired.isArray()) {
            thenRequired.forEach(node -> {
                String field = node.asText();
                reqs.additionalRequired.add(field);
                // log(" Requires: " + field);
            });
        }

        // Handle else clause if present
        JsonNode elseNode = clauseNode.get("else");
        if (elseNode != null) {
            JsonNode elseRequired = elseNode.get("required");
            if (elseRequired != null && elseRequired.isArray()) {
                // Note: For test generation, we typically focus on the positive case (then)
                // Else clauses are less common but could be handled here if needed
                // log(" Found else clause (not currently processed for test generation)");
            }
        }
    }

    /**
     * Extract condition from if clause (JSON Schema Draft 7).
     * Supports: if.properties.{property}.const=value
     * Returns: "{property}={value}"
     */
    private String extractCondition(JsonNode ifNode) {
        JsonNode props = ifNode.get("properties");
        if (props == null) {
            return null;
        }

        // Look for property with const value (most common pattern)
        java.util.Iterator<Map.Entry<String, JsonNode>> fields = props.fields();
        while (fields.hasNext()) {
            Map.Entry<String, JsonNode> entry = fields.next();
            String propName = entry.getKey();
            JsonNode propValue = entry.getValue();

            // Check for const value (JSON Schema Draft 7 pattern)
            if (propValue.has("const")) {
                String constValue = propValue.get("const").asText();
                return propName + "=" + constValue;
            }

            // Check for enum with single value (alternative pattern)
            if (propValue.has("enum")) {
                JsonNode enumNode = propValue.get("enum");
                if (enumNode.isArray() && enumNode.size() == 1) {
                    return propName + "=" + enumNode.get(0).asText();
                }
            }
        }

        return null;
    }

    /**
     * Find the primary conditional field from the schema (e.g., "action",
     * "target_type").
     * Returns the field name that appears most in conditional requirements and has
     * an enum.
     */
    private String findPrimaryConditionalField(JsonNode properties,
            Map<String, ConditionalRequirements> conditionalReqs) {
        if (conditionalReqs.isEmpty()) {
            return null;
        }

        // Count occurrences of each field in conditional keys
        Map<String, Integer> fieldCounts = new HashMap<>();
        for (String conditionKey : conditionalReqs.keySet()) {
            int eqIndex = conditionKey.indexOf('=');
            if (eqIndex > 0) {
                String fieldName = conditionKey.substring(0, eqIndex);
                fieldCounts.put(fieldName, fieldCounts.getOrDefault(fieldName, 0) + 1);
            }
        }

        // Find the field with most conditional usage that also has an enum
        return fieldCounts.entrySet().stream()
                .filter(entry -> {
                    JsonNode prop = properties.get(entry.getKey());
                    return prop != null && prop.has("enum");
                })
                .max(Map.Entry.comparingByValue())
                .map(Map.Entry::getKey)
                .orElse(null);
    }

    /**
     * Find fields that have nested conditionals (e.g., data_type_kind has
     * conditionals for typedef/pointer).
     * Returns the set of field names that are used in conditional if clauses.
     * Excludes the primary conditional field to avoid duplication.
     */
    private Set<String> findNestedConditionalFields(JsonNode properties,
            Map<String, ConditionalRequirements> conditionalReqs,
            Set<String> currentlyRequiredFields,
            String primaryConditionalField) {
        Set<String> nestedFields = new HashSet<>();

        for (String conditionKey : conditionalReqs.keySet()) {
            // Parse condition key like "data_type_kind=typedef" or "action=create"
            int eqIndex = conditionKey.indexOf('=');
            if (eqIndex > 0) {
                String fieldName = conditionKey.substring(0, eqIndex);
                // Skip the primary conditional field AND fileName
                if (!fieldName.equals(primaryConditionalField) &&
                        !fieldName.equals("fileName") &&
                        currentlyRequiredFields.contains(fieldName) &&
                        properties.has(fieldName)) {
                    JsonNode prop = properties.get(fieldName);
                    if (prop.has("enum")) {
                        nestedFields.add(fieldName);
                    }
                }
            }
        }

        return nestedFields;
    }

    /**
     * Generate configs for nested conditionals (e.g., action=create with
     * data_type_kind=typedef).
     * For each nested conditional field's enum values, generate appropriate test
     * configs.
     */
    private void generateNestedConditionalConfigs(List<TestConfig> configs, String primaryValue,
            JsonNode properties, Set<String> baseRequiredFields,
            Set<String> nestedConditionalFields,
            Map<String, ConditionalRequirements> conditionalReqs,
            TestDataFactory.TestDataContext testData,
            String primaryFieldName) {

        // For each nested conditional field, get its possible values
        for (String nestedField : nestedConditionalFields) {
            JsonNode nestedProp = properties.get(nestedField);
            if (nestedProp == null || !nestedProp.has("enum")) {
                continue;
            }

            JsonNode nestedEnum = nestedProp.get("enum");
            for (JsonNode nestedValue : nestedEnum) {
                String nestedValueStr = nestedValue.asText();
                String nestedCondKey = nestedField + "=" + nestedValueStr;

                // Get requirements for this nested condition
                Set<String> finalRequiredFields = new HashSet<>(baseRequiredFields);
                finalRequiredFields.add(nestedField); // The nested field itself is now required

                ConditionalRequirements nestedReqs = conditionalReqs.get(nestedCondKey);
                if (nestedReqs != null) {
                    finalRequiredFields.addAll(nestedReqs.additionalRequired);
                    // log(" Nested condition '" + nestedCondKey + "' adds requirements: "
                    // + nestedReqs.additionalRequired);
                }

                // Get optional params (excluding nested required ones)
                List<String> optionalParams = new ArrayList<>(getOptionalParams(properties, finalRequiredFields));
                List<Set<String>> combinations = powerSet(optionalParams);

                for (Set<String> combination : combinations) {
                    Map<String, Object> args = new LinkedHashMap<>();
                    args.put(primaryFieldName, primaryValue);
                    args.put(nestedField, nestedValueStr);
                    boolean hasAllRequiredFields = true;

                    // Add all required params
                    for (String field : finalRequiredFields) {
                        if (field.equals("fileName") || field.equals(primaryFieldName) || field.equals(nestedField)) {
                            continue;
                        }
                        JsonNode prop = properties.get(field);
                        if (prop != null) {
                            Object value = generateValue(field, prop, testData, args, null);
                            if (value != null) {
                                args.put(field, value);
                            } else {
                                // Required field couldn't be generated
                                hasAllRequiredFields = false;
                                break;
                            }
                        }
                    }

                    // Skip this config if required fields are missing
                    if (!hasAllRequiredFields) {
                        continue;
                    }

                    // Add optional params
                    for (String optionalParam : combination) {
                        JsonNode prop = properties.get(optionalParam);
                        if (prop != null) {
                            Object value = generateValue(optionalParam, prop, testData, args, null);
                            if (value != null) {
                                args.put(optionalParam, value);
                            }
                        }
                    }

                    // Skip if anyOf requirements are not met (need to pass the parent schemaNode)
                    // Note: For nested configs, we would need to pass the schemaNode from outer
                    // scope
                    // For now, anyOf validation is primarily for top-level delete tools

                    String description = primaryValue + "/" + nestedValueStr;
                    if (!combination.isEmpty()) {
                        description += " [" + String.join(", ", combination) + "]";
                    }
                    configs.add(new TestConfig(args, description));
                }
            }
        }
    }

    /**
     * Build argument map from primary conditional value, required fields, and
     * optional combination.
     * Returns null if any required field cannot be generated.
     */
    private Map<String, Object> buildArgs(String primaryValue, JsonNode properties,
            Set<String> requiredFields, Set<String> optionalCombination,
            TestDataFactory.TestDataContext testData,
            String primaryFieldName) {
        Map<String, Object> args = new LinkedHashMap<>();

        if (primaryValue != null && primaryFieldName != null) {
            args.put(primaryFieldName, primaryValue);
        }

        // Add all required params (excluding fileName and primary field)
        for (String field : requiredFields) {
            if (field.equals("fileName") || field.equals(primaryFieldName)) {
                continue;
            }
            JsonNode prop = properties.get(field);
            if (prop != null) {
                Object value = generateValue(field, prop, testData, args, null);
                if (value != null) {
                    args.put(field, value);
                } else {
                    // Required field couldn't be generated - return null to skip this config
                    return null;
                }
            }
        }

        // Add optional params
        for (String optionalParam : optionalCombination) {
            JsonNode prop = properties.get(optionalParam);
            if (prop != null) {
                Object value = generateValue(optionalParam, prop, testData, args, null);
                if (value != null) {
                    args.put(optionalParam, value);
                }
            }
        }

        return args;
    }

    /**
     * Build descriptive name for test config.
     */
    private String buildDescription(String primaryValue, Set<String> combination, Map<String, Object> args) {
        StringBuilder desc = new StringBuilder();

        if (primaryValue != null) {
            desc.append(primaryValue);
        }

        // Add key differentiating parameters
        if (args.containsKey("data_type_kind") && !primaryValue.equals(args.get("data_type_kind"))) {
            desc.append("/").append(args.get("data_type_kind"));
        }
        if (args.containsKey("target_type") && !primaryValue.equals(args.get("target_type"))) {
            desc.append("/").append(args.get("target_type"));
        }

        // Add optional params if any
        if (!combination.isEmpty()) {
            desc.append(" [").append(String.join(", ", combination)).append("]");
        }

        return desc.length() > 0 ? desc.toString() : "base";
    }

    /**
     * Get optional parameters (all params that aren't required or fileName).
     */
    private Set<String> getOptionalParams(JsonNode properties, Set<String> requiredFields) {
        Set<String> optional = new HashSet<>();
        properties.fieldNames().forEachRemaining(fieldName -> {
            if (!fieldName.equals("fileName") &&
                    !requiredFields.contains(fieldName)) {
                optional.add(fieldName);
            }
        });
        return optional;
    }

    /**
     * Generate power set - all possible combinations of elements.
     * For a set of size n, this generates 2^n combinations.
     * Example: [A, B] -> [[], [A], [B], [A,B]]
     */
    private <T> List<Set<T>> powerSet(List<T> elements) {
        List<Set<T>> result = new ArrayList<>();
        int n = elements.size();

        // There are 2^n possible combinations
        for (int i = 0; i < (1 << n); i++) {
            Set<T> combination = new LinkedHashSet<>();
            for (int j = 0; j < n; j++) {
                // Check if jth element should be in this combination
                if ((i & (1 << j)) > 0) {
                    combination.add(elements.get(j));
                }
            }
            result.add(combination);
        }

        return result;
    }

    /**
     * Generate minimal args - only required parameters.
     * (Currently unused but kept for potential future use)
     */
    private Map<String, Object> generateMinimalArgs(String action, JsonNode properties,
            Set<String> requiredFields, TestDataFactory.TestDataContext testData) {
        Map<String, Object> args = new LinkedHashMap<>();

        if (action != null) {
            args.put("action", action);
        }

        // Only add required fields (excluding fileName and action)
        for (String field : requiredFields) {
            if (field.equals("fileName") || field.equals("action")) {
                continue;
            }

            JsonNode prop = properties.get(field);
            if (prop != null) {
                Object value = generateValue(field, prop, testData, args, null);
                if (value != null) {
                    args.put(field, value);
                }
            }
        }

        return args;
    }

    /**
     * Generate full args - all parameters (required + optional).
     * (Currently unused but kept for potential future use)
     */
    private Map<String, Object> generateFullArgs(String action, JsonNode properties,
            TestDataFactory.TestDataContext testData) {
        Map<String, Object> args = new LinkedHashMap<>();

        if (action != null) {
            args.put("action", action);
        }

        // Add ALL properties
        properties.fields().forEachRemaining(entry -> {
            String fieldName = entry.getKey();
            JsonNode prop = entry.getValue();

            if (fieldName.equals("fileName") ||
                    (fieldName.equals("action") && action != null)) {
                return;
            }

            Object value = generateValue(fieldName, prop, testData, args, null);
            if (value != null) {
                args.put(fieldName, value);
            }
        });

        return args;
    }

    /**
     * Generate smart test values based on parameter name, type, schema constraints,
     * and context from other arguments.
     * Uses test data context for realistic addresses/names.
     */
    private Object generateValue(String fieldName, JsonNode propNode,
            TestDataFactory.TestDataContext testData,
            Map<String, Object> currentArgs,
            String toolClassName) {

        // Detect if this is a delete/update/convert operation (operations that need
        // existing resources)
        boolean isDeleteOrUpdate = false;
        Object action = currentArgs.get("action");
        if (action != null) {
            String actionStr = action.toString();
            isDeleteOrUpdate = actionStr.equals("delete") || actionStr.equals("update")
                    || actionStr.startsWith("convert");
        }
        // Also detect standalone delete/update tools
        if (toolClassName != null && (toolClassName.startsWith("Delete") || toolClassName.contains("Update"))) {
            isDeleteOrUpdate = true;
        }

        // Detect if this is a READ operation looking up by name (not creating)
        // READ tools with 'name' field but NO 'address' are lookups, not creates
        boolean isReadLookup = false;
        if (toolClassName != null && toolClassName.startsWith("Read")) {
            // If we're about to generate a 'name' value and there's no address, it's a
            // lookup
            if (fieldName.equals("name") && !currentArgs.containsKey("address")) {
                isReadLookup = true;
            }
        }

        // Check for enum - use first value (most common case)
        if (propNode.has("enum")) {
            JsonNode enumNode = propNode.get("enum");
            if (enumNode.isArray() && enumNode.size() > 0) {
                JsonNode firstEnum = enumNode.get(0);
                // Handle different enum value types
                if (firstEnum.isTextual()) {
                    return firstEnum.asText();
                } else if (firstEnum.isInt()) {
                    return firstEnum.asInt();
                } else if (firstEnum.isBoolean()) {
                    return firstEnum.asBoolean();
                }
                return firstEnum.asText(); // Fallback to string
            }
        }

        // Check for default value
        if (propNode.has("default")) {
            JsonNode defaultNode = propNode.get("default");
            if (defaultNode.isTextual()) {
                return defaultNode.asText();
            } else if (defaultNode.isInt()) {
                return defaultNode.asInt();
            } else if (defaultNode.isBoolean()) {
                return defaultNode.asBoolean();
            }
        }

        String type = propNode.has("type") ? propNode.get("type").asText() : "string";

        // Smart generation based on field name patterns
        if (fieldName.contains("address") || fieldName.equals("startAddress") || fieldName.equals("startAddr")) {
            // For delete/update operations, use the correct test address based on tool type
            if (isDeleteOrUpdate) {
                if (toolClassName != null) {
                    if (toolClassName.contains("Function")) {
                        // Only return if the test function was actually created
                        return testData.testFunctionAddress != null ? testData.testFunctionAddress.toString() : null;
                    } else if (toolClassName.contains("Symbol")) {
                        // Only return if the test symbol was actually created
                        return testData.testSymbolAddress != null ? testData.testSymbolAddress.toString() : null;
                    } else if (toolClassName.contains("Bookmark")) {
                        // Only return if the test bookmark was actually created
                        return testData.testBookmarkAddress != null ? testData.testBookmarkAddress.toString() : null;
                    }
                }
            }
            // For READ operations with address, also use test data addresses
            if (toolClassName != null && toolClassName.startsWith("Read")) {
                if (toolClassName.contains("Function")) {
                    // Only return if the test function was actually created
                    return testData.testFunctionAddress != null ? testData.testFunctionAddress.toString() : null;
                } else if (toolClassName.contains("Symbol")) {
                    // Only return if the test symbol was actually created
                    return testData.testSymbolAddress != null ? testData.testSymbolAddress.toString() : null;
                }
            }
            // For create operations, use test function address if available, otherwise
            // entry address
            Address addr = testData.testFunctionAddress != null ? testData.testFunctionAddress : testData.entryAddress;
            return addr != null ? addr.toString() : "0x401000";
        }

        if (fieldName.equals("endAddress") || fieldName.equals("endAddr")) {
            return testData.entryAddress != null
                    ? String.format("0x%x", testData.entryAddress.getOffset() + 0x100)
                    : "0x401100";
        }

        if (fieldName.contains("functionName") || fieldName.equals("function_name")) {
            // Use actual test function name if available
            return testData.testFunctionName != null ? testData.testFunctionName : "main";
        }

        if (fieldName.equals("name") && type.equals("string")) {
            // Context-sensitive name generation with uniqueness using atomic counter
            Object dataTypeKind = currentArgs.get("data_type_kind");
            if (dataTypeKind != null) {
                String kind = dataTypeKind.toString();

                // For delete/update operations OR read lookups, use actual test data names
                if (isDeleteOrUpdate || isReadLookup) {
                    return switch (kind) {
                        case "struct" -> testData.testStructCreated ? testData.testStructName : null;
                        case "enum" -> testData.testEnumCreated ? testData.testEnumName : null;
                        case "category" -> "TestCategory"; // Use a fixed name for categories
                        default -> null; // Don't test operations for types we didn't create
                    };
                }

                // For create operations, generate unique names
                int unique = uniqueCounter.incrementAndGet();
                return switch (kind) {
                    case "struct" -> "TestStruct_" + unique;
                    case "enum" -> "TestEnum_" + unique;
                    case "union" -> "TestUnion_" + unique;
                    case "typedef" -> "TestTypedef_" + unique;
                    case "pointer" -> "TestPtr_" + unique;
                    case "function_definition" -> "TestFuncDef_" + unique;
                    case "category" -> "TestCat_" + unique;
                    case "rtti0" -> "TestRtti_" + unique;
                    default -> "test_name_" + unique;
                };
            }

            // For READ lookups of symbols, use actual test label name
            if (isReadLookup && toolClassName != null && toolClassName.contains("Symbol")) {
                // Only return if the test symbol was actually created
                return testData.testSymbolAddress != null ? testData.testLabelName : null;
            }

            // For READ lookups of functions, use test function name
            if (isReadLookup && toolClassName != null && toolClassName.contains("Function")) {
                // Only return if the test function was actually created
                return testData.testFunctionAddress != null ? testData.testFunctionName : null;
            }

            // For delete/update symbol operations, use actual test label name
            if (isDeleteOrUpdate && toolClassName != null && toolClassName.contains("Symbol")) {
                // Only return if the test symbol was actually created
                return testData.testSymbolAddress != null ? testData.testLabelName : null;
            }

            // For delete/update function operations, use test function name
            if (isDeleteOrUpdate && toolClassName != null && toolClassName.contains("Function")) {
                // Only return if the test function was actually created
                return testData.testFunctionAddress != null ? testData.testFunctionName : null;
            }

            // For other delete/update operations, use test function name as fallback
            if (isDeleteOrUpdate) {
                // Only return if the test function was actually created
                return testData.testFunctionAddress != null ? testData.testFunctionName : null;
            }

            // For create operations, generate unique name
            return "test_name_" + uniqueCounter.incrementAndGet();
        }

        if (fieldName.contains("symbolName") || fieldName.equals("symbol_name")) {
            // Use actual test label name if available
            return testData.testLabelName != null ? testData.testLabelName : "test_symbol";
        }

        if (fieldName.equals("bookmark_type") || fieldName.equals("bookmarkType")) {
            return "NOTE";
        }

        if (fieldName.equals("bookmark_category") || fieldName.equals("bookmarkCategory")) {
            return "Analysis";
        }

        if (fieldName.equals("comment") || fieldName.equals("description")) {
            return "Test comment";
        }

        if (fieldName.equals("base_type") || fieldName.equals("baseType")) {
            return "int";
        }

        if (fieldName.equals("searchType") || fieldName.equals("search_type")) {
            return "string";
        }

        if (fieldName.equals("searchValue") || fieldName.equals("search_value")) {
            return "test";
        }

        if (fieldName.equals("target_type")) {
            return "function";
        }

        if (fieldName.equals("target_value")) {
            // Context-aware generation based on target_type
            Object targetType = currentArgs.get("target_type");
            if (targetType != null) {
                String targetTypeStr = targetType.toString();
                return switch (targetTypeStr) {
                    case "function" -> "main";
                    case "address" -> testData.mainAddress != null ? testData.mainAddress.toString()
                            : (testData.entryAddress != null ? testData.entryAddress.toString() : "0x401000");
                    case "address_range" -> {
                        Address start = testData.mainAddress != null ? testData.mainAddress : testData.entryAddress;
                        if (start != null) {
                            yield start.toString() + "-" + String.format("0x%x", start.getOffset() + 0x100);
                        }
                        yield "0x401000-0x401100";
                    }
                    case "all_functions" -> null; // No target_value needed for all_functions
                    default -> "main";
                };
            }
            // Fallback if no context
            return "main";
        }

        if (fieldName.equals("direction")) {
            return "TO";
        }

        if (fieldName.equals("mangledSymbol") || fieldName.equals("mangledName") || fieldName.equals("mangled_name")) {
            return "_Z3addii";
        }

        if (fieldName.equals("symbol_type")) {
            return "label";
        }

        if (fieldName.equals("symbol_id")) {
            // Skip symbol_id in tests - it's an alternative identifier
            // Tools should work with address/name instead
            return null;
        }

        if (fieldName.equals("prototype")) {
            return "void test_func(int param1)";
        }

        if (fieldName.equals("bytes_hex") || fieldName.equals("bytesHex")) {
            return "4889e5";
        }

        if (fieldName.equals("pattern") || fieldName.equals("name_pattern")) {
            return ".*";
        }

        if (fieldName.equals("category_path") || fieldName.equals("categoryPath")) {
            return "/";
        }

        if (fieldName.equals("namespace")) {
            return "Global";
        }

        if (fieldName.equals("data_type_kind")) {
            return "struct";
        }

        if (fieldName.equals("operations")) {
            // For batch_operations - create a minimal operation array
            List<Map<String, Object>> operations = new ArrayList<>();
            Map<String, Object> operation = new LinkedHashMap<>();
            operation.put("tool", "list_programs");
            operation.put("arguments", new LinkedHashMap<>());
            operations.add(operation);
            return operations;
        }

        // Type-based defaults with schema constraints
        switch (type) {
            case "integer":
                // Check for minimum/maximum constraints
                int minValue = propNode.has("minimum") ? propNode.get("minimum").asInt() : 1;
                int maxValue = propNode.has("maximum") ? propNode.get("maximum").asInt() : 100;

                // Smart defaults based on field name
                if (fieldName.contains("length") || fieldName.contains("size")) {
                    return Math.max(16, minValue);
                }
                if (fieldName.contains("max") || fieldName.contains("limit")) {
                    return Math.min(10, maxValue);
                }
                if (fieldName.contains("timeout")) {
                    return Math.max(30, minValue);
                }
                if (fieldName.contains("offset")) {
                    return 0;
                }
                if (fieldName.contains("value")) {
                    return 0;
                }
                if (fieldName.contains("id") || fieldName.equals("symbol_id") || fieldName.equals("data_type_id")) {
                    return 1;
                }
                // Return a safe middle value
                return Math.max(minValue, Math.min(10, maxValue));

            case "boolean":
                // Smart defaults based on field name
                if (fieldName.contains("include") || fieldName.contains("enabled")) {
                    return false; // Conservative default
                }
                if (fieldName.contains("case_sensitive") || fieldName.contains("caseSensitive")) {
                    return false;
                }
                return false;

            case "array":
                // Return empty array unless schema specifies items
                return new ArrayList<>();

            case "object":
                // Return empty object
                return new LinkedHashMap<>();

            case "null":
                return null;

            default: // string or unknown type
                // Check pattern constraint for hints
                if (propNode.has("pattern")) {
                    String pattern = propNode.get("pattern").asText();
                    if (pattern.contains("[0-9a-fA-F]")) {
                        return "0x401000"; // Looks like hex address
                    }
                }
                return "test_value";
        }
    }
}
