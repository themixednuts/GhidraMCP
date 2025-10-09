// Comprehensive MCP Tools Test Runner for Ghidra Headless Mode
// Schema-driven, deterministic simulation testing
// @category Testing

package com.themixednuts.headless;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import ghidra.app.script.GhidraScript;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;

import java.util.*;

/**
 * Deterministic test runner for all GhidraMCP tools.
 * 
 * Architecture:
 * 1. Create test data (TestDataFactory)
 * 2. Discover tools (ServiceLoader)
 * 3. Generate configs from schemas (SchemaTestGenerator)
 * 4. Validate against schemas
 * 5. Execute and verify results
 * 
 * Note: This class does NOT extend GhidraScript. It accepts a GhidraScript
 * instance as a parameter to access its context (program, tool, println, etc.)
 */
public class TestRunner {

    private final TestStats stats = new TestStats();
    private GhidraScript script;
    private PluginTool tool;
    private Program program;

    // ========================================================================
    // TEST STATISTICS
    // ========================================================================

    static class TestStats {
        int total = 0;
        int passed = 0;
        int failed = 0;
        List<String> failures = new ArrayList<>();

        void pass(String testName) {
            total++;
            passed++;
        }

        void fail(String testName, String reason) {
            total++;
            failed++;
            String shortReason = reason != null && reason.length() > 100
                    ? reason.substring(0, 100) + "..."
                    : reason;
            failures.add(testName + ": " + shortReason);
        }

        void print(GhidraScript script) {
            script.println("=" + "=".repeat(79));
            script.println("=== Test Summary ===");
            script.println("=" + "=".repeat(79));
            script.println("Total:  " + total);
            script.println("Passed: " + passed + " [OK]");
            script.println("Failed: " + failed + " [FAIL]");
            script.println("");

            if (!failures.isEmpty()) {
                script.println("Failed Tests:");
                for (int i = 0; i < Math.min(failures.size(), 20); i++) {
                    script.println("  * " + failures.get(i));
                }
                if (failures.size() > 20) {
                    script.println("  ... +" + (failures.size() - 20) + " more");
                }
                script.println("");
            }

            if (failed == 0) {
                script.println("=" + "=".repeat(79));
                script.println("*** ALL TESTS PASSED! ***");
                script.println("=" + "=".repeat(79));
            } else {
                script.println("=" + "=".repeat(79));
                script.println("*** " + failed + " test(s) FAILED ***");
                script.println("=" + "=".repeat(79));
            }
        }
    }

    // ========================================================================
    // MAIN EXECUTION
    // ========================================================================

    /**
     * Run the test suite with the provided GhidraScript context.
     * 
     * @param script  The GhidraScript instance (provides println, printerr, etc.)
     * @param program The loaded Ghidra program to test
     * @param tool    The PluginTool instance
     */
    public void run(GhidraScript script, Program program, PluginTool tool) throws Exception {
        this.script = script;
        this.program = program;
        this.tool = tool;

        script.println("=" + "=".repeat(79));
        script.println("GhidraMCP Comprehensive Tool Test Suite (Java)");
        script.println("Schema-Driven Deterministic Simulation Testing");
        script.println("=" + "=".repeat(79));
        script.println("");

        // ====================================================================
        // PHASE 1: ENVIRONMENT SETUP
        // ====================================================================

        if (program == null) {
            script.printerr("[SETUP] [FAIL] No program loaded");
            return;
        }

        // Setup OK - program loaded successfully (silent)

        // ====================================================================
        // PHASE 2: CREATE TEST DATA
        // ====================================================================

        TestDataFactory.TestDataContext testData = TestDataFactory.createTestData(program);

        // Only report failures
        if (testData.testFunctionAddress == null) {
            script.println("[SETUP] [FAIL] Test function not created");
        }
        if (testData.testSymbolAddress == null) {
            script.println("[SETUP] [FAIL] Test symbol not created");
        }
        if (!testData.testStructCreated) {
            script.println("[SETUP] [FAIL] TestStruct not created");
        }
        if (!testData.testEnumCreated) {
            script.println("[SETUP] [FAIL] TestEnum not created");
        }
        if (!testData.testBookmarkCreated) {
            script.println("[SETUP] [FAIL] Test bookmark not created");
        }

        // ====================================================================
        // PHASE 3: DISCOVER ALL TOOLS
        // ====================================================================

        ServiceLoader<IGhidraMcpSpecification> loader = ServiceLoader.load(
                IGhidraMcpSpecification.class,
                IGhidraMcpSpecification.class.getClassLoader());

        Map<String, IGhidraMcpSpecification> tools = new TreeMap<>();
        for (IGhidraMcpSpecification toolInstance : loader) {
            GhidraMcpTool annotation = toolInstance.getClass().getAnnotation(GhidraMcpTool.class);
            if (annotation != null) {
                tools.put(annotation.mcpName(), toolInstance);
            }
        }

        // Tool discovery successful (silent)

        // ====================================================================
        // PHASE 4: RUN SCHEMA-DRIVEN TESTS
        // ====================================================================

        script.println("=" + "=".repeat(79));
        script.println("RUNNING COMPREHENSIVE TESTS");
        script.println("=" + "=".repeat(79));
        script.println("");

        SchemaTestGenerator generator = new SchemaTestGenerator();
        generator.setDebugScript(script); // Enable debug logging

        for (Map.Entry<String, IGhidraMcpSpecification> entry : tools.entrySet()) {
            String toolName = entry.getKey();
            IGhidraMcpSpecification toolInstance = entry.getValue();

            try {
                testTool(toolName, toolInstance, program, tool, testData, generator, tools);
            } catch (Exception e) {
                script.println("  [CATASTROPHIC] " + e.getMessage());
                stats.fail(toolName + "/catastrophic", e.getMessage());
            }

            script.println("");
        }

        // ====================================================================
        // PHASE 5: SUMMARY
        // ====================================================================

        stats.print(script);

        // Exit with appropriate code
        if (stats.failed > 0) {
            System.exit(1);
        }
    }

    // ========================================================================
    // TOOL TESTING
    // ========================================================================

    private void testTool(String toolName, IGhidraMcpSpecification toolInstance,
            Program program, PluginTool tool,
            TestDataFactory.TestDataContext testData,
            SchemaTestGenerator generator,
            Map<String, IGhidraMcpSpecification> allTools) throws Exception {

        script.println("-" + "-".repeat(79));
        script.println("[" + toolName + "] " + toolInstance.getClass().getSimpleName());
        script.println("-" + "-".repeat(79));

        // Test 1: Schema generation
        try {
            if (toolInstance.schema() != null) {
                stats.pass(toolName + "/schema");
                // Schema OK - silent
            } else {
                stats.fail(toolName + "/schema", "null schema");
                script.println("  Schema: [FAIL]");
            }
        } catch (Exception e) {
            stats.fail(toolName + "/schema", e.getMessage());
            script.println("  Schema: [FAIL]");
        }

        // Test 2: Execute with schema-generated configs
        List<SchemaTestGenerator.TestConfig> testConfigs = generator.generateConfigs(toolInstance, testData);

        if (testConfigs.isEmpty()) {
            script.println("  No test configs generated");
            return;
        }

        for (SchemaTestGenerator.TestConfig config : testConfigs) {
            String testName = toolName + "/" + config.description;

            try {
                // Prepare args with fileName BEFORE validation
                Map<String, Object> args = new HashMap<>(config.args);
                args.put("fileName", program.getName());

                // Create a config for validation with fileName included
                SchemaTestGenerator.TestConfig configWithFileName = new SchemaTestGenerator.TestConfig(args,
                        config.description);

                // VALIDATE with fileName included
                SchemaTestGenerator.ValidationResult validation = generator.validate(configWithFileName,
                        toolInstance.schema());

                if (!validation.isValid) {
                    stats.fail(testName, "Schema validation: " + validation.errorMessage);
                    script.println("  " + config.description + ": [FAIL] Schema");
                    continue;
                }

                // Setup if needed (create resources before deleting/updating)
                if (toolName.equals("delete_bookmark")) {
                    setupForDeleteBookmark(program, tool, testData, allTools, args);
                } else if (toolName.equals("delete_function")) {
                    setupForDeleteFunction(program, tool, testData, allTools, args);
                } else if (toolName.equals("delete_symbol")) {
                    setupForDeleteSymbol(program, tool, testData, allTools, args);
                } else if (toolName.equals("delete_data_type")) {
                    setupForDeleteDataType(program, tool, testData, allTools, args);
                } else if (toolName.equals("manage_data_types")) {
                    setupForManageDataTypes(program, tool, testData, allTools, args);
                }

                // Execute
                Object result = toolInstance.execute(null, args, tool).block();

                // Validate result
                if (result != null) {
                    stats.pass(testName);
                    // Test passed - silent
                } else if (toolName.startsWith("delete_") || toolName.contains("undo")) {
                    stats.pass(testName);
                    // Delete/undo passed - silent
                } else {
                    stats.fail(testName, "null result");
                    script.println("  " + config.description + ": [FAIL]");
                }

            } catch (Exception e) {
                handleTestException(toolName, config.description, e);
            }
        }
    }

    // ========================================================================
    // HELPERS
    // ========================================================================

    private void handleTestException(String toolName, String desc, Exception e) {
        String testName = toolName + "/" + desc;
        String errorMsg = e.getMessage();

        // Expected errors for search/read operations
        if (errorMsg != null && (errorMsg.toLowerCase().contains("no results") ||
                errorMsg.toLowerCase().contains("no match"))) {
            stats.pass(testName);
            // Expected "no results" - silent
        } else if (toolName.startsWith("delete_") && errorMsg != null &&
                (errorMsg.toLowerCase().contains("not found") ||
                        errorMsg.toLowerCase().contains("does not exist"))) {
            // Delete operations must have data to delete - this is a failure
            stats.fail(testName, errorMsg);
            script.println("  " + desc + ": [FAIL] " + errorMsg);
        } else {
            stats.fail(testName, errorMsg != null ? errorMsg : "unknown error");
            script.println("  " + desc + ": [FAIL]");
        }
    }

    private void setupForDeleteBookmark(Program program, PluginTool tool,
            TestDataFactory.TestDataContext testData,
            Map<String, IGhidraMcpSpecification> allTools,
            Map<String, Object> deleteArgs) {
        try {
            // Extract the address that will be deleted
            String targetAddress = deleteArgs.getOrDefault("address", testData.entryAddress.toString()).toString();

            IGhidraMcpSpecification manageProject = allTools.get("manage_project");
            if (manageProject != null) {
                Map<String, Object> args = new HashMap<>();
                args.put("fileName", program.getName());
                args.put("action", "create_bookmark");
                args.put("address", targetAddress);
                args.put("bookmark_type", deleteArgs.getOrDefault("bookmark_type", "NOTE"));
                args.put("bookmark_category", deleteArgs.getOrDefault("bookmark_category", "Test"));
                // Match comment to filter if provided
                String comment = deleteArgs.containsKey("comment_contains")
                        ? "Test bookmark with " + deleteArgs.get("comment_contains")
                        : "Test bookmark for deletion";
                args.put("comment", comment);
                manageProject.execute(null, args, tool).block();
            }
        } catch (Exception e) {
            // If creation fails, deletion test will fail
        }
    }

    private void setupForDeleteFunction(Program program, PluginTool tool,
            TestDataFactory.TestDataContext testData,
            Map<String, IGhidraMcpSpecification> allTools,
            Map<String, Object> deleteArgs) {
        // Function should already exist from TestDataFactory
        // Generator now creates correct test values upfront
    }

    private void setupForDeleteSymbol(Program program, PluginTool tool,
            TestDataFactory.TestDataContext testData,
            Map<String, IGhidraMcpSpecification> allTools,
            Map<String, Object> deleteArgs) {
        // Symbol should already exist from TestDataFactory
        // Generator now creates correct test values upfront
        // Override address for symbol operations since generator uses function address
        // by default
        if (deleteArgs.containsKey("address") && testData.testSymbolAddress != null) {
            deleteArgs.put("address", testData.testSymbolAddress.toString());
        }
    }

    private void setupForDeleteDataType(Program program, PluginTool tool,
            TestDataFactory.TestDataContext testData,
            Map<String, IGhidraMcpSpecification> allTools,
            Map<String, Object> deleteArgs) {
        // Data types should already exist from TestDataFactory
        // Generator now creates correct test values upfront
    }

    private void setupForManageDataTypes(Program program, PluginTool tool,
            TestDataFactory.TestDataContext testData,
            Map<String, IGhidraMcpSpecification> allTools,
            Map<String, Object> args) {
        try {
            String action = args.containsKey("action") ? args.get("action").toString() : "";
            String dataTypeKind = args.containsKey("data_type_kind") ? args.get("data_type_kind").toString() : "";

            // For category updates, ensure category exists first
            if ("update".equals(action) && "category".equals(dataTypeKind)) {
                String categoryName = args.containsKey("name") ? args.get("name").toString() : null;
                if (categoryName != null) {
                    IGhidraMcpSpecification manageDataTypes = allTools.get("manage_data_types");
                    if (manageDataTypes != null) {
                        Map<String, Object> createArgs = new HashMap<>();
                        createArgs.put("fileName", program.getName());
                        createArgs.put("action", "create");
                        createArgs.put("data_type_kind", "category");
                        createArgs.put("name", categoryName);
                        createArgs.put("category_path", "/");
                        try {
                            manageDataTypes.execute(null, createArgs, tool).block();
                        } catch (Exception e) {
                            // Category might already exist, that's fine
                        }
                    }
                }
            }
        } catch (Exception e) {
            // If setup fails, test might fail (which is acceptable)
        }
    }
}