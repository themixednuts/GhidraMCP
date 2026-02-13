package com.themixednuts;

import org.junit.platform.suite.api.SelectPackages;
import org.junit.platform.suite.api.Suite;
import org.junit.platform.suite.api.SuiteDisplayName;

/**
 * Comprehensive test suite for the Ghidra MCP plugin.
 *
 * <p>This test suite runs all unit tests, integration tests, and validation tests for the plugin
 * components.
 */
@Suite
@SuiteDisplayName("Ghidra MCP Plugin Test Suite")
@SelectPackages({
  "com.themixednuts.models",
  "com.themixednuts.utils",
  "com.themixednuts.exceptions",
  "com.themixednuts.tools"
})
public class TestSuite {
  // This class serves as a test suite configuration
  // All tests are automatically discovered and run
}
