package com.themixednuts.models;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for GhidraMcpError model class.
 */
class GhidraMcpErrorTest {

    private GhidraMcpError error;
    private GhidraMcpError.ErrorContext context;
    private GhidraMcpError.ErrorSuggestion suggestion;
    private GhidraMcpError.ErrorDebugInfo debugInfo;

    @BeforeEach
    void setUp() {
        context = new GhidraMcpError.ErrorContext(
            "test_tool",
            "test_operation",
            Map.of("arg1", "value1"),
            Map.of("provided1", "value1"),
            Map.of("meta1", "value1")
        );
        
        suggestion = new GhidraMcpError.ErrorSuggestion(
            GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
            "Test suggestion",
            "Test description",
            List.of("arg1", "arg2"),
            List.of("tool1", "tool2")
        );

        debugInfo = new GhidraMcpError.ErrorDebugInfo(
            "stack trace",
            "Ghidra 10.4",
            "TestTool",
            "2024-01-01T00:00:00Z",
            Map.of("key", "value")
        );
    }

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should create error with all parameters")
        void shouldCreateErrorWithAllParameters() {
            error = new GhidraMcpError(
                GhidraMcpError.ErrorType.VALIDATION,
                GhidraMcpError.ErrorCode.MISSING_REQUIRED_ARGUMENT.getCode(),
                "Test error message",
                context,
                List.of(suggestion),
                List.of("resource1", "resource2"),
                debugInfo
            );

            assertNotNull(error);
            assertEquals(GhidraMcpError.ErrorType.VALIDATION, error.getErrorType());
            assertEquals(GhidraMcpError.ErrorCode.MISSING_REQUIRED_ARGUMENT.getCode(), error.getErrorCode());
            assertEquals("Test error message", error.getMessage());
            assertEquals(context, error.getContext());
            assertEquals(List.of(suggestion), error.getSuggestions());
            assertEquals(List.of("resource1", "resource2"), error.getRelatedResources());
            assertEquals(debugInfo, error.getDebugInfo());
        }

        @Test
        @DisplayName("Should create error with minimal parameters")
        void shouldCreateErrorWithMinimalParameters() {
            error = new GhidraMcpError(
                GhidraMcpError.ErrorType.INTERNAL,
                GhidraMcpError.ErrorCode.UNEXPECTED_ERROR.getCode(),
                "Test error message",
                null,
                null,
                null,
                null
            );

            assertNotNull(error);
            assertEquals(GhidraMcpError.ErrorType.INTERNAL, error.getErrorType());
            assertEquals(GhidraMcpError.ErrorCode.UNEXPECTED_ERROR.getCode(), error.getErrorCode());
            assertEquals("Test error message", error.getMessage());
            assertNull(error.getContext());
            assertNull(error.getSuggestions());
            assertNull(error.getRelatedResources());
            assertNull(error.getDebugInfo());
        }
    }

    @Nested
    @DisplayName("Builder Pattern Tests")
    class BuilderPatternTests {

        @Test
        @DisplayName("Should build error using builder pattern")
        void shouldBuildErrorUsingBuilderPattern() {
            error = GhidraMcpError.validation()
                .errorCode(GhidraMcpError.ErrorCode.MISSING_REQUIRED_ARGUMENT)
                .message("Builder test message")
                .context(context)
                .suggestions(List.of(suggestion))
                .relatedResources(List.of("resource1"))
                .debugInfo(debugInfo)
                .build();

            assertNotNull(error);
            assertEquals(GhidraMcpError.ErrorType.VALIDATION, error.getErrorType());
            assertEquals(GhidraMcpError.ErrorCode.MISSING_REQUIRED_ARGUMENT.getCode(), error.getErrorCode());
            assertEquals("Builder test message", error.getMessage());
            assertEquals(context, error.getContext());
            assertEquals(List.of(suggestion), error.getSuggestions());
            assertEquals(List.of("resource1"), error.getRelatedResources());
            assertEquals(debugInfo, error.getDebugInfo());
        }

        @Test
        @DisplayName("Should build error with chained methods")
        void shouldBuildErrorWithChainedMethods() {
            error = GhidraMcpError.resourceNotFound()
                .errorCode(GhidraMcpError.ErrorCode.FUNCTION_NOT_FOUND)
                .message("Chained test message")
                .context(context)
                .suggestions(List.of(suggestion))
                .relatedResources(List.of("resource1", "resource2"))
                .build();

            assertNotNull(error);
            assertEquals(GhidraMcpError.ErrorType.RESOURCE_NOT_FOUND, error.getErrorType());
            assertEquals(GhidraMcpError.ErrorCode.FUNCTION_NOT_FOUND.getCode(), error.getErrorCode());
            assertEquals("Chained test message", error.getMessage());
            assertEquals(context, error.getContext());
            assertEquals(List.of(suggestion), error.getSuggestions());
            assertEquals(List.of("resource1", "resource2"), error.getRelatedResources());
        }
    }

    @Nested
    @DisplayName("Static Factory Method Tests")
    class StaticFactoryMethodTests {

        @Test
        @DisplayName("Should create validation error")
        void shouldCreateValidationError() {
            error = GhidraMcpError.validation()
                .errorCode(GhidraMcpError.ErrorCode.MISSING_REQUIRED_ARGUMENT)
                .message("Validation error message")
                .context(context)
                .suggestions(List.of(suggestion))
                .build();

            assertNotNull(error);
            assertEquals(GhidraMcpError.ErrorType.VALIDATION, error.getErrorType());
            assertEquals(GhidraMcpError.ErrorCode.MISSING_REQUIRED_ARGUMENT.getCode(), error.getErrorCode());
            assertEquals("Validation error message", error.getMessage());
            assertEquals(context, error.getContext());
            assertEquals(List.of(suggestion), error.getSuggestions());
        }

        @Test
        @DisplayName("Should create resource not found error")
        void shouldCreateResourceNotFoundError() {
            error = GhidraMcpError.resourceNotFound()
                .errorCode(GhidraMcpError.ErrorCode.FUNCTION_NOT_FOUND)
                .message("Resource not found message")
                .context(context)
                .relatedResources(List.of("resource1"))
                .build();

            assertNotNull(error);
            assertEquals(GhidraMcpError.ErrorType.RESOURCE_NOT_FOUND, error.getErrorType());
            assertEquals(GhidraMcpError.ErrorCode.FUNCTION_NOT_FOUND.getCode(), error.getErrorCode());
            assertEquals("Resource not found message", error.getMessage());
            assertEquals(context, error.getContext());
            assertEquals(List.of("resource1"), error.getRelatedResources());
        }

        @Test
        @DisplayName("Should create data type parsing error")
        void shouldCreateDataTypeParsingError() {
            error = GhidraMcpError.dataTypeParsing()
                .errorCode(GhidraMcpError.ErrorCode.INVALID_POINTER_SYNTAX)
                .message("Data type parsing error message")
                .context(context)
                .build();

            assertNotNull(error);
            assertEquals(GhidraMcpError.ErrorType.DATA_TYPE_PARSING, error.getErrorType());
            assertEquals(GhidraMcpError.ErrorCode.INVALID_POINTER_SYNTAX.getCode(), error.getErrorCode());
            assertEquals("Data type parsing error message", error.getMessage());
            assertEquals(context, error.getContext());
        }

        @Test
        @DisplayName("Should create execution error")
        void shouldCreateExecutionError() {
            error = GhidraMcpError.execution()
                .errorCode(GhidraMcpError.ErrorCode.SCRIPT_EXECUTION_FAILED)
                .message("Execution error message")
                .context(context)
                .build();

            assertNotNull(error);
            assertEquals(GhidraMcpError.ErrorType.EXECUTION, error.getErrorType());
            assertEquals(GhidraMcpError.ErrorCode.SCRIPT_EXECUTION_FAILED.getCode(), error.getErrorCode());
            assertEquals("Execution error message", error.getMessage());
            assertEquals(context, error.getContext());
        }

        @Test
        @DisplayName("Should create search no results error")
        void shouldCreateSearchNoResultsError() {
            error = GhidraMcpError.searchNoResults()
                .errorCode(GhidraMcpError.ErrorCode.NO_SEARCH_RESULTS)
                .message("Search no results message")
                .context(context)
                .build();

            assertNotNull(error);
            assertEquals(GhidraMcpError.ErrorType.SEARCH_NO_RESULTS, error.getErrorType());
            assertEquals(GhidraMcpError.ErrorCode.NO_SEARCH_RESULTS.getCode(), error.getErrorCode());
            assertEquals("Search no results message", error.getMessage());
            assertEquals(context, error.getContext());
        }

        @Test
        @DisplayName("Should create internal error")
        void shouldCreateInternalError() {
            error = GhidraMcpError.internal()
                .errorCode(GhidraMcpError.ErrorCode.UNEXPECTED_ERROR)
                .message("Internal error message")
                .context(context)
                .build();

            assertNotNull(error);
            assertEquals(GhidraMcpError.ErrorType.INTERNAL, error.getErrorType());
            assertEquals(GhidraMcpError.ErrorCode.UNEXPECTED_ERROR.getCode(), error.getErrorCode());
            assertEquals("Internal error message", error.getMessage());
            assertEquals(context, error.getContext());
        }
    }

    @Nested
    @DisplayName("Getter Tests")
    class GetterTests {

        @BeforeEach
        void setUp() {
            error = new GhidraMcpError(
                GhidraMcpError.ErrorType.VALIDATION,
                GhidraMcpError.ErrorCode.MISSING_REQUIRED_ARGUMENT.getCode(),
                "Test error message",
                context,
                List.of(suggestion),
                List.of("resource1"),
                debugInfo
            );
        }

        @Test
        @DisplayName("Should return correct error type")
        void shouldReturnCorrectErrorType() {
            assertEquals(GhidraMcpError.ErrorType.VALIDATION, error.getErrorType());
        }

        @Test
        @DisplayName("Should return correct error code")
        void shouldReturnCorrectErrorCode() {
            assertEquals(GhidraMcpError.ErrorCode.MISSING_REQUIRED_ARGUMENT.getCode(), error.getErrorCode());
        }

        @Test
        @DisplayName("Should return correct message")
        void shouldReturnCorrectMessage() {
            assertEquals("Test error message", error.getMessage());
        }

        @Test
        @DisplayName("Should return correct context")
        void shouldReturnCorrectContext() {
            assertEquals(context, error.getContext());
        }

        @Test
        @DisplayName("Should return correct suggestions")
        void shouldReturnCorrectSuggestions() {
            assertEquals(List.of(suggestion), error.getSuggestions());
        }

        @Test
        @DisplayName("Should return correct related resources")
        void shouldReturnCorrectRelatedResources() {
            assertEquals(List.of("resource1"), error.getRelatedResources());
        }

        @Test
        @DisplayName("Should return correct debug info")
        void shouldReturnCorrectDebugInfo() {
            assertEquals(debugInfo, error.getDebugInfo());
        }
    }

    @Nested
    @DisplayName("Error Type Enum Tests")
    class ErrorTypeEnumTests {

        @Test
        @DisplayName("Should have all expected error types")
        void shouldHaveAllExpectedErrorTypes() {
            GhidraMcpError.ErrorType[] errorTypes = GhidraMcpError.ErrorType.values();
            
            assertTrue(errorTypes.length > 0);
            
            // Check for all expected error types
            boolean hasValidation = false;
            boolean hasResourceNotFound = false;
            boolean hasDataTypeParsing = false;
            boolean hasExecution = false;
            boolean hasPermissionState = false;
            boolean hasToolExecution = false;
            boolean hasSearchNoResults = false;
            boolean hasGroupedOperations = false;
            boolean hasInternal = false;
            
            for (GhidraMcpError.ErrorType type : errorTypes) {
                switch (type) {
                    case VALIDATION -> hasValidation = true;
                    case RESOURCE_NOT_FOUND -> hasResourceNotFound = true;
                    case DATA_TYPE_PARSING -> hasDataTypeParsing = true;
                    case EXECUTION -> hasExecution = true;
                    case PERMISSION_STATE -> hasPermissionState = true;
                    case TOOL_EXECUTION -> hasToolExecution = true;
                    case SEARCH_NO_RESULTS -> hasSearchNoResults = true;
                    case GROUPED_OPERATIONS -> hasGroupedOperations = true;
                    case INTERNAL -> hasInternal = true;
                }
            }
            
            assertTrue(hasValidation, "Should have VALIDATION error type");
            assertTrue(hasResourceNotFound, "Should have RESOURCE_NOT_FOUND error type");
            assertTrue(hasDataTypeParsing, "Should have DATA_TYPE_PARSING error type");
            assertTrue(hasExecution, "Should have EXECUTION error type");
            assertTrue(hasPermissionState, "Should have PERMISSION_STATE error type");
            assertTrue(hasToolExecution, "Should have TOOL_EXECUTION error type");
            assertTrue(hasSearchNoResults, "Should have SEARCH_NO_RESULTS error type");
            assertTrue(hasGroupedOperations, "Should have GROUPED_OPERATIONS error type");
            assertTrue(hasInternal, "Should have INTERNAL error type");
        }
    }

    @Nested
    @DisplayName("Error Code Enum Tests")
    class ErrorCodeEnumTests {

        @Test
        @DisplayName("Should have all expected error codes")
        void shouldHaveAllExpectedErrorCodes() {
            GhidraMcpError.ErrorCode[] errorCodes = GhidraMcpError.ErrorCode.values();
            
            assertTrue(errorCodes.length > 0);
            
            // Check for some expected error codes
            boolean hasMissingRequiredArgument = false;
            boolean hasFunctionNotFound = false;
            boolean hasUnexpectedError = false;
            boolean hasAddressParseFailed = false;
            
            for (GhidraMcpError.ErrorCode code : errorCodes) {
                switch (code) {
                    case MISSING_REQUIRED_ARGUMENT -> hasMissingRequiredArgument = true;
                    case FUNCTION_NOT_FOUND -> hasFunctionNotFound = true;
                    case UNEXPECTED_ERROR -> hasUnexpectedError = true;
                    case ADDRESS_PARSE_FAILED -> hasAddressParseFailed = true;
                }
            }
            
            assertTrue(hasMissingRequiredArgument, "Should have MISSING_REQUIRED_ARGUMENT error code");
            assertTrue(hasFunctionNotFound, "Should have FUNCTION_NOT_FOUND error code");
            assertTrue(hasUnexpectedError, "Should have UNEXPECTED_ERROR error code");
            assertTrue(hasAddressParseFailed, "Should have ADDRESS_PARSE_FAILED error code");
        }

        @Test
        @DisplayName("Should have proper error code format")
        void shouldHaveProperErrorCodeFormat() {
            for (GhidraMcpError.ErrorCode code : GhidraMcpError.ErrorCode.values()) {
                String codeString = code.getCode();
                assertNotNull(codeString, "Error code should not be null");
                assertFalse(codeString.isEmpty(), "Error code should not be empty");
                // Most error codes follow pattern like "VAL_001", "RNF_002", etc.
                assertTrue(codeString.matches("[A-Z]{3}_\\d{3}"), 
                    "Error code should follow pattern XXX_###: " + codeString);
            }
        }
    }

    @Nested
    @DisplayName("ErrorContext Tests")
    class ErrorContextTests {

        @Test
        @DisplayName("Should create context with all fields")
        void shouldCreateContextWithAllFields() {
            String operation = "test_operation";
            String targetResource = "test_resource";
            Map<String, Object> arguments = Map.of("arg1", "value1");
            Map<String, Object> attemptedValues = Map.of("attempted", "value");
            Map<String, Object> validationDetails = Map.of("validation", "failed");

            GhidraMcpError.ErrorContext context = new GhidraMcpError.ErrorContext(
                operation,
                targetResource,
                arguments,
                attemptedValues,
                validationDetails
            );

            assertNotNull(context);
            assertEquals(operation, context.getOperation());
            assertEquals(targetResource, context.getTargetResource());
            assertEquals(arguments, context.getArguments());
            assertEquals(attemptedValues, context.getAttemptedValues());
            assertEquals(validationDetails, context.getValidationDetails());
        }

        @Test
        @DisplayName("Should create context with null fields")
        void shouldCreateContextWithNullFields() {
            GhidraMcpError.ErrorContext context = new GhidraMcpError.ErrorContext(
                null, null, null, null, null
            );

            assertNotNull(context);
            assertNull(context.getOperation());
            assertNull(context.getTargetResource());
            assertNull(context.getArguments());
            assertNull(context.getAttemptedValues());
            assertNull(context.getValidationDetails());
        }
    }

    @Nested
    @DisplayName("ErrorSuggestion Tests")
    class ErrorSuggestionTests {

        @Test
        @DisplayName("Should create suggestion with all fields")
        void shouldCreateSuggestionWithAllFields() {
            GhidraMcpError.ErrorSuggestion.SuggestionType type = 
                GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST;
            String message = "Fix the request";
            String action = "Provide valid arguments";
            List<String> examples = List.of("example1", "example2");
            List<String> relatedTools = List.of("tool1", "tool2");

            GhidraMcpError.ErrorSuggestion suggestion = new GhidraMcpError.ErrorSuggestion(
                type, message, action, examples, relatedTools
            );

            assertNotNull(suggestion);
            assertEquals(type, suggestion.getType());
            assertEquals(message, suggestion.getMessage());
            assertEquals(action, suggestion.getAction());
            assertEquals(examples, suggestion.getExamples());
            assertEquals(relatedTools, suggestion.getRelatedTools());
        }

        @Test
        @DisplayName("Should have all suggestion types")
        void shouldHaveAllSuggestionTypes() {
            GhidraMcpError.ErrorSuggestion.SuggestionType[] types = 
                GhidraMcpError.ErrorSuggestion.SuggestionType.values();

            assertTrue(types.length >= 5);
            
            boolean hasFixRequest = false;
            boolean hasAlternativeApproach = false;
            boolean hasUseDifferentTool = false;
            boolean hasCheckResources = false;
            boolean hasSimilarValues = false;

            for (GhidraMcpError.ErrorSuggestion.SuggestionType type : types) {
                switch (type) {
                    case FIX_REQUEST -> hasFixRequest = true;
                    case ALTERNATIVE_APPROACH -> hasAlternativeApproach = true;
                    case USE_DIFFERENT_TOOL -> hasUseDifferentTool = true;
                    case CHECK_RESOURCES -> hasCheckResources = true;
                    case SIMILAR_VALUES -> hasSimilarValues = true;
                }
            }

            assertTrue(hasFixRequest, "Should have FIX_REQUEST suggestion type");
            assertTrue(hasAlternativeApproach, "Should have ALTERNATIVE_APPROACH suggestion type");
            assertTrue(hasUseDifferentTool, "Should have USE_DIFFERENT_TOOL suggestion type");
            assertTrue(hasCheckResources, "Should have CHECK_RESOURCES suggestion type");
            assertTrue(hasSimilarValues, "Should have SIMILAR_VALUES suggestion type");
        }
    }

    @Nested
    @DisplayName("ErrorDebugInfo Tests")
    class ErrorDebugInfoTests {

        @Test
        @DisplayName("Should create debug info with all fields")
        void shouldCreateDebugInfoWithAllFields() {
            String stackTrace = "stack trace";
            String ghidraVersion = "Ghidra 10.4";
            String toolClass = "TestTool";
            String timestamp = "2024-01-01T00:00:00Z";
            Map<String, Object> additionalInfo = Map.of("key", "value");

            GhidraMcpError.ErrorDebugInfo debugInfo = new GhidraMcpError.ErrorDebugInfo(
                stackTrace,
                ghidraVersion,
                toolClass,
                timestamp,
                additionalInfo
            );

            assertNotNull(debugInfo);
            assertEquals(stackTrace, debugInfo.getStackTrace());
            assertEquals(ghidraVersion, debugInfo.getGhidraVersion());
            assertEquals(toolClass, debugInfo.getToolClass());
            assertEquals(timestamp, debugInfo.getTimestamp());
            assertEquals(additionalInfo, debugInfo.getAdditionalInfo());
        }

        @Test
        @DisplayName("Should create debug info with null fields")
        void shouldCreateDebugInfoWithNullFields() {
            GhidraMcpError.ErrorDebugInfo debugInfo = new GhidraMcpError.ErrorDebugInfo(
                null, null, null, null, null
            );

            assertNotNull(debugInfo);
            assertNull(debugInfo.getStackTrace());
            assertNull(debugInfo.getGhidraVersion());
            assertNull(debugInfo.getToolClass());
            assertNull(debugInfo.getTimestamp());
            assertNull(debugInfo.getAdditionalInfo());
        }
    }
}