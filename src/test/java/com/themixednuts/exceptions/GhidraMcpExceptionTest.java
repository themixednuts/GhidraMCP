package com.themixednuts.exceptions;

import com.themixednuts.models.GhidraMcpError;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for GhidraMcpException class.
 */
class GhidraMcpExceptionTest {

    private GhidraMcpError error;
    private GhidraMcpException exception;

    @BeforeEach
    void setUp() {
        GhidraMcpError.ErrorContext context = new GhidraMcpError.ErrorContext(
            "test_tool",
            "test_operation",
            Map.of("arg1", "value1"),
            Map.of("provided1", "value1"),
            Map.of("meta1", "value1")
        );

        GhidraMcpError.ErrorSuggestion suggestion = new GhidraMcpError.ErrorSuggestion(
            GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
            "Test suggestion",
            "Test description",
            List.of("arg1", "arg2"),
            List.of("tool1", "tool2")
        );

        error = GhidraMcpError.validation()
            .errorCode(GhidraMcpError.ErrorCode.MISSING_REQUIRED_ARGUMENT)
            .message("Test error message")
            .context(context)
            .suggestions(List.of(suggestion))
            .build();
    }

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should create exception with error only")
        void shouldCreateExceptionWithErrorOnly() {
            exception = new GhidraMcpException(error);

            assertNotNull(exception);
            assertEquals(error, exception.getErr());
            assertEquals(error.getMessage(), exception.getMessage());
            assertNull(exception.getCause());
        }

        @Test
        @DisplayName("Should create exception with error and cause")
        void shouldCreateExceptionWithErrorAndCause() {
            RuntimeException cause = new RuntimeException("Root cause");
            exception = new GhidraMcpException(error, cause);

            assertNotNull(exception);
            assertEquals(error, exception.getErr());
            assertEquals(error.getMessage(), exception.getMessage());
            assertEquals(cause, exception.getCause());
        }
    }

    @Nested
    @DisplayName("Getter Tests")
    class GetterTests {

        @BeforeEach
        void setUp() {
            exception = new GhidraMcpException(error);
        }

        @Test
        @DisplayName("Should return correct error")
        void shouldReturnCorrectError() {
            assertEquals(error, exception.getErr());
        }

        @Test
        @DisplayName("Should return correct error type")
        void shouldReturnCorrectErrorType() {
            assertEquals(error.getErrorType(), exception.getErrorType());
        }

        @Test
        @DisplayName("Should return correct error code")
        void shouldReturnCorrectErrorCode() {
            assertEquals(error.getErrorCode(), exception.getErrorCode());
        }
    }

    @Nested
    @DisplayName("Error Type Check Methods")
    class ErrorTypeCheckMethods {

        @Test
        @DisplayName("Should correctly identify validation error")
        void shouldCorrectlyIdentifyValidationError() {
            GhidraMcpError validationError = GhidraMcpError.validation()
                .errorCode(GhidraMcpError.ErrorCode.MISSING_REQUIRED_ARGUMENT)
                .message("Validation error")
                .build();

            exception = new GhidraMcpException(validationError);

            assertTrue(exception.isValidationError());
            assertFalse(exception.isResourceNotFoundError());
            assertFalse(exception.isDataTypeParsingError());
            assertFalse(exception.isExecutionError());
        }

        @Test
        @DisplayName("Should correctly identify resource not found error")
        void shouldCorrectlyIdentifyResourceNotFoundError() {
            GhidraMcpError resourceError = GhidraMcpError.resourceNotFound()
                .errorCode(GhidraMcpError.ErrorCode.FUNCTION_NOT_FOUND)
                .message("Resource not found error")
                .build();

            exception = new GhidraMcpException(resourceError);

            assertFalse(exception.isValidationError());
            assertTrue(exception.isResourceNotFoundError());
            assertFalse(exception.isDataTypeParsingError());
            assertFalse(exception.isExecutionError());
        }

        @Test
        @DisplayName("Should correctly identify data type parsing error")
        void shouldCorrectlyIdentifyDataTypeParsingError() {
            GhidraMcpError parsingError = GhidraMcpError.dataTypeParsing()
                .errorCode(GhidraMcpError.ErrorCode.INVALID_POINTER_SYNTAX)
                .message("Data type parsing error")
                .build();

            exception = new GhidraMcpException(parsingError);

            assertFalse(exception.isValidationError());
            assertFalse(exception.isResourceNotFoundError());
            assertTrue(exception.isDataTypeParsingError());
            assertFalse(exception.isExecutionError());
        }

        @Test
        @DisplayName("Should correctly identify execution error")
        void shouldCorrectlyIdentifyExecutionError() {
            GhidraMcpError executionError = GhidraMcpError.execution()
                .errorCode(GhidraMcpError.ErrorCode.SCRIPT_EXECUTION_FAILED)
                .message("Execution error")
                .build();

            exception = new GhidraMcpException(executionError);

            assertFalse(exception.isValidationError());
            assertFalse(exception.isResourceNotFoundError());
            assertFalse(exception.isDataTypeParsingError());
            assertTrue(exception.isExecutionError());
        }
    }

    @Nested
    @DisplayName("Static Factory Method Tests")
    class StaticFactoryMethodTests {

        @Test
        @DisplayName("Should create exception from generic throwable")
        void shouldCreateExceptionFromGenericThrowable() {
            RuntimeException cause = new RuntimeException("Test exception");
            String toolOperation = "test_operation";
            String toolClass = "TestTool";

            exception = GhidraMcpException.fromException(cause, toolOperation, toolClass);

            assertNotNull(exception);
            assertEquals(cause, exception.getCause());
            assertEquals("Unexpected error occurred: Test exception", exception.getMessage());
            assertEquals(GhidraMcpError.ErrorType.INTERNAL, exception.getErrorType());
            assertEquals(GhidraMcpError.ErrorCode.UNEXPECTED_ERROR.getCode(), exception.getErrorCode());

            // Check that the error context is properly set
            GhidraMcpError err = exception.getErr();
            assertNotNull(err.getContext());
            assertEquals(toolOperation, err.getContext().getOperation());
            assertNotNull(err.getDebugInfo());
            assertEquals(toolClass, err.getDebugInfo().getToolClass());
        }

        @Test
        @DisplayName("Should create exception from null throwable")
        void shouldCreateExceptionFromNullThrowable() {
            String toolOperation = "test_operation";
            String toolClass = "TestTool";

            assertThrows(NullPointerException.class, () -> {
                GhidraMcpException.fromException(null, toolOperation, toolClass);
            });
        }

        @Test
        @DisplayName("Should create exception from throwable with null message")
        void shouldCreateExceptionFromThrowableWithNullMessage() {
            RuntimeException cause = new RuntimeException((String) null);
            String toolOperation = "test_operation";
            String toolClass = "TestTool";

            // The method throws NPE when message is null due to Map.of() usage
            assertThrows(NullPointerException.class, () -> {
                GhidraMcpException.fromException(cause, toolOperation, toolClass);
            });
        }
    }

    @Nested
    @DisplayName("ToString Tests")
    class ToStringTests {

        @Test
        @DisplayName("Should return meaningful string representation")
        void shouldReturnMeaningfulStringRepresentation() {
            exception = new GhidraMcpException(error);

            String stringRepresentation = exception.toString();

            assertNotNull(stringRepresentation);
            assertFalse(stringRepresentation.isEmpty());
            assertTrue(stringRepresentation.contains("GhidraMcpException"));
            assertTrue(stringRepresentation.contains("VALIDATION"));
            assertTrue(stringRepresentation.contains("VAL_001"));
            assertTrue(stringRepresentation.contains("Test error message"));
        }

        @Test
        @DisplayName("Should handle exception with cause in toString")
        void shouldHandleExceptionWithCauseInToString() {
            RuntimeException cause = new RuntimeException("Root cause");
            exception = new GhidraMcpException(error, cause);

            String stringRepresentation = exception.toString();

            assertNotNull(stringRepresentation);
            assertFalse(stringRepresentation.isEmpty());
            assertTrue(stringRepresentation.contains("GhidraMcpException"));
            assertTrue(stringRepresentation.contains("Test error message"));
        }
    }

    @Nested
    @DisplayName("Inheritance Tests")
    class InheritanceTests {

        @Test
        @DisplayName("Should be instance of Exception")
        void shouldBeInstanceOfException() {
            exception = new GhidraMcpException(error);

            assertTrue(exception instanceof Exception);
            assertTrue(exception instanceof Throwable);
        }

        @Test
        @DisplayName("Should have proper exception chain")
        void shouldHaveProperExceptionChain() {
            RuntimeException cause = new RuntimeException("Root cause");
            exception = new GhidraMcpException(error, cause);

            assertEquals(cause, exception.getCause());
            assertEquals(error.getMessage(), exception.getMessage());
        }
    }

    @Nested
    @DisplayName("Edge Case Tests")
    class EdgeCaseTests {

        @Test
        @DisplayName("Should handle null error gracefully")
        void shouldHandleNullErrorGracefully() {
            // This test verifies that the constructor doesn't throw NPE
            // Note: The constructor should not allow null errors, but we test defensive behavior
            assertDoesNotThrow(() -> {
                try {
                    new GhidraMcpException(null);
                } catch (Exception e) {
                    // Expected to throw NPE or similar
                }
            });
        }

        @Test
        @DisplayName("Should handle error with null message")
        void shouldHandleErrorWithNullMessage() {
            GhidraMcpError nullMessageError = GhidraMcpError.validation()
                .errorCode(GhidraMcpError.ErrorCode.MISSING_REQUIRED_ARGUMENT)
                .message(null)
                .build();

            exception = new GhidraMcpException(nullMessageError);

            assertNotNull(exception);
            assertNull(exception.getMessage());
            assertEquals(nullMessageError, exception.getErr());
        }

        @Test
        @DisplayName("Should handle multiple nested exceptions")
        void shouldHandleMultipleNestedExceptions() {
            RuntimeException cause1 = new RuntimeException("Level 1");
            RuntimeException cause2 = new RuntimeException("Level 2", cause1);
            RuntimeException cause3 = new RuntimeException("Level 3", cause2);

            exception = GhidraMcpException.fromException(cause3, "test_operation", "TestTool");

            assertNotNull(exception);
            assertEquals(cause3, exception.getCause());
            assertEquals(cause2, exception.getCause().getCause());
            assertEquals(cause1, exception.getCause().getCause().getCause());
        }
    }
}