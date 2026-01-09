package com.themixednuts.models;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for GhidraMcpError model.
 */
class GhidraMcpErrorTest {

    @Nested
    @DisplayName("Factory Method Tests")
    class FactoryMethodTests {

        @Test
        @DisplayName("Should create notFound error")
        void shouldCreateNotFoundError() {
            GhidraMcpError error = GhidraMcpError.notFound("Function", "main");

            assertEquals(GhidraMcpError.ErrorType.RESOURCE_NOT_FOUND, error.getErrorType());
            assertTrue(error.getMsg().contains("Function"));
            assertTrue(error.getMsg().contains("main"));
            assertTrue(error.getMsg().contains("not found"));
        }

        @Test
        @DisplayName("Should create notFound error with hint")
        void shouldCreateNotFoundErrorWithHint() {
            GhidraMcpError error = GhidraMcpError.notFound("Symbol", "foo", "See: read_symbols");

            assertTrue(error.getMsg().contains("Symbol"));
            assertEquals("See: read_symbols", error.getHint());
        }

        @Test
        @DisplayName("Should create missingArg error")
        void shouldCreateMissingArgError() {
            GhidraMcpError error = GhidraMcpError.missingArg("file_name");

            assertEquals(GhidraMcpError.ErrorType.VALIDATION, error.getErrorType());
            assertTrue(error.getMsg().contains("Missing"));
            assertTrue(error.getMsg().contains("file_name"));
        }

        @Test
        @DisplayName("Should create invalidArg error with value")
        void shouldCreateInvalidArgErrorWithValue() {
            GhidraMcpError error = GhidraMcpError.invalidArg("offset", -1, "must be positive");

            assertEquals(GhidraMcpError.ErrorType.VALIDATION, error.getErrorType());
            assertTrue(error.getMsg().contains("offset"));
            assertTrue(error.getMsg().contains("-1"));
            assertTrue(error.getMsg().contains("must be positive"));
        }

        @Test
        @DisplayName("Should create invalidArg error simple")
        void shouldCreateInvalidArgErrorSimple() {
            GhidraMcpError error = GhidraMcpError.invalidArg("action", "must be create or update");

            assertTrue(error.getMsg().contains("action"));
            assertTrue(error.getMsg().contains("must be"));
        }

        @Test
        @DisplayName("Should create parseError")
        void shouldCreateParseError() {
            GhidraMcpError error = GhidraMcpError.parseError("address", "xyz");

            assertEquals(GhidraMcpError.ErrorType.DATA_TYPE_PARSING, error.getErrorType());
            assertTrue(error.getMsg().contains("Cannot parse"));
            assertTrue(error.getMsg().contains("address"));
        }

        @Test
        @DisplayName("Should create failed error")
        void shouldCreateFailedError() {
            GhidraMcpError error = GhidraMcpError.failed("rename", "symbol already exists");

            assertEquals(GhidraMcpError.ErrorType.EXECUTION, error.getErrorType());
            assertTrue(error.getMsg().contains("rename"));
            assertTrue(error.getMsg().contains("failed"));
            assertTrue(error.getMsg().contains("symbol already exists"));
        }

        @Test
        @DisplayName("Should create noResults error")
        void shouldCreateNoResultsError() {
            GhidraMcpError error = GhidraMcpError.noResults("pattern=.*main.*");

            assertEquals(GhidraMcpError.ErrorType.SEARCH_NO_RESULTS, error.getErrorType());
            assertTrue(error.getMsg().contains("No results"));
            assertEquals("Broaden search criteria", error.getHint());
        }

        @Test
        @DisplayName("Should create conflict error")
        void shouldCreateConflictError() {
            GhidraMcpError error = GhidraMcpError.conflict("Multiple matches found");

            assertEquals(GhidraMcpError.ErrorType.VALIDATION, error.getErrorType());
            assertEquals("Multiple matches found", error.getMsg());
        }

        @Test
        @DisplayName("Should create internal error")
        void shouldCreateInternalError() {
            GhidraMcpError error = GhidraMcpError.internal("unexpected null");

            assertEquals(GhidraMcpError.ErrorType.INTERNAL, error.getErrorType());
            assertTrue(error.getMsg().contains("Internal error"));
        }

        @Test
        @DisplayName("Should create generic error with hint")
        void shouldCreateGenericErrorWithHint() {
            GhidraMcpError error = GhidraMcpError.error("Something went wrong", "Try again");

            assertEquals("Something went wrong", error.getMsg());
            assertEquals("Try again", error.getHint());
        }

        @Test
        @DisplayName("Should truncate long values")
        void shouldTruncateLongValues() {
            String longValue = "a".repeat(100);
            GhidraMcpError error = GhidraMcpError.invalidArg("data", longValue, "too long");

            assertTrue(error.getMsg().contains("..."));
            assertTrue(error.getMsg().length() < 200);
        }
    }

    @Nested
    @DisplayName("Builder Pattern Tests")
    class BuilderPatternTests {

        @Test
        @DisplayName("Should build error using builder")
        void shouldBuildErrorUsingBuilder() {
            GhidraMcpError error = GhidraMcpError.validation()
                .msg("Test message")
                .hint("Do something")
                .build();

            assertEquals("Test message", error.getMsg());
            assertEquals("Do something", error.getHint());
            assertEquals(GhidraMcpError.ErrorType.VALIDATION, error.getErrorType());
        }

        @Test
        @DisplayName("Should build minimal error")
        void shouldBuildMinimalError() {
            GhidraMcpError error = GhidraMcpError.internal()
                .msg("Error occurred")
                .build();

            assertEquals("Error occurred", error.getMsg());
            assertNull(error.getHint());
        }

        @Test
        @DisplayName("Should support fix as alias for hint")
        void shouldSupportFixAsAlias() {
            GhidraMcpError error = GhidraMcpError.validation()
                .msg("Invalid")
                .fix("Use correct format")
                .build();

            assertEquals("Use correct format", error.getHint());
        }

        @Test
        @DisplayName("Should support see() to build hint")
        void shouldSupportSeeAsHint() {
            GhidraMcpError error = GhidraMcpError.resourceNotFound()
                .msg("Not found")
                .see("tool1", "tool2")
                .build();

            assertEquals("See: tool1, tool2", error.getHint());
        }

        @Test
        @DisplayName("Should extract action from suggestions as hint")
        void shouldExtractSuggestionAction() {
            GhidraMcpError.ErrorSuggestion suggestion = new GhidraMcpError.ErrorSuggestion(
                GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
                "Message", "Do this", null, null);

            GhidraMcpError error = GhidraMcpError.validation()
                .msg("Test")
                .suggestions(List.of(suggestion))
                .build();

            assertEquals("Do this", error.getHint());
        }
    }

    @Nested
    @DisplayName("Error Type Tests")
    class ErrorTypeTests {

        @Test
        @DisplayName("Should have all error types")
        void shouldHaveAllErrorTypes() {
            assertNotNull(GhidraMcpError.ErrorType.VALIDATION);
            assertNotNull(GhidraMcpError.ErrorType.RESOURCE_NOT_FOUND);
            assertNotNull(GhidraMcpError.ErrorType.DATA_TYPE_PARSING);
            assertNotNull(GhidraMcpError.ErrorType.EXECUTION);
            assertNotNull(GhidraMcpError.ErrorType.PERMISSION_STATE);
            assertNotNull(GhidraMcpError.ErrorType.INTERNAL);
        }

        @Test
        @DisplayName("Should set correct type via builder factory methods")
        void shouldSetCorrectTypeViaFactoryMethods() {
            assertEquals(GhidraMcpError.ErrorType.VALIDATION, 
                GhidraMcpError.validation().msg("x").build().getErrorType());
            assertEquals(GhidraMcpError.ErrorType.RESOURCE_NOT_FOUND, 
                GhidraMcpError.resourceNotFound().msg("x").build().getErrorType());
            assertEquals(GhidraMcpError.ErrorType.EXECUTION, 
                GhidraMcpError.execution().msg("x").build().getErrorType());
        }
    }

    @Nested
    @DisplayName("Error Code Tests")
    class ErrorCodeTests {

        @Test
        @DisplayName("Should have error codes")
        void shouldHaveErrorCodes() {
            assertNotNull(GhidraMcpError.ErrorCode.MISSING_ARG);
            assertNotNull(GhidraMcpError.ErrorCode.INVALID_ARG);
            assertNotNull(GhidraMcpError.ErrorCode.NOT_FOUND);
            assertNotNull(GhidraMcpError.ErrorCode.PARSE_ERROR);
            assertNotNull(GhidraMcpError.ErrorCode.FAILED);
            assertNotNull(GhidraMcpError.ErrorCode.FUNCTION_NOT_FOUND);
            assertNotNull(GhidraMcpError.ErrorCode.UNEXPECTED_ERROR);
        }

        @Test
        @DisplayName("Should return code name")
        void shouldReturnCodeName() {
            assertEquals("MISSING_ARG", GhidraMcpError.ErrorCode.MISSING_ARG.code());
            assertEquals("MISSING_ARG", GhidraMcpError.ErrorCode.MISSING_ARG.getCode());
        }
    }

    @Nested
    @DisplayName("Accessor Tests")
    class AccessorTests {

        @Test
        @DisplayName("getMessage should alias getMsg")
        void getMessageShouldAliasGetMsg() {
            GhidraMcpError error = GhidraMcpError.error("Test");
            assertEquals(error.getMsg(), error.getMessage());
        }

        @Test
        @DisplayName("getCode should return ErrorType name")
        void getCodeShouldReturnTypeName() {
            GhidraMcpError error = GhidraMcpError.validation().msg("x").build();
            assertEquals("VALIDATION", error.getCode());
            assertEquals("VALIDATION", error.getErrorCode());
        }

        @Test
        @DisplayName("getFix should alias getHint")
        void getFixShouldAliasGetHint() {
            GhidraMcpError error = GhidraMcpError.error("x", "hint");
            assertEquals(error.getHint(), error.getFix());
        }
    }

    @Nested
    @DisplayName("JSON Output Tests")
    class JsonOutputTests {

        @Test
        @DisplayName("Should only have msg and hint fields")
        void shouldOnlyOutputMsgAndHintFields() {
            GhidraMcpError error = GhidraMcpError.error("Test message", "Test hint");

            assertEquals("Test message", error.getMsg());
            assertEquals("Test hint", error.getHint());
            assertNull(error.getDetails());
            assertNull(error.getSee());
        }

        @Test
        @DisplayName("hint should be null when not provided")
        void hintShouldBeNullWhenNotProvided() {
            GhidraMcpError error = GhidraMcpError.error("Just a message");

            assertEquals("Just a message", error.getMsg());
            assertNull(error.getHint());
        }
    }
}
