package com.themixednuts.models;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/** Unit tests for GhidraMcpError model. */
class GhidraMcpErrorTest {

  @Nested
  @DisplayName("Factory Method Tests")
  class FactoryMethodTests {

    @Test
    @DisplayName("Should create notFound error")
    void shouldCreateNotFoundError() {
      GhidraMcpError error = GhidraMcpError.notFound("Function", "main");

      assertEquals(GhidraMcpError.ErrorType.RESOURCE_NOT_FOUND, error.getErrorType());
      assertTrue(error.getMessage().contains("Function"));
      assertTrue(error.getMessage().contains("main"));
      assertTrue(error.getMessage().contains("not found"));
    }

    @Test
    @DisplayName("Should create notFound error with hint")
    void shouldCreateNotFoundErrorWithHint() {
      GhidraMcpError error = GhidraMcpError.notFound("Symbol", "foo", "See: read_symbols");

      assertTrue(error.getMessage().contains("Symbol"));
      assertEquals("See: read_symbols", error.getHint());
    }

    @Test
    @DisplayName("Should create missing error")
    void shouldCreateMissingArgError() {
      GhidraMcpError error = GhidraMcpError.missing("file_name");

      assertEquals(GhidraMcpError.ErrorType.VALIDATION, error.getErrorType());
      assertTrue(error.getMessage().contains("Missing"));
      assertTrue(error.getMessage().contains("file_name"));
    }

    @Test
    @DisplayName("Should create invalid error with value")
    void shouldCreateInvalidArgErrorWithValue() {
      GhidraMcpError error = GhidraMcpError.invalid("offset", -1, "must be positive");

      assertEquals(GhidraMcpError.ErrorType.VALIDATION, error.getErrorType());
      assertTrue(error.getMessage().contains("offset"));
      assertTrue(error.getMessage().contains("-1"));
      assertTrue(error.getMessage().contains("must be positive"));
    }

    @Test
    @DisplayName("Should create invalid error simple")
    void shouldCreateInvalidArgErrorSimple() {
      GhidraMcpError error = GhidraMcpError.invalid("action", "must be create or update");

      assertTrue(error.getMessage().contains("action"));
      assertTrue(error.getMessage().contains("must be"));
    }

    @Test
    @DisplayName("Should create parseError")
    void shouldCreateParseError() {
      GhidraMcpError error = GhidraMcpError.parse("address", "xyz");

      assertEquals(GhidraMcpError.ErrorType.DATA_TYPE_PARSING, error.getErrorType());
      assertTrue(error.getMessage().contains("Cannot parse"));
      assertTrue(error.getMessage().contains("address"));
    }

    @Test
    @DisplayName("Should create failed error")
    void shouldCreateFailedError() {
      GhidraMcpError error = GhidraMcpError.failed("rename", "symbol already exists");

      assertEquals(GhidraMcpError.ErrorType.EXECUTION, error.getErrorType());
      assertTrue(error.getMessage().contains("rename"));
      assertTrue(error.getMessage().contains("failed"));
      assertTrue(error.getMessage().contains("symbol already exists"));
    }

    @Test
    @DisplayName("Should create noResults error")
    void shouldCreateNoResultsError() {
      GhidraMcpError error = GhidraMcpError.noResults("pattern=.*main.*");

      assertEquals(GhidraMcpError.ErrorType.SEARCH_NO_RESULTS, error.getErrorType());
      assertTrue(error.getMessage().contains("No results"));
      assertEquals("Broaden search criteria", error.getHint());
    }

    @Test
    @DisplayName("Should create conflict error")
    void shouldCreateConflictError() {
      GhidraMcpError error = GhidraMcpError.conflict("Multiple matches found");

      assertEquals(GhidraMcpError.ErrorType.VALIDATION, error.getErrorType());
      assertEquals("Multiple matches found", error.getMessage());
    }

    @Test
    @DisplayName("Should create internal error")
    void shouldCreateInternalError() {
      GhidraMcpError error = GhidraMcpError.internal("unexpected null");

      assertEquals(GhidraMcpError.ErrorType.INTERNAL, error.getErrorType());
      assertTrue(error.getMessage().contains("Internal error"));
    }

    @Test
    @DisplayName("Should create generic error with hint")
    void shouldCreateGenericErrorWithHint() {
      GhidraMcpError error = GhidraMcpError.error("Something went wrong", "Try again");

      assertEquals("Something went wrong", error.getMessage());
      assertEquals("Try again", error.getHint());
    }

    @Test
    @DisplayName("Should truncate long values")
    void shouldTruncateLongValues() {
      String longValue = "a".repeat(100);
      GhidraMcpError error = GhidraMcpError.invalid("data", longValue, "too long");

      assertTrue(error.getMessage().contains("..."));
      assertTrue(error.getMessage().length() < 200);
    }
  }

  @Nested
  @DisplayName("Builder Pattern Tests")
  class BuilderPatternTests {

    @Test
    @DisplayName("Should build error using builder")
    void shouldBuildErrorUsingBuilder() {
      GhidraMcpError error =
          GhidraMcpError.validation().message("Test message").hint("Do something").build();

      assertEquals("Test message", error.getMessage());
      assertEquals("Do something", error.getHint());
      assertEquals(GhidraMcpError.ErrorType.VALIDATION, error.getErrorType());
    }

    @Test
    @DisplayName("Should build minimal error")
    void shouldBuildMinimalError() {
      GhidraMcpError error = GhidraMcpError.internal().message("Error occurred").build();

      assertEquals("Error occurred", error.getMessage());
      assertNull(error.getHint());
    }

    @Test
    @DisplayName("Should support fix as alias for hint")
    void shouldSupportFixAsAlias() {
      GhidraMcpError error =
          GhidraMcpError.validation().message("Invalid").fix("Use correct format").build();

      assertEquals("Use correct format", error.getHint());
    }

    @Test
    @DisplayName("Should support see() to build hint")
    void shouldSupportSeeAsHint() {
      GhidraMcpError error =
          GhidraMcpError.resourceNotFound().message("Not found").see("tool1", "tool2").build();

      assertEquals("See: tool1, tool2", error.getHint());
    }

    @Test
    @DisplayName("Should extract action from suggestions as hint")
    void shouldExtractSuggestionAction() {
      GhidraMcpError.ErrorSuggestion suggestion =
          new GhidraMcpError.ErrorSuggestion(
              GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
              "Message",
              "Do this",
              null,
              null);

      GhidraMcpError error =
          GhidraMcpError.validation().message("Test").suggestions(List.of(suggestion)).build();

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
      assertEquals(
          GhidraMcpError.ErrorType.VALIDATION,
          GhidraMcpError.validation().message("x").build().getErrorType());
      assertEquals(
          GhidraMcpError.ErrorType.RESOURCE_NOT_FOUND,
          GhidraMcpError.resourceNotFound().message("x").build().getErrorType());
      assertEquals(
          GhidraMcpError.ErrorType.EXECUTION,
          GhidraMcpError.execution().message("x").build().getErrorType());
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
    @DisplayName("getMessage should return message")
    void getMessageShouldReturnMessage() {
      GhidraMcpError error = GhidraMcpError.error("Test");
      assertEquals("Test", error.getMessage());
    }

    @Test
    @DisplayName("getCode should return payload error code")
    void getCodeShouldReturnTypeName() {
      GhidraMcpError error = GhidraMcpError.validation().message("x").build();
      assertEquals("INVALID_ARGUMENT_VALUE", error.getCode());
      assertEquals("INVALID_ARGUMENT_VALUE", error.getErrorCode());
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
    @DisplayName("Should expose structured error fields")
    void shouldOnlyOutputMsgAndHintFields() {
      GhidraMcpError error = GhidraMcpError.error("Test message", "Test hint");

      assertEquals("Test message", error.getMessage());
      assertEquals("Test hint", error.getHint());
      assertNull(error.getDetails());
      assertNull(error.getSee());
    }

    @Test
    @DisplayName("hint should be null when not provided")
    void hintShouldBeNullWhenNotProvided() {
      GhidraMcpError error = GhidraMcpError.error("Just a message");

      assertEquals("Just a message", error.getMessage());
      assertNull(error.getHint());
    }
  }
}
