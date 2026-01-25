package com.themixednuts.exceptions;

import static org.junit.jupiter.api.Assertions.*;

import com.themixednuts.models.GhidraMcpError;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/** Unit tests for GhidraMcpException class. */
class GhidraMcpExceptionTest {

  private GhidraMcpError error;
  private GhidraMcpException exception;

  @BeforeEach
  void setUp() {
    error = GhidraMcpError.validation().msg("Test error message").hint("Fix it").build();
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

    @Test
    @DisplayName("Should return correct error type")
    void shouldReturnCorrectErrorType() {
      exception = new GhidraMcpException(error);
      assertEquals(error.getErrorType(), exception.getErrorType());
    }

    @Test
    @DisplayName("Should return correct error code")
    void shouldReturnCorrectErrorCode() {
      exception = new GhidraMcpException(error);
      assertEquals(error.getErrorCode(), exception.getErrorCode());
    }
  }

  @Nested
  @DisplayName("Error Type Check Methods")
  class ErrorTypeCheckMethods {

    @Test
    @DisplayName("Should correctly identify validation error")
    void shouldCorrectlyIdentifyValidationError() {
      exception = new GhidraMcpException(GhidraMcpError.validation().msg("x").build());

      assertTrue(exception.isValidationError());
      assertFalse(exception.isResourceNotFoundError());
      assertFalse(exception.isDataTypeParsingError());
      assertFalse(exception.isExecutionError());
    }

    @Test
    @DisplayName("Should correctly identify resource not found error")
    void shouldCorrectlyIdentifyResourceNotFoundError() {
      exception = new GhidraMcpException(GhidraMcpError.resourceNotFound().msg("x").build());

      assertFalse(exception.isValidationError());
      assertTrue(exception.isResourceNotFoundError());
      assertFalse(exception.isDataTypeParsingError());
      assertFalse(exception.isExecutionError());
    }

    @Test
    @DisplayName("Should correctly identify data type parsing error")
    void shouldCorrectlyIdentifyDataTypeParsingError() {
      exception = new GhidraMcpException(GhidraMcpError.dataTypeParsing().msg("x").build());

      assertFalse(exception.isValidationError());
      assertFalse(exception.isResourceNotFoundError());
      assertTrue(exception.isDataTypeParsingError());
      assertFalse(exception.isExecutionError());
    }

    @Test
    @DisplayName("Should correctly identify execution error")
    void shouldCorrectlyIdentifyExecutionError() {
      exception = new GhidraMcpException(GhidraMcpError.execution().msg("x").build());

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

      exception = GhidraMcpException.fromException(cause, "test_operation", "TestTool");

      assertNotNull(exception);
      assertEquals(cause, exception.getCause());
      assertTrue(exception.getMessage().contains("test_operation"));
      assertTrue(exception.getMessage().contains("Test exception"));
      assertEquals(GhidraMcpError.ErrorType.INTERNAL, exception.getErrorType());
    }

    @Test
    @DisplayName("Should handle null throwable gracefully")
    void shouldHandleNullThrowableGracefully() {
      exception = GhidraMcpException.fromException(null, "test_operation", "TestTool");
      assertNotNull(exception);
      assertTrue(exception.getMessage().contains("Unknown error"));
    }

    @Test
    @DisplayName("wrap() should pass through GhidraMcpException")
    void wrapShouldPassThrough() {
      GhidraMcpException original = new GhidraMcpException(error);
      GhidraMcpException wrapped = GhidraMcpException.wrap(original);
      assertSame(original, wrapped);
    }

    @Test
    @DisplayName("wrap() should convert other exceptions")
    void wrapShouldConvertOthers() {
      RuntimeException cause = new RuntimeException("cause");
      GhidraMcpException wrapped = GhidraMcpException.wrap(cause);
      assertEquals(cause, wrapped.getCause());
      assertEquals(GhidraMcpError.ErrorType.INTERNAL, wrapped.getErrorType());
    }

    @Test
    @DisplayName("of() should create simple exception")
    void ofShouldCreateSimple() {
      exception = GhidraMcpException.of("error message");
      assertEquals("error message", exception.getMessage());
    }

    @Test
    @DisplayName("of() should create exception with hint")
    void ofShouldCreateWithHint() {
      exception = GhidraMcpException.of("error message", "hint");
      assertEquals("error message", exception.getMessage());
      assertEquals("hint", exception.getErr().getHint());
    }
  }

  @Nested
  @DisplayName("ToString Tests")
  class ToStringTests {

    @Test
    @DisplayName("Should return meaningful string representation")
    void shouldReturnMeaningfulStringRepresentation() {
      exception = new GhidraMcpException(error);

      String str = exception.toString();

      assertNotNull(str);
      assertTrue(str.contains("GhidraMcpException"));
      assertTrue(str.contains("VALIDATION"));
      assertTrue(str.contains("Test error message"));
    }

    @Test
    @DisplayName("Should include hint in toString")
    void shouldIncludeHintInToString() {
      exception = new GhidraMcpException(error);
      String str = exception.toString();
      assertTrue(str.contains("Fix it"));
    }
  }

  @Nested
  @DisplayName("Inheritance Tests")
  class InheritanceTests {

    @Test
    @DisplayName("Should be RuntimeException")
    void shouldBeRuntimeException() {
      exception = new GhidraMcpException(error);
      assertTrue(exception instanceof RuntimeException);
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
    @DisplayName("Should handle null error")
    void shouldHandleNullError() {
      exception = new GhidraMcpException(null);
      assertEquals("Unknown error", exception.getMessage());
      assertEquals(GhidraMcpError.ErrorType.INTERNAL, exception.getErrorType());
    }

    @Test
    @DisplayName("Should handle error with null message")
    void shouldHandleErrorWithNullMessage() {
      GhidraMcpError nullMsgError = GhidraMcpError.validation().msg(null).build();
      exception = new GhidraMcpException(nullMsgError);

      assertNotNull(exception);
      assertEquals(nullMsgError, exception.getErr());
    }

    @Test
    @DisplayName("Should handle nested exceptions")
    void shouldHandleNestedExceptions() {
      RuntimeException cause1 = new RuntimeException("Level 1");
      RuntimeException cause2 = new RuntimeException("Level 2", cause1);
      RuntimeException cause3 = new RuntimeException("Level 3", cause2);

      exception = GhidraMcpException.fromException(cause3, "test_operation", "TestTool");

      assertNotNull(exception);
      assertEquals(cause3, exception.getCause());
      assertEquals(cause2, exception.getCause().getCause());
    }
  }
}
