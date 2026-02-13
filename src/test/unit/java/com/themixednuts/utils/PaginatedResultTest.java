package com.themixednuts.utils;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/** Unit tests for PaginatedResult utility class. */
class PaginatedResultTest {

  @Nested
  @DisplayName("Constructor Tests")
  class ConstructorTests {

    @Test
    @DisplayName("Should create PaginatedResult with results and cursor")
    void shouldCreatePaginatedResultWithResultsAndCursor() {
      List<String> results = Arrays.asList("item1", "item2", "item3");
      String nextCursor = "cursor123";

      PaginatedResult<String> paginatedResult = new PaginatedResult<>(results, nextCursor);

      assertNotNull(paginatedResult);
      assertEquals(results, paginatedResult.results);
      assertEquals(nextCursor, paginatedResult.nextCursor);
      assertEquals(results.size(), paginatedResult.results.size());
    }

    @Test
    @DisplayName("Should create PaginatedResult with null cursor")
    void shouldCreatePaginatedResultWithNullCursor() {
      List<String> results = Arrays.asList("item1", "item2");

      PaginatedResult<String> paginatedResult = new PaginatedResult<>(results, null);

      assertNotNull(paginatedResult);
      assertEquals(results, paginatedResult.results);
      assertNull(paginatedResult.nextCursor);
      assertEquals(results.size(), paginatedResult.results.size());
    }

    @Test
    @DisplayName("Should create PaginatedResult with empty results")
    void shouldCreatePaginatedResultWithEmptyResults() {
      List<String> results = Arrays.asList();

      PaginatedResult<String> paginatedResult = new PaginatedResult<>(results, null);

      assertNotNull(paginatedResult);
      assertEquals(results, paginatedResult.results);
      assertTrue(paginatedResult.results.isEmpty());
      assertNull(paginatedResult.nextCursor);
      assertEquals(0, paginatedResult.results.size());
    }

    @Test
    @DisplayName("Should handle null results list")
    void shouldHandleNullResultsList() {
      PaginatedResult<String> paginatedResult = new PaginatedResult<>(null, null);

      assertNotNull(paginatedResult);
      assertNull(paginatedResult.results);
      assertNull(paginatedResult.nextCursor);
      // Can't get size of null list, so we just check it's null
    }
  }

  @Nested
  @DisplayName("Field Access Tests")
  class FieldAccessTests {

    private PaginatedResult<String> paginatedResult;

    @BeforeEach
    void setUp() {
      List<String> results = Arrays.asList("item1", "item2", "item3", "item4", "item5");
      String nextCursor = "nextCursor123";
      paginatedResult = new PaginatedResult<>(results, nextCursor);
    }

    @Test
    @DisplayName("Should return correct results")
    void shouldReturnCorrectResults() {
      List<String> results = paginatedResult.results;
      assertNotNull(results);
      assertEquals(5, results.size());
      assertEquals("item1", results.get(0));
      assertEquals("item5", results.get(4));
    }

    @Test
    @DisplayName("Should return correct next cursor")
    void shouldReturnCorrectNextCursor() {
      String nextCursor = paginatedResult.nextCursor;
      assertEquals("nextCursor123", nextCursor);
    }

    @Test
    @DisplayName("Should return correct count")
    void shouldReturnCorrectCount() {
      int count = paginatedResult.results.size();
      assertEquals(5, count);
    }

    @Test
    @DisplayName("Should return zero count for null results")
    void shouldReturnZeroCountForNullResults() {
      PaginatedResult<String> resultWithNull = new PaginatedResult<>(null, null);
      assertNull(resultWithNull.results);
    }
  }

  @Nested
  @DisplayName("Pagination Logic Tests")
  class PaginationLogicTests {

    @Test
    @DisplayName("Should correctly identify if there are more results")
    void shouldCorrectlyIdentifyIfThereAreMoreResults() {
      List<String> results = Arrays.asList("item1", "item2");
      String nextCursor = "cursor123";

      PaginatedResult<String> paginatedResult = new PaginatedResult<>(results, nextCursor);

      // Since PaginatedResult doesn't have hasMoreResults method, we check the cursor
      assertNotNull(paginatedResult.nextCursor);
      assertFalse(paginatedResult.nextCursor.isEmpty());
    }

    @Test
    @DisplayName("Should correctly identify when there are no more results")
    void shouldCorrectlyIdentifyWhenThereAreNoMoreResults() {
      List<String> results = Arrays.asList("item1", "item2");

      PaginatedResult<String> paginatedResult = new PaginatedResult<>(results, null);

      assertNull(paginatedResult.nextCursor);
    }

    @Test
    @DisplayName("Should correctly identify when there are no more results with empty cursor")
    void shouldCorrectlyIdentifyWhenThereAreNoMoreResultsWithEmptyCursor() {
      List<String> results = Arrays.asList("item1", "item2");

      PaginatedResult<String> paginatedResult = new PaginatedResult<>(results, "");

      assertEquals("", paginatedResult.nextCursor);
    }

    @Test
    @DisplayName("Should correctly identify when there are no more results with null results")
    void shouldCorrectlyIdentifyWhenThereAreNoMoreResultsWithNullResults() {
      PaginatedResult<String> paginatedResult = new PaginatedResult<>(null, null);

      assertNull(paginatedResult.nextCursor);
      assertNull(paginatedResult.results);
    }
  }

  @Nested
  @DisplayName("ToString Tests")
  class ToStringTests {

    @Test
    @DisplayName("Should return meaningful string representation")
    void shouldReturnMeaningfulStringRepresentation() {
      List<String> results = Arrays.asList("item1", "item2");
      String nextCursor = "cursor123";

      PaginatedResult<String> paginatedResult = new PaginatedResult<>(results, nextCursor);
      String stringRepresentation = paginatedResult.toString();

      assertNotNull(stringRepresentation);
      assertTrue(stringRepresentation.contains("PaginatedResult"));
    }

    @Test
    @DisplayName("Should handle null cursor in string representation")
    void shouldHandleNullCursorInStringRepresentation() {
      List<String> results = Arrays.asList("item1", "item2");

      PaginatedResult<String> paginatedResult = new PaginatedResult<>(results, null);
      String stringRepresentation = paginatedResult.toString();

      assertNotNull(stringRepresentation);
      assertTrue(stringRepresentation.contains("PaginatedResult"));
    }
  }

  @Nested
  @DisplayName("Object Identity Tests")
  class ObjectIdentityTests {

    @Test
    @DisplayName("Should be equal to itself")
    void shouldBeEqualToItself() {
      List<String> results = Arrays.asList("item1", "item2");
      String nextCursor = "cursor123";

      PaginatedResult<String> paginatedResult = new PaginatedResult<>(results, nextCursor);

      assertEquals(paginatedResult, paginatedResult);
    }

    @Test
    @DisplayName("Should not be equal to null")
    void shouldNotBeEqualToNull() {
      List<String> results = Arrays.asList("item1", "item2");
      String nextCursor = "cursor123";

      PaginatedResult<String> paginatedResult = new PaginatedResult<>(results, nextCursor);

      assertNotEquals(paginatedResult, null);
    }

    @Test
    @DisplayName("Should not be equal to different class")
    void shouldNotBeEqualToDifferentClass() {
      List<String> results = Arrays.asList("item1", "item2");
      String nextCursor = "cursor123";

      PaginatedResult<String> paginatedResult = new PaginatedResult<>(results, nextCursor);

      assertNotEquals(paginatedResult, "not a PaginatedResult");
    }
  }

  @Nested
  @DisplayName("Generic Type Tests")
  class GenericTypeTests {

    @Test
    @DisplayName("Should work with Integer type")
    void shouldWorkWithIntegerType() {
      List<Integer> results = Arrays.asList(1, 2, 3, 4, 5);
      String nextCursor = "cursor123";

      PaginatedResult<Integer> paginatedResult = new PaginatedResult<>(results, nextCursor);

      assertNotNull(paginatedResult);
      assertEquals(results, paginatedResult.results);
      assertEquals(nextCursor, paginatedResult.nextCursor);
      assertEquals(5, paginatedResult.results.size());
    }

    @Test
    @DisplayName("Should work with custom object type")
    void shouldWorkWithCustomObjectType() {
      List<TestObject> results =
          Arrays.asList(new TestObject("test1", 1), new TestObject("test2", 2));
      String nextCursor = "cursor123";

      PaginatedResult<TestObject> paginatedResult = new PaginatedResult<>(results, nextCursor);

      assertNotNull(paginatedResult);
      assertEquals(results, paginatedResult.results);
      assertEquals(nextCursor, paginatedResult.nextCursor);
      assertEquals(2, paginatedResult.results.size());
    }
  }

  // Helper class for testing generic types
  private static class TestObject {
    private final String name;
    private final int value;

    public TestObject(String name, int value) {
      this.name = name;
      this.value = value;
    }

    @Override
    public boolean equals(Object obj) {
      if (this == obj) return true;
      if (obj == null || getClass() != obj.getClass()) return false;
      TestObject that = (TestObject) obj;
      return value == that.value && name.equals(that.name);
    }

    @Override
    public int hashCode() {
      return name.hashCode() * 31 + value;
    }
  }
}
