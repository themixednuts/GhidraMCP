package com.themixednuts.utils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.Test;

class TextSearchTest {
  @Test
  void mergesContextAndPagesByMatchingLine() {
    String source = "one\ncall();\nother\ncall();\nfive\nsix\ncall();\neight\n";

    TextSearch first = TextSearch.of(source, "call()", true, 1, 0, 2);
    assertEquals(8, first.totalLines());
    assertEquals(3, first.totalMatches());
    assertEquals(1, first.omittedMatches());
    assertEquals(2, first.nextMatchOffset());
    assertEquals(List.of(2, 4), first.matchingLines());
    assertTrue(first.excerpt().contains("> 2 | call();"));
    assertTrue(first.excerpt().contains("  3 | other"));
    assertFalse(first.excerpt().contains("  7 |"));

    TextSearch second = TextSearch.of(source, "call()", true, 1, 2, 2);
    assertEquals(List.of(7), second.matchingLines());
    assertEquals(2, second.omittedMatches());
    assertNull(second.nextMatchOffset());
  }

  @Test
  void literalCaseInsensitiveSearchFindsMetacharactersAndHandlesEmptyResult() {
    TextSearch found = TextSearch.of("abc\r\nFoo.*Bar\r\n", ".*bar", false, 0, 0, 10);
    assertEquals(List.of(2), found.matchingLines());
    assertTrue(found.excerpt().contains("> 2 | Foo.*Bar"));

    TextSearch absent = TextSearch.of("abc\n", "missing", false, 2, 0, 10);
    assertEquals(0, absent.totalMatches());
    assertTrue(absent.excerpt().isEmpty());
  }

  @Test
  void longMatchingLineKeepsMatchVisible() {
    String source = "x".repeat(800) + "target" + "y".repeat(800);
    TextSearch found = TextSearch.of(source, "target", true, 0, 0, 10);
    assertTrue(found.excerpt().contains("target"));
    assertTrue(found.excerpt().length() < 530);
  }
}
