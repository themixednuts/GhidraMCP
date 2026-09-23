package com.themixednuts.utils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.Test;

class TextWindowTest {

  @Test
  void windowsPreserveLineEndingsAndContinuation() {
    String source = "first\r\nsecond\r\nthird\r\n";

    TextWindow first = TextWindow.of(source, 1, 2);
    assertEquals("first\r\nsecond\r\n", first.text());
    assertEquals(3, first.totalLines());
    assertEquals(3, first.nextLine());

    TextWindow last = TextWindow.of(source, first.nextLine(), 2);
    assertEquals("third\r\n", last.text());
    assertEquals(3, last.startLine());
    assertNull(last.nextLine());
  }

  @Test
  void zeroLimitReturnsFullRemainingText() {
    TextWindow window = TextWindow.of("one\ntwo\nthree", 2, 0);
    assertEquals("two\nthree", window.text());
    assertEquals(3, window.totalLines());
    assertNull(window.nextLine());
  }
}
