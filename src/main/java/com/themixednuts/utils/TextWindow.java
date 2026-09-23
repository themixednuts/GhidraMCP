package com.themixednuts.utils;

/** A one-based line window over text, preserving the original line endings. */
public record TextWindow(String text, int startLine, int totalLines, Integer nextLine) {

  public static TextWindow of(String text, int startLine, int maxLines) {
    if (startLine < 1 || maxLines < 0) {
      throw new IllegalArgumentException("startLine must be positive and maxLines non-negative");
    }

    int totalLines = text.isEmpty() ? 0 : 1;
    for (int i = 0; i < text.length(); i++) {
      if (text.charAt(i) == '\n' && i + 1 < text.length()) {
        totalLines++;
      }
    }

    if (startLine > totalLines) {
      return new TextWindow("", startLine, totalLines, null);
    }

    int first = 0;
    for (int line = 1; line < startLine; line++) {
      first = text.indexOf('\n', first) + 1;
    }

    int end = text.length();
    Integer nextLine = null;
    if (maxLines > 0) {
      int scan = first;
      for (int line = 0; line < maxLines; line++) {
        int newline = text.indexOf('\n', scan);
        if (newline < 0) {
          break;
        }
        scan = newline + 1;
        if (line == maxLines - 1 && scan < text.length()) {
          end = scan;
          nextLine = startLine + maxLines;
        }
      }
    }
    return new TextWindow(text.substring(first, end), startLine, totalLines, nextLine);
  }
}
