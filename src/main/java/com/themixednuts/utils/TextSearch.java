package com.themixednuts.utils;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/** A bounded literal search over one-based source lines. */
public record TextSearch(
    String excerpt,
    int totalLines,
    int totalMatches,
    int omittedMatches,
    Integer nextMatchOffset,
    List<Integer> matchingLines) {
  private static final int MAX_RENDERED_LINE_CHARS = 500;

  public static TextSearch of(
      String source,
      String query,
      boolean caseSensitive,
      int contextLines,
      int matchOffset,
      int maxMatches) {
    if (query == null || query.isBlank() || query.indexOf('\n') >= 0 || query.indexOf('\r') >= 0) {
      throw new IllegalArgumentException("query must be a nonblank single line");
    }
    if (contextLines < 0 || matchOffset < 0 || maxMatches < 1) {
      throw new IllegalArgumentException(
          "search bounds must be nonnegative and maxMatches positive");
    }

    List<String> lines = splitLines(source);
    String needle = caseSensitive ? query : query.toLowerCase(Locale.ROOT);
    List<Integer> allMatches = new ArrayList<>();
    for (int index = 0; index < lines.size(); index++) {
      String haystack =
          caseSensitive ? lines.get(index) : lines.get(index).toLowerCase(Locale.ROOT);
      if (haystack.contains(needle)) {
        allMatches.add(index + 1);
      }
    }

    int first = Math.min(matchOffset, allMatches.size());
    int last = Math.min(first + maxMatches, allMatches.size());
    List<Integer> selected = List.copyOf(allMatches.subList(first, last));
    List<int[]> spans = new ArrayList<>();
    for (int line : selected) {
      int start = Math.max(1, line - contextLines);
      int end = Math.min(lines.size(), line + contextLines);
      if (!spans.isEmpty() && start <= spans.get(spans.size() - 1)[1] + 1) {
        spans.get(spans.size() - 1)[1] = Math.max(end, spans.get(spans.size() - 1)[1]);
      } else {
        spans.add(new int[] {start, end});
      }
    }

    StringBuilder excerpt = new StringBuilder();
    for (int spanIndex = 0; spanIndex < spans.size(); spanIndex++) {
      if (spanIndex > 0) {
        excerpt.append("...\n");
      }
      int[] span = spans.get(spanIndex);
      for (int line = span[0]; line <= span[1]; line++) {
        boolean matched = selected.contains(line);
        excerpt.append(matched ? "> " : "  ").append(line).append(" | ");
        excerpt.append(renderLine(lines.get(line - 1), query, caseSensitive, matched));
        excerpt.append('\n');
      }
    }

    return new TextSearch(
        excerpt.toString(),
        lines.size(),
        allMatches.size(),
        allMatches.size() - selected.size(),
        last < allMatches.size() ? last : null,
        selected);
  }

  private static List<String> splitLines(String source) {
    if (source.isEmpty()) {
      return List.of();
    }
    String[] parts = source.split("\n", -1);
    int count = parts.length - (parts[parts.length - 1].isEmpty() ? 1 : 0);
    List<String> lines = new ArrayList<>(count);
    for (int index = 0; index < count; index++) {
      String line = parts[index];
      lines.add(line.endsWith("\r") ? line.substring(0, line.length() - 1) : line);
    }
    return lines;
  }

  private static String renderLine(
      String line, String query, boolean caseSensitive, boolean matched) {
    if (line.length() <= MAX_RENDERED_LINE_CHARS) {
      return line;
    }
    int start = 0;
    if (matched) {
      String haystack = caseSensitive ? line : line.toLowerCase(Locale.ROOT);
      String needle = caseSensitive ? query : query.toLowerCase(Locale.ROOT);
      start = Math.max(0, haystack.indexOf(needle) - 120);
    }
    int end = Math.min(line.length(), start + MAX_RENDERED_LINE_CHARS);
    return (start > 0 ? "..." : "")
        + line.substring(start, end)
        + (end < line.length() ? "..." : "");
  }
}
