package com.themixednuts.utils;

import com.themixednuts.models.GhidraMcpError;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Utility class for creating error messages. Most methods just delegate to GhidraMcpError factory
 * methods.
 */
public class GhidraMcpErrorUtils {

  public static GhidraMcpError missingRequiredArgument(String toolName, String arg) {
    return GhidraMcpError.missing(arg);
  }

  public static GhidraMcpError addressParseError(String address, String toolName, Throwable cause) {
    return GhidraMcpError.parse("address", address);
  }

  public static GhidraMcpError unexpectedError(String toolName, String op, Throwable cause) {
    return GhidraMcpError.internal(cause);
  }

  public static GhidraMcpError fileNotFound(
      String fileName, List<String> available, String toolName) {
    String hint =
        available != null && !available.isEmpty()
            ? "Available: " + String.join(", ", available.subList(0, Math.min(3, available.size())))
            : null;
    return GhidraMcpError.notFound("File", fileName, hint);
  }

  /**
   * Builds an "invalid action" error with a one-shot recovery suggestion. Sessions show agents
   * looping on the same wrong action because the error message lists valid actions but doesn't
   * point at the closest one — a model can ignore "Must be one of: a, b, c" and try "d" again.
   * Putting "did you mean X?" directly in the message anchors recovery on the next turn.
   *
   * @param invalidValue the action the agent passed (e.g. "find")
   * @param validValues the canonical actions the tool supports
   * @param aliases optional explicit synonym map (lower-cased input → canonical action). Use this
   *     for non-fuzzy mappings like "disassemble" → "listing" where Levenshtein wouldn't match.
   */
  public static GhidraMcpError invalidAction(
      String invalidValue, List<String> validValues, Map<String, String> aliases) {
    String suggestion = suggestActionMatch(invalidValue, validValues, aliases);
    StringBuilder message = new StringBuilder();
    message.append("Invalid action=").append(invalidValue).append(": ");
    if (suggestion != null) {
      message.append("did you mean '").append(suggestion).append("'? ");
    }
    message.append("Must be one of: ").append(String.join(", ", validValues));
    return GhidraMcpError.invalid("action", invalidValue, message.toString());
  }

  /**
   * Returns the closest valid action for {@code invalidValue}: explicit alias map first, then exact
   * prefix/contains match, then Levenshtein distance ≤ 2. Returns {@code null} when nothing is
   * close enough — better silent than wrong.
   */
  public static String suggestActionMatch(
      String invalidValue, List<String> validValues, Map<String, String> aliases) {
    if (invalidValue == null || invalidValue.isBlank() || validValues == null) {
      return null;
    }
    String lower = invalidValue.toLowerCase(Locale.ROOT);
    if (aliases != null && aliases.containsKey(lower)) {
      return aliases.get(lower);
    }
    for (String candidate : validValues) {
      if (candidate.equalsIgnoreCase(invalidValue)) {
        return candidate;
      }
    }
    // Prefix/substring — handles cases like "ref" → "references_to" before Levenshtein gives up.
    String prefixMatch = null;
    for (String candidate : validValues) {
      String candLower = candidate.toLowerCase(Locale.ROOT);
      if (candLower.startsWith(lower) || candLower.contains(lower) || lower.contains(candLower)) {
        if (prefixMatch == null
            || Math.abs(candidate.length() - invalidValue.length())
                < Math.abs(prefixMatch.length() - invalidValue.length())) {
          prefixMatch = candidate;
        }
      }
    }
    if (prefixMatch != null) {
      return prefixMatch;
    }
    String best = null;
    int bestDistance = Integer.MAX_VALUE;
    int threshold = Math.max(2, invalidValue.length() / 3);
    for (String candidate : validValues) {
      int distance = levenshtein(lower, candidate.toLowerCase(Locale.ROOT));
      if (distance < bestDistance && distance <= threshold) {
        bestDistance = distance;
        best = candidate;
      }
    }
    return best;
  }

  private static int levenshtein(String a, String b) {
    int[][] dp = new int[a.length() + 1][b.length() + 1];
    for (int i = 0; i <= a.length(); i++) {
      dp[i][0] = i;
    }
    for (int j = 0; j <= b.length(); j++) {
      dp[0][j] = j;
    }
    for (int i = 1; i <= a.length(); i++) {
      for (int j = 1; j <= b.length(); j++) {
        int cost = a.charAt(i - 1) == b.charAt(j - 1) ? 0 : 1;
        dp[i][j] = Math.min(Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1), dp[i - 1][j - 1] + cost);
      }
    }
    return dp[a.length()][b.length()];
  }
}
