package com.themixednuts.utils;

import java.util.regex.Pattern;

/** Compiles function and RTTI name filters as a glob or regular expression. */
public final class NameFilterPattern {
  private NameFilterPattern() {}

  public static Pattern compile(String value, int flags) {
    boolean hasWildcard = value.indexOf('*') >= 0 || value.indexOf('?') >= 0;
    boolean hasRegexSyntax = value.chars().anyMatch(ch -> ".[]{}()+^$|\\".indexOf(ch) >= 0);
    String regex =
        hasWildcard && !hasRegexSyntax ? SymbolLookupHelper.wildcardToRegex(value) : value;
    return Pattern.compile(regex, flags);
  }
}
