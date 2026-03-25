package com.themixednuts.utils;

import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import ghidra.app.util.NamespaceUtils;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.StreamSupport;

/**
 * Shared helpers for resolving functions and symbols by name, with namespace-qualified and wildcard
 * support.
 *
 * <p>All tools that look up functions by name should delegate here so that the cascading logic
 * (exact → namespace-qualified → wildcard) stays consistent and improvements are applied
 * everywhere.
 */
public final class SymbolLookupHelper {

  private static final int MAX_MATCH_SUGGESTIONS = 10;

  private SymbolLookupHelper() {}

  // =================== Function Lookup ===================

  /**
   * Resolves a single {@link Function} by name using a cascading strategy:
   *
   * <ol>
   *   <li><b>Exact bare-name match</b> (only when the name has no {@code ::} or wildcards) — fast
   *       symbol-table lookup.
   *   <li><b>Namespace-qualified match</b> (when the name contains {@code ::}) — compares against
   *       fully-qualified names; supports wildcards ({@code *}, {@code ?}) matched as globs against
   *       the qualified name.
   *   <li><b>Bare-name wildcard match</b> (when the name has {@code *} or {@code ?} but no {@code
   *       ::}) — uses Ghidra's native symbol iterator.
   * </ol>
   *
   * @throws GhidraMcpException with a descriptive conflict error listing matches if more than one
   *     function matches, or a not-found error if none match.
   */
  public static Function resolveFunction(Program program, String name) {
    if (name == null || name.isBlank()) {
      throw new GhidraMcpException(GhidraMcpError.missing("name"));
    }

    FunctionManager functionManager = program.getFunctionManager();
    SymbolTable symbolTable = program.getSymbolTable();
    boolean hasNamespaceSeparator = name.contains("::");
    boolean hasWildcard = name.contains("*") || name.contains("?");

    // --- Mode 1: Exact bare-name match (no :: or wildcards) ---
    if (!hasNamespaceSeparator && !hasWildcard) {
      List<Function> exactMatches = collectFunctionSymbols(symbolTable, functionManager, name);

      if (exactMatches.size() == 1) {
        return exactMatches.get(0);
      }
      if (exactMatches.size() > 1) {
        throw buildAmbiguousError(name, exactMatches);
      }
    }

    // --- Mode 2: Namespace-qualified match (exact or wildcard) ---
    if (hasNamespaceSeparator) {
      java.util.function.Predicate<String> matcher;
      if (hasWildcard) {
        Pattern pattern = Pattern.compile(wildcardToRegex(name));
        matcher = qn -> pattern.matcher(qn).matches();
      } else {
        matcher = qn -> qn.equals(name);
      }

      List<Function> qualifiedMatches =
          StreamSupport.stream(functionManager.getFunctions(true).spliterator(), false)
              .filter(
                  f -> {
                    String qualifiedName =
                        NamespaceUtils.getNamespaceQualifiedName(
                            f.getParentNamespace(), f.getName(), false);
                    return matcher.test(qualifiedName);
                  })
              .toList();

      if (qualifiedMatches.size() == 1) {
        return qualifiedMatches.get(0);
      }
      if (qualifiedMatches.size() > 1) {
        throw buildAmbiguousError(name, qualifiedMatches);
      }
    }

    // --- Mode 3: Bare-name wildcard match (no ::) ---
    if (hasWildcard && !hasNamespaceSeparator) {
      List<Function> wildcardMatches =
          collectWildcardFunctionSymbols(symbolTable, functionManager, name);

      if (wildcardMatches.size() == 1) {
        return wildcardMatches.get(0);
      }
      if (wildcardMatches.size() > 1) {
        throw buildAmbiguousError(name, wildcardMatches);
      }
    }

    throw new GhidraMcpException(GhidraMcpError.notFound("function", "name=" + name));
  }

  // =================== Symbol Lookup ===================

  /**
   * Resolves a single {@link Symbol} by name using a cascading strategy similar to {@link
   * #resolveFunction}:
   *
   * <ol>
   *   <li>Exact bare-name match via symbol table.
   *   <li>Namespace-qualified match (when name contains {@code ::}), with optional wildcard
   *       support.
   *   <li>Bare-name wildcard match via Ghidra's native symbol iterator.
   * </ol>
   *
   * @throws GhidraMcpException with a descriptive conflict error listing matches if more than one
   *     symbol matches, or a not-found error if none match.
   */
  public static Symbol resolveSymbol(Program program, String name) {
    if (name == null || name.isBlank()) {
      throw new GhidraMcpException(GhidraMcpError.missing("name"));
    }

    SymbolTable symbolTable = program.getSymbolTable();
    boolean hasNamespaceSeparator = name.contains("::");
    boolean hasWildcard = name.contains("*") || name.contains("?");

    // --- Mode 1: Exact bare-name match ---
    if (!hasNamespaceSeparator && !hasWildcard) {
      List<Symbol> exactMatches = new ArrayList<>();
      SymbolIterator exactIter = symbolTable.getSymbols(name);
      while (exactIter.hasNext()) {
        exactMatches.add(exactIter.next());
      }

      if (exactMatches.size() == 1) {
        return exactMatches.get(0);
      }
      if (exactMatches.size() > 1) {
        throw buildAmbiguousSymbolError(name, exactMatches);
      }
    }

    // --- Mode 2: Namespace-qualified match (exact or wildcard) ---
    if (hasNamespaceSeparator) {
      java.util.function.Predicate<String> matcher;
      if (hasWildcard) {
        Pattern pattern = Pattern.compile(wildcardToRegex(name));
        matcher = qn -> pattern.matcher(qn).matches();
      } else {
        matcher = qn -> qn.equals(name);
      }

      List<Symbol> qualifiedMatches = new ArrayList<>();
      SymbolIterator allIter = symbolTable.getAllSymbols(true);
      while (allIter.hasNext()) {
        Symbol symbol = allIter.next();
        String qualifiedName =
            NamespaceUtils.getNamespaceQualifiedName(
                symbol.getParentNamespace(), symbol.getName(), false);
        if (matcher.test(qualifiedName)) {
          qualifiedMatches.add(symbol);
        }
      }

      if (qualifiedMatches.size() == 1) {
        return qualifiedMatches.get(0);
      }
      if (qualifiedMatches.size() > 1) {
        throw buildAmbiguousSymbolError(name, qualifiedMatches);
      }
    }

    // --- Mode 3: Bare-name wildcard match ---
    if (hasWildcard && !hasNamespaceSeparator) {
      List<Symbol> wildcardMatches = new ArrayList<>();
      SymbolIterator wildcardIter = symbolTable.getSymbolIterator(name, false);
      while (wildcardIter.hasNext()) {
        wildcardMatches.add(wildcardIter.next());
      }

      if (wildcardMatches.size() == 1) {
        return wildcardMatches.get(0);
      }
      if (wildcardMatches.size() > 1) {
        throw buildAmbiguousSymbolError(name, wildcardMatches);
      }
    }

    throw new GhidraMcpException(GhidraMcpError.notFound("symbol", "name=" + name));
  }

  // =================== Error Builders ===================

  /**
   * Builds an error that lists the qualified names and addresses of conflicting function matches so
   * that agents can disambiguate by retrying with a fully-qualified name or address.
   */
  public static GhidraMcpException buildAmbiguousError(String name, List<Function> matches) {
    List<String> qualifiedNames =
        matches.stream()
            .limit(MAX_MATCH_SUGGESTIONS)
            .map(
                f ->
                    NamespaceUtils.getNamespaceQualifiedName(
                            f.getParentNamespace(), f.getName(), false)
                        + " @ "
                        + f.getEntryPoint().toString())
            .toList();

    String listing = String.join(", ", qualifiedNames);
    if (matches.size() > MAX_MATCH_SUGGESTIONS) {
      listing += " ... and " + (matches.size() - MAX_MATCH_SUGGESTIONS) + " more";
    }

    return new GhidraMcpException(
        GhidraMcpError.conflict(
            "Multiple functions ("
                + matches.size()
                + ") found for '"
                + name
                + "'. Matches: ["
                + listing
                + "]. Retry with the fully-qualified namespace name"
                + " (e.g. Namespace::Class::Function) or use address for an exact match."));
  }

  /**
   * Builds an error that lists the qualified names of conflicting symbol matches so that agents can
   * disambiguate.
   */
  public static GhidraMcpException buildAmbiguousSymbolError(String name, List<Symbol> matches) {
    List<String> qualifiedNames =
        matches.stream()
            .limit(MAX_MATCH_SUGGESTIONS)
            .map(
                s ->
                    NamespaceUtils.getNamespaceQualifiedName(
                            s.getParentNamespace(), s.getName(), false)
                        + " @ "
                        + s.getAddress().toString()
                        + " ("
                        + s.getSymbolType().toString()
                        + ")")
            .toList();

    String listing = String.join(", ", qualifiedNames);
    if (matches.size() > MAX_MATCH_SUGGESTIONS) {
      listing += " ... and " + (matches.size() - MAX_MATCH_SUGGESTIONS) + " more";
    }

    return new GhidraMcpException(
        GhidraMcpError.conflict(
            "Multiple symbols ("
                + matches.size()
                + ") found for '"
                + name
                + "'. Matches: ["
                + listing
                + "]. Retry with the fully-qualified namespace name"
                + " (e.g. Namespace::Class::Symbol) or use address/symbol_id for an exact"
                + " match."));
  }

  // =================== Internal Helpers ===================

  /** Collects functions from an exact bare-name symbol lookup, deduplicating by entry point. */
  private static List<Function> collectFunctionSymbols(
      SymbolTable symbolTable, FunctionManager functionManager, String name) {
    List<Function> matches = new ArrayList<>();
    SymbolIterator iter = symbolTable.getSymbols(name);
    while (iter.hasNext()) {
      Symbol symbol = iter.next();
      if (symbol.getSymbolType() == SymbolType.FUNCTION) {
        Function function = functionManager.getFunctionAt(symbol.getAddress());
        if (function != null
            && matches.stream()
                .noneMatch(existing -> existing.getEntryPoint().equals(function.getEntryPoint()))) {
          matches.add(function);
        }
      }
    }
    return matches;
  }

  /**
   * Collects functions from a wildcard symbol lookup, deduplicating by entry point. Uses Ghidra's
   * native {@code *} and {@code ?} matching on bare symbol names.
   */
  private static List<Function> collectWildcardFunctionSymbols(
      SymbolTable symbolTable, FunctionManager functionManager, String pattern) {
    List<Function> matches = new ArrayList<>();
    SymbolIterator iter = symbolTable.getSymbolIterator(pattern, false);
    while (iter.hasNext()) {
      Symbol symbol = iter.next();
      if (symbol.getSymbolType() == SymbolType.FUNCTION) {
        Function function = functionManager.getFunctionAt(symbol.getAddress());
        if (function != null
            && matches.stream()
                .noneMatch(existing -> existing.getEntryPoint().equals(function.getEntryPoint()))) {
          matches.add(function);
        }
      }
    }
    return matches;
  }

  /**
   * Converts a name containing {@code *} and {@code ?} wildcards into a regex pattern, escaping all
   * other regex metacharacters.
   */
  public static String wildcardToRegex(String pattern) {
    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < pattern.length(); i++) {
      char c = pattern.charAt(i);
      if (c == '*') {
        sb.append(".*");
      } else if (c == '?') {
        sb.append(".");
      } else if ("\\.[]{}()+^$|".indexOf(c) >= 0) {
        sb.append('\\').append(c);
      } else {
        sb.append(c);
      }
    }
    return sb.toString();
  }
}
