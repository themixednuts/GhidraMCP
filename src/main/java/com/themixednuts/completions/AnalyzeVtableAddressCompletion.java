package com.themixednuts.completions;

import com.themixednuts.annotation.GhidraMcpCompletion;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.utils.GhidraStateUtils;
import ghidra.framework.model.DomainFile;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import io.modelcontextprotocol.common.McpTransportContext;
import io.modelcontextprotocol.spec.McpSchema.CompleteReference;
import io.modelcontextprotocol.spec.McpSchema.CompleteResult;
import io.modelcontextprotocol.spec.McpSchema.PromptReference;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import reactor.core.publisher.Mono;

/**
 * Provides auto-completion for vtable addresses. Suggests addresses of symbols whose names contain
 * "vtable", "vftable", or "RTTI" to help locate vtable candidates.
 */
@GhidraMcpCompletion(
    refType = "prompt",
    refName = "analyze_vtable",
    argumentName = "vtable_address")
public class AnalyzeVtableAddressCompletion extends BaseMcpCompletion {

  private static final String PROMPT_NAME = "analyze_vtable";

  @Override
  public CompleteReference getReference() {
    return new PromptReference(PROMPT_NAME);
  }

  @Override
  public String getArgumentName() {
    return "vtable_address";
  }

  @Override
  public Mono<CompleteResult> complete(
      McpTransportContext context,
      String argumentValue,
      Map<String, String> completionContext,
      PluginTool tool) {
    return Mono.fromCallable(
        () -> {
          List<String> suggestions = new ArrayList<>();

          try {
            String scopedProgramName =
                completionContext != null ? completionContext.get("file_name") : null;

            if (scopedProgramName != null && !scopedProgramName.isBlank()) {
              Program program = GhidraStateUtils.getProgramByName(scopedProgramName, this);
              try {
                collectVtableSuggestions(program, argumentValue, suggestions);
              } finally {
                program.release(this);
              }
            } else {
              List<DomainFile> files = GhidraStateUtils.getAllFiles();
              if (!files.isEmpty()) {
                DomainFile file = files.get(0);
                try {
                  var obj = file.getDomainObject(this, true, false, null);
                  if (obj instanceof Program program) {
                    try {
                      collectVtableSuggestions(program, argumentValue, suggestions);
                    } finally {
                      program.release(this);
                    }
                  }
                } catch (Exception e) {
                  // Ignore and return empty suggestions
                }
              }
            }
          } catch (GhidraMcpException e) {
            // No project - return empty suggestions
          }

          return new CompleteResult(
              new CompleteResult.CompleteCompletion(
                  suggestions, suggestions.size(), suggestions.size() >= MAX_COMPLETIONS));
        });
  }

  private void collectVtableSuggestions(Program program, String prefix, List<String> suggestions) {
    String lowerPrefix = prefix.toLowerCase();
    SymbolIterator symIter = program.getSymbolTable().getAllSymbols(true);

    while (symIter.hasNext() && suggestions.size() < MAX_COMPLETIONS) {
      Symbol sym = symIter.next();
      String name = sym.getName().toLowerCase();

      // Match symbols that look like vtables
      if (name.contains("vtable")
          || name.contains("vftable")
          || name.contains("rtti")
          || name.contains("_ztv")
          || name.contains("??_7")) {
        String address = sym.getAddress().toString();
        if (prefix.isEmpty()
            || address.toLowerCase().contains(lowerPrefix)
            || sym.getName().toLowerCase().contains(lowerPrefix)) {
          suggestions.add(address + " // " + sym.getName());
        }
      }
    }
  }
}
