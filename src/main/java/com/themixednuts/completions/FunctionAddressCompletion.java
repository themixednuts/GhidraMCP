package com.themixednuts.completions;

import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.utils.GhidraStateUtils;
import ghidra.framework.model.DomainFile;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.common.McpTransportContext;
import io.modelcontextprotocol.spec.McpSchema.CompleteReference;
import io.modelcontextprotocol.spec.McpSchema.CompleteResult;
import io.modelcontextprotocol.spec.McpSchema.PromptReference;
import java.util.ArrayList;
import java.util.List;
import reactor.core.publisher.Mono;

/**
 * Provides auto-completion for function addresses. Suggests function names and their addresses
 * based on partial input.
 */
public class FunctionAddressCompletion extends BaseMcpCompletion {

  private final String promptName;

  public FunctionAddressCompletion(String promptName) {
    this.promptName = promptName;
  }

  @Override
  public CompleteReference getReference() {
    return new PromptReference(promptName);
  }

  @Override
  public String getArgumentName() {
    return "function_address";
  }

  @Override
  public Mono<CompleteResult> complete(
      McpTransportContext context, String argumentValue, PluginTool tool) {
    return Mono.fromCallable(
        () -> {
          List<String> suggestions = new ArrayList<>();

          try {
            // Get all files from project
            List<DomainFile> files = GhidraStateUtils.getAllFiles();

            // Search first available program
            if (!files.isEmpty()) {
              DomainFile file = files.get(0);
              try {
                var obj = file.getDomainObject(this, true, false, null);
                if (obj instanceof Program program) {
                  try {
                    collectFunctionSuggestions(program, argumentValue, suggestions);
                  } finally {
                    program.release(this);
                  }
                }
              } catch (Exception e) {
                // Ignore and return empty suggestions
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

  private void collectFunctionSuggestions(
      Program program, String prefix, List<String> suggestions) {
    FunctionIterator funcIter = program.getFunctionManager().getFunctions(true);
    String lowerPrefix = prefix.toLowerCase();

    while (funcIter.hasNext() && suggestions.size() < MAX_COMPLETIONS) {
      Function func = funcIter.next();
      String name = func.getName();
      String address = func.getEntryPoint().toString();

      // Match by name or address
      if (prefix.isEmpty()
          || name.toLowerCase().contains(lowerPrefix)
          || address.toLowerCase().contains(lowerPrefix)) {
        // Return address with function name as comment
        suggestions.add(address + " // " + name);
      }
    }
  }
}
