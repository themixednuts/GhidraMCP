package com.themixednuts.completions;

import ghidra.framework.plugintool.PluginTool;
import io.modelcontextprotocol.common.McpTransportContext;
import io.modelcontextprotocol.spec.McpSchema.CompleteReference;
import io.modelcontextprotocol.spec.McpSchema.CompleteResult;
import io.modelcontextprotocol.spec.McpSchema.PromptReference;
import java.util.List;
import reactor.core.publisher.Mono;

/**
 * Provides auto-completion for program names (file_name argument). Used by prompts and tools that
 * need to specify a program.
 */
public class ProgramNameCompletion extends BaseMcpCompletion {

  private final String promptName;

  public ProgramNameCompletion(String promptName) {
    this.promptName = promptName;
  }

  @Override
  public CompleteReference getReference() {
    return new PromptReference(promptName);
  }

  @Override
  public String getArgumentName() {
    return "file_name";
  }

  @Override
  public Mono<CompleteResult> complete(
      McpTransportContext context,
      String argumentValue,
      java.util.Map<String, String> completionContext,
      PluginTool tool) {
    return Mono.fromCallable(
        () -> {
          List<String> programNames = getProgramNames(argumentValue);
          List<String> filtered = filterByPrefix(programNames, argumentValue);

          return new CompleteResult(
              new CompleteResult.CompleteCompletion(
                  filtered, programNames.size(), programNames.size() > filtered.size()));
        });
  }
}
