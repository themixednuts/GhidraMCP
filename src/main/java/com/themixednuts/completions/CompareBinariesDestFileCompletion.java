package com.themixednuts.completions;

import com.themixednuts.annotation.GhidraMcpCompletion;
import io.modelcontextprotocol.spec.McpSchema.CompleteReference;
import io.modelcontextprotocol.spec.McpSchema.PromptReference;

@GhidraMcpCompletion(
    refType = "prompt",
    refName = "compare_binaries",
    argumentName = "destination_file")
public class CompareBinariesDestFileCompletion extends ProgramNameCompletion {

  public CompareBinariesDestFileCompletion() {
    super("compare_binaries");
  }

  @Override
  public CompleteReference getReference() {
    return new PromptReference("compare_binaries");
  }

  @Override
  public String getArgumentName() {
    return "destination_file";
  }
}
