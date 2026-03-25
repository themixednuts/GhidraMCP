package com.themixednuts.completions;

import com.themixednuts.annotation.GhidraMcpCompletion;
import io.modelcontextprotocol.spec.McpSchema.CompleteReference;
import io.modelcontextprotocol.spec.McpSchema.PromptReference;

@GhidraMcpCompletion(refType = "prompt", refName = "compare_binaries", argumentName = "source_file")
public class CompareBinariesSourceFileCompletion extends ProgramNameCompletion {

  public CompareBinariesSourceFileCompletion() {
    super("compare_binaries");
  }

  @Override
  public CompleteReference getReference() {
    return new PromptReference("compare_binaries");
  }

  @Override
  public String getArgumentName() {
    return "source_file";
  }
}
