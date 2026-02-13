package com.themixednuts.completions;

import com.themixednuts.annotation.GhidraMcpCompletion;

@GhidraMcpCompletion(
    refType = "prompt",
    refName = "analyze_function",
    argumentName = "file_name")
public class AnalyzeFunctionFileNameCompletion extends ProgramNameCompletion {

  public AnalyzeFunctionFileNameCompletion() {
    super("analyze_function");
  }
}
