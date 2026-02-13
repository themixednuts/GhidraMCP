package com.themixednuts.completions;

import com.themixednuts.annotation.GhidraMcpCompletion;

@GhidraMcpCompletion(
    refType = "prompt",
    refName = "analyze_function",
    argumentName = "function_address")
public class AnalyzeFunctionAddressCompletion extends FunctionAddressCompletion {

  public AnalyzeFunctionAddressCompletion() {
    super("analyze_function");
  }
}
