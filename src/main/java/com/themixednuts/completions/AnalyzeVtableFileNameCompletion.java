package com.themixednuts.completions;

import com.themixednuts.annotation.GhidraMcpCompletion;

@GhidraMcpCompletion(refType = "prompt", refName = "analyze_vtable", argumentName = "file_name")
public class AnalyzeVtableFileNameCompletion extends ProgramNameCompletion {

  public AnalyzeVtableFileNameCompletion() {
    super("analyze_vtable");
  }
}
