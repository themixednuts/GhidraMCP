package com.themixednuts.completions;

import com.themixednuts.annotation.GhidraMcpCompletion;

@GhidraMcpCompletion(refType = "prompt", refName = "rename_analysis", argumentName = "file_name")
public class RenameAnalysisFileNameCompletion extends ProgramNameCompletion {

  public RenameAnalysisFileNameCompletion() {
    super("rename_analysis");
  }
}
