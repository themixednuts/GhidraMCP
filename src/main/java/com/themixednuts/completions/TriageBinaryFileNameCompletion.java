package com.themixednuts.completions;

import com.themixednuts.annotation.GhidraMcpCompletion;

@GhidraMcpCompletion(refType = "prompt", refName = "triage_binary", argumentName = "file_name")
public class TriageBinaryFileNameCompletion extends ProgramNameCompletion {

  public TriageBinaryFileNameCompletion() {
    super("triage_binary");
  }
}
