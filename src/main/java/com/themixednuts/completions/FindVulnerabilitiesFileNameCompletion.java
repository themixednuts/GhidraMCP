package com.themixednuts.completions;

import com.themixednuts.annotation.GhidraMcpCompletion;

@GhidraMcpCompletion(
    refType = "prompt",
    refName = "find_vulnerabilities",
    argumentName = "file_name")
public class FindVulnerabilitiesFileNameCompletion extends ProgramNameCompletion {

  public FindVulnerabilitiesFileNameCompletion() {
    super("find_vulnerabilities");
  }
}
