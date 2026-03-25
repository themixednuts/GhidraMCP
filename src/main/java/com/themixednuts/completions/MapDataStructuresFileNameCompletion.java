package com.themixednuts.completions;

import com.themixednuts.annotation.GhidraMcpCompletion;

@GhidraMcpCompletion(
    refType = "prompt",
    refName = "map_data_structures",
    argumentName = "file_name")
public class MapDataStructuresFileNameCompletion extends ProgramNameCompletion {

  public MapDataStructuresFileNameCompletion() {
    super("map_data_structures");
  }
}
