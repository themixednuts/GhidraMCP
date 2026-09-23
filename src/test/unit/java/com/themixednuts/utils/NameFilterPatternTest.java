package com.themixednuts.utils;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;

class NameFilterPatternTest {
  @Test
  void acceptsAgentStyleGlobAndExistingRegex() {
    Pattern glob = NameFilterPattern.compile("*PhysicalWorld*", 0);
    assertTrue(glob.matcher("GetPhysicalWorldData").matches());
    assertFalse(glob.matcher("GetPhysicsData").matches());

    Pattern regex = NameFilterPattern.compile(".*PhysicalWorld.*", Pattern.CASE_INSENSITIVE);
    assertTrue(regex.matcher("getphysicalworlddata").matches());
  }
}
