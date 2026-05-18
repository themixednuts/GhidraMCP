package com.themixednuts;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.themixednuts.utils.ToolOutputStore;
import ghidra.framework.options.ToolOptions;
import org.junit.jupiter.api.Test;

class McpOutputOptionsTest {

  @Test
  void resolvesDefaultsWhenOptionsAreUnavailable() {
    McpOutputOptions.Limits limits = McpOutputOptions.from((ToolOptions) null);

    assertEquals(
        McpOutputOptions.DEFAULT_INLINE_RESPONSE_CHAR_LIMIT, limits.inlineResponseCharLimit());
    assertEquals(ToolOutputStore.DEFAULT_READ_CHUNK_CHARS, limits.defaultReadChunkChars());
    assertEquals(ToolOutputStore.MAX_READ_CHUNK_CHARS, limits.maxReadChunkChars());
  }

  @Test
  void clampsConfiguredLimitsToSafeRanges() {
    ToolOptions options = new ToolOptions(GhidraMcpPlugin.OPTIONS_CATEGORY);
    McpOutputOptions.registerOptions(options, "GhidraMCP");
    options.setInt(McpOutputOptions.INLINE_RESPONSE_CHAR_LIMIT_OPTION, Integer.MAX_VALUE);
    options.setInt(McpOutputOptions.DEFAULT_READ_CHUNK_CHARS_OPTION, 500_000);
    options.setInt(McpOutputOptions.MAX_READ_CHUNK_CHARS_OPTION, 120_000);

    McpOutputOptions.Limits limits = McpOutputOptions.from(options);

    assertEquals(McpOutputOptions.MAX_INLINE_RESPONSE_CHAR_LIMIT, limits.inlineResponseCharLimit());
    assertEquals(120_000, limits.defaultReadChunkChars());
    assertEquals(120_000, limits.maxReadChunkChars());
  }
}
