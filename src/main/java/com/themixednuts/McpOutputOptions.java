package com.themixednuts;

import com.themixednuts.utils.ToolOutputStore;
import ghidra.framework.options.OptionType;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.HelpLocation;

/** Centralizes tunable output-size limits for MCP tool responses and stored-output reads. */
public final class McpOutputOptions {

  public static final String INLINE_RESPONSE_CHAR_LIMIT_OPTION = "Output Inline Character Limit";
  public static final String DEFAULT_READ_CHUNK_CHARS_OPTION =
      "Read Output Default Chunk Characters";
  public static final String MAX_READ_CHUNK_CHARS_OPTION = "Read Output Maximum Chunk Characters";

  public static final int DEFAULT_INLINE_RESPONSE_CHAR_LIMIT = 48_000;
  public static final int MIN_INLINE_RESPONSE_CHAR_LIMIT = 8_000;
  public static final int MAX_INLINE_RESPONSE_CHAR_LIMIT = 256_000;
  public static final int MAX_CONFIGURABLE_READ_CHUNK_CHARS = 256_000;

  private static final String INLINE_RESPONSE_CHAR_LIMIT_DESCRIPTION =
      "Maximum serialized characters to return inline before storing the tool output for chunked"
          + " retrieval. Increase this to avoid extra read_tool_output calls for large"
          + " decompilations.";
  private static final String DEFAULT_READ_CHUNK_CHARS_DESCRIPTION =
      "Default raw characters returned by read_tool_output when max_chars is omitted.";
  private static final String MAX_READ_CHUNK_CHARS_DESCRIPTION =
      "Maximum raw characters that read_tool_output accepts for max_chars. The returned chunk may"
          + " still be trimmed to keep the MCP response inline-safe.";

  private McpOutputOptions() {}

  public static void registerOptions(ToolOptions options, String topic) {
    HelpLocation inlineHelp = new HelpLocation(topic, "OutputInlineCharacterLimitOption");
    HelpLocation defaultChunkHelp = new HelpLocation(topic, "ReadOutputDefaultChunkCharacters");
    HelpLocation maxChunkHelp = new HelpLocation(topic, "ReadOutputMaximumChunkCharacters");

    options.registerOption(
        INLINE_RESPONSE_CHAR_LIMIT_OPTION,
        OptionType.INT_TYPE,
        DEFAULT_INLINE_RESPONSE_CHAR_LIMIT,
        inlineHelp,
        INLINE_RESPONSE_CHAR_LIMIT_DESCRIPTION,
        (java.util.function.Supplier<java.beans.PropertyEditor>) null);

    options.registerOption(
        DEFAULT_READ_CHUNK_CHARS_OPTION,
        OptionType.INT_TYPE,
        ToolOutputStore.DEFAULT_READ_CHUNK_CHARS,
        defaultChunkHelp,
        DEFAULT_READ_CHUNK_CHARS_DESCRIPTION,
        (java.util.function.Supplier<java.beans.PropertyEditor>) null);

    options.registerOption(
        MAX_READ_CHUNK_CHARS_OPTION,
        OptionType.INT_TYPE,
        ToolOutputStore.MAX_READ_CHUNK_CHARS,
        maxChunkHelp,
        MAX_READ_CHUNK_CHARS_DESCRIPTION,
        (java.util.function.Supplier<java.beans.PropertyEditor>) null);
  }

  public static Limits from(PluginTool tool) {
    if (tool == null) {
      return defaults();
    }
    return from(tool.getOptions(GhidraMcpPlugin.OPTIONS_CATEGORY));
  }

  public static Limits from(ToolOptions options) {
    if (options == null) {
      return defaults();
    }

    int inlineLimit =
        clamp(
            options.getInt(INLINE_RESPONSE_CHAR_LIMIT_OPTION, DEFAULT_INLINE_RESPONSE_CHAR_LIMIT),
            MIN_INLINE_RESPONSE_CHAR_LIMIT,
            MAX_INLINE_RESPONSE_CHAR_LIMIT);
    int maxReadChunkChars =
        clamp(
            options.getInt(MAX_READ_CHUNK_CHARS_OPTION, ToolOutputStore.MAX_READ_CHUNK_CHARS),
            1,
            MAX_CONFIGURABLE_READ_CHUNK_CHARS);
    int defaultReadChunkChars =
        clamp(
            options.getInt(
                DEFAULT_READ_CHUNK_CHARS_OPTION, ToolOutputStore.DEFAULT_READ_CHUNK_CHARS),
            1,
            maxReadChunkChars);

    return new Limits(inlineLimit, defaultReadChunkChars, maxReadChunkChars);
  }

  public static Limits defaults() {
    return new Limits(
        DEFAULT_INLINE_RESPONSE_CHAR_LIMIT,
        ToolOutputStore.DEFAULT_READ_CHUNK_CHARS,
        ToolOutputStore.MAX_READ_CHUNK_CHARS);
  }

  private static int clamp(int value, int min, int max) {
    return Math.max(min, Math.min(value, max));
  }

  public record Limits(
      int inlineResponseCharLimit, int defaultReadChunkChars, int maxReadChunkChars) {}
}
