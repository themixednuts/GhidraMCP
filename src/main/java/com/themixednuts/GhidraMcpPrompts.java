package com.themixednuts;

import com.themixednuts.annotation.GhidraMcpPrompt;
import com.themixednuts.prompts.BaseMcpPrompt;
import com.themixednuts.services.IGhidraMcpPromptProvider;
import ghidra.framework.options.OptionType;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpStatelessServerFeatures.AsyncPromptSpecification;
import java.util.ArrayList;
import java.util.List;
import java.util.ServiceLoader;

/**
 * Provides MCP prompt specifications for reverse engineering workflows. Discovers prompts via
 * ServiceLoader from META-INF/services.
 */
public class GhidraMcpPrompts implements IGhidraMcpPromptProvider {

  private static final String OPTIONS_ANCHOR = "GhidraMcpPrompts";

  private final PluginTool tool;
  private final ToolOptions options;

  public GhidraMcpPrompts(PluginTool tool) {
    this.tool = tool;
    this.options = tool.getOptions(GhidraMcpPlugin.OPTIONS_CATEGORY);
  }

  @Override
  public List<AsyncPromptSpecification> getPromptSpecifications() {
    List<AsyncPromptSpecification> specs = new ArrayList<>();

    ServiceLoader.load(BaseMcpPrompt.class)
        .forEach(
            prompt -> {
              GhidraMcpPrompt annotation = prompt.getClass().getAnnotation(GhidraMcpPrompt.class);
              if (annotation == null) {
                Msg.warn(
                    this,
                    "Prompt "
                        + prompt.getClass().getSimpleName()
                        + " missing @GhidraMcpPrompt annotation");
                return;
              }

              if (!isPromptEnabled(annotation)) {
                return;
              }

              try {
                specs.add(prompt.toPromptSpecification(tool));
                Msg.debug(this, "Registered prompt: " + annotation.name());
              } catch (Exception e) {
                Msg.error(
                    this, "Failed to create specification for prompt: " + annotation.name(), e);
              }
            });

    Msg.info(this, "Loaded " + specs.size() + " prompts via ServiceLoader");
    return specs;
  }

  private boolean isPromptEnabled(GhidraMcpPrompt annotation) {
    String optionKey = getOptionKey(annotation);
    boolean enabled = options.getBoolean(optionKey, true);
    if (!enabled) {
      Msg.info(this, "Prompt disabled via options: " + optionKey);
    }
    return enabled;
  }

  public static void registerOptions(ToolOptions options, String topic) {
    HelpLocation help = new HelpLocation(topic, OPTIONS_ANCHOR);

    ServiceLoader.load(BaseMcpPrompt.class).stream()
        .forEach(
            provider -> {
              Class<? extends BaseMcpPrompt> promptClass = provider.type();
              GhidraMcpPrompt annotation = promptClass.getAnnotation(GhidraMcpPrompt.class);
              if (annotation == null) {
                Msg.warn(
                    GhidraMcpPrompts.class,
                    "Prompt "
                        + promptClass.getSimpleName()
                        + " missing @GhidraMcpPrompt annotation; skipping option"
                        + " registration");
                return;
              }

              String optionKey = getOptionKey(annotation);
              String description = "Enable MCP prompt '" + annotation.name() + "'";
              options.registerOption(optionKey, OptionType.BOOLEAN_TYPE, true, help, description);
            });
  }

  private static String getOptionKey(GhidraMcpPrompt annotation) {
    return "Prompt: " + annotation.name();
  }
}
