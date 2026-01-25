package com.themixednuts;

import com.themixednuts.annotation.GhidraMcpPrompt;
import com.themixednuts.prompts.BaseMcpPrompt;
import com.themixednuts.services.IGhidraMcpPromptProvider;
import ghidra.framework.plugintool.PluginTool;
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

  private final PluginTool tool;

  public GhidraMcpPrompts(PluginTool tool) {
    this.tool = tool;
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
}
