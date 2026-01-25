package com.themixednuts;

import com.themixednuts.completions.BaseMcpCompletion;
import com.themixednuts.completions.FunctionAddressCompletion;
import com.themixednuts.completions.ProgramNameCompletion;
import com.themixednuts.services.IGhidraMcpCompletionProvider;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpStatelessServerFeatures.AsyncCompletionSpecification;
import java.util.ArrayList;
import java.util.List;

/**
 * Provides MCP completion specifications for auto-complete functionality. Completions are
 * registered for each prompt that needs them.
 *
 * <p>Note: Unlike tools, resources, and prompts, completions are bound to specific
 * prompts/resources at construction time, so we use direct instantiation rather than ServiceLoader
 * discovery.
 */
public class GhidraMcpCompletions implements IGhidraMcpCompletionProvider {

  private final PluginTool tool;
  private final List<BaseMcpCompletion> completions;

  public GhidraMcpCompletions(PluginTool tool) {
    this.tool = tool;
    this.completions = createCompletions();
    Msg.info(this, "Initialized " + completions.size() + " completion handlers");
  }

  private List<BaseMcpCompletion> createCompletions() {
    return List.of(
        // Completions for analyze_function prompt
        new ProgramNameCompletion("analyze_function"),
        new FunctionAddressCompletion("analyze_function"),
        // Completions for find_vulnerabilities prompt
        new ProgramNameCompletion("find_vulnerabilities"));
  }

  @Override
  public List<AsyncCompletionSpecification> getCompletionSpecifications() {
    List<AsyncCompletionSpecification> specs = new ArrayList<>();

    for (BaseMcpCompletion completion : completions) {
      try {
        specs.add(completion.toCompletionSpecification(tool));
        Msg.debug(this, "Registered completion for: " + completion.getReference());
      } catch (Exception e) {
        Msg.error(this, "Failed to create completion specification", e);
      }
    }

    return specs;
  }
}
