package com.themixednuts.completions;

import com.themixednuts.annotation.GhidraMcpCompletion;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.utils.GhidraStateUtils;
import ghidra.framework.model.Project;
import ghidra.framework.plugintool.PluginTool;
import io.modelcontextprotocol.common.McpTransportContext;
import io.modelcontextprotocol.server.McpStatelessServerFeatures.AsyncCompletionSpecification;
import io.modelcontextprotocol.spec.McpSchema.CompleteReference;
import io.modelcontextprotocol.spec.McpSchema.CompleteRequest;
import io.modelcontextprotocol.spec.McpSchema.CompleteResult;
import io.modelcontextprotocol.spec.McpSchema.PromptReference;
import io.modelcontextprotocol.spec.McpSchema.ResourceReference;
import java.util.ArrayList;
import java.util.List;
import reactor.core.publisher.Mono;

/**
 * Abstract base class for MCP completion providers. Provides auto-completion suggestions for prompt
 * arguments and resource template parameters.
 *
 * <p>Implementations should be annotated with @GhidraMcpCompletion and registered via ServiceLoader
 * in META-INF/services/com.themixednuts.completions.BaseMcpCompletion.
 */
public abstract class BaseMcpCompletion {

  protected static final int MAX_COMPLETIONS = 100;

  // =================== Abstract Methods ===================

  /**
   * Generates completion suggestions.
   *
   * @param context The MCP transport context
   * @param argumentValue The current value of the argument (partial input)
   * @param tool The Ghidra plugin tool
   * @return Mono emitting the CompleteResult
   */
  public abstract Mono<CompleteResult> complete(
      McpTransportContext context, String argumentValue, PluginTool tool);

  // =================== Annotation Accessors ===================

  /** Gets the annotation for this completion. */
  protected GhidraMcpCompletion getAnnotation() {
    return this.getClass().getAnnotation(GhidraMcpCompletion.class);
  }

  /** Gets the reference this completion handler is associated with. */
  public CompleteReference getReference() {
    GhidraMcpCompletion annotation = getAnnotation();
    if (annotation == null) {
      return null;
    }

    if ("prompt".equals(annotation.refType())) {
      return new PromptReference("ref/prompt", annotation.refName());
    } else if ("resource".equals(annotation.refType())) {
      return new ResourceReference("ref/resource", annotation.refName());
    }
    return null;
  }

  /** Gets the name of the argument this completion handles. */
  public String getArgumentName() {
    GhidraMcpCompletion annotation = getAnnotation();
    return annotation != null ? annotation.argumentName() : "";
  }

  // =================== Specification Generation ===================

  /** Creates an AsyncCompletionSpecification for this completion handler. */
  public AsyncCompletionSpecification toCompletionSpecification(PluginTool tool) {
    return new AsyncCompletionSpecification(
        getReference(), (ctx, request) -> handleComplete(ctx, request, tool));
  }

  /** Handles a completion request. */
  protected Mono<CompleteResult> handleComplete(
      McpTransportContext ctx, CompleteRequest request, PluginTool tool) {
    // Check if this is the right argument
    if (request.argument() == null || !getArgumentName().equals(request.argument().name())) {
      // Return empty completions for arguments we don't handle
      return Mono.just(
          new CompleteResult(new CompleteResult.CompleteCompletion(List.of(), 0, false)));
    }

    String value = request.argument().value();
    return complete(ctx, value != null ? value : "", tool)
        .onErrorResume(
            t -> {
              // On error, return empty completions
              return Mono.just(
                  new CompleteResult(new CompleteResult.CompleteCompletion(List.of(), 0, false)));
            });
  }

  // =================== Ghidra Helpers ===================

  /** Gets the active Ghidra project. */
  protected Project getActiveProject() throws GhidraMcpException {
    return GhidraStateUtils.getActiveProject();
  }

  /** Gets all program names in the project that match a prefix. */
  protected List<String> getProgramNames(String prefix) throws GhidraMcpException {
    return GhidraStateUtils.getFileNames(prefix, MAX_COMPLETIONS);
  }

  /** Filters a list of strings by prefix. */
  protected List<String> filterByPrefix(List<String> items, String prefix) {
    if (prefix == null || prefix.isEmpty()) {
      return items.size() > MAX_COMPLETIONS ? items.subList(0, MAX_COMPLETIONS) : items;
    }

    String lowerPrefix = prefix.toLowerCase();
    List<String> filtered = new ArrayList<>();

    // First add exact prefix matches
    for (String item : items) {
      if (filtered.size() >= MAX_COMPLETIONS) break;
      if (item.toLowerCase().startsWith(lowerPrefix)) {
        filtered.add(item);
      }
    }

    // Then add contains matches
    for (String item : items) {
      if (filtered.size() >= MAX_COMPLETIONS) break;
      if (!item.toLowerCase().startsWith(lowerPrefix) && item.toLowerCase().contains(lowerPrefix)) {
        filtered.add(item);
      }
    }

    return filtered;
  }
}
