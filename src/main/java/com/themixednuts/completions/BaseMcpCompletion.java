package com.themixednuts.completions;

import com.themixednuts.annotation.GhidraMcpCompletion;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
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
import java.util.Map;
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
   * @param completionContext Context arguments provided by the MCP client
   * @param tool The Ghidra plugin tool
   * @return Mono emitting the CompleteResult
   */
  public abstract Mono<CompleteResult> complete(
      McpTransportContext context,
      String argumentValue,
      Map<String, String> completionContext,
      PluginTool tool);

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
      return new PromptReference(annotation.refName());
    } else if ("resource".equals(annotation.refType())) {
      return new ResourceReference(annotation.refName());
    }

    throw new GhidraMcpException(
        GhidraMcpError.invalid(
            "refType", annotation.refType(), "must be either 'prompt' or 'resource'"));
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
      return Mono.error(
          new GhidraMcpException(
              GhidraMcpError.invalid(
                  "argument",
                  request.argument() != null ? request.argument().name() : null,
                  "completion handler does not support this argument")));
    }

    String value = request.argument().value();
    Map<String, String> completionContext =
        request.context() != null && request.context().arguments() != null
            ? request.context().arguments()
            : Map.of();

    return complete(ctx, value != null ? value : "", completionContext, tool)
        .onErrorMap(t -> normalizeCompletionException(t, request));
  }

  private RuntimeException normalizeCompletionException(
      Throwable throwable, CompleteRequest request) {
    if (throwable instanceof RuntimeException runtimeException
        && runtimeException.getCause() instanceof GhidraMcpException gme) {
      return gme;
    }
    if (throwable instanceof GhidraMcpException gme) {
      return gme;
    }

    if (throwable instanceof IllegalArgumentException iae) {
      return new GhidraMcpException(
          GhidraMcpError.validation()
              .errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
              .message(iae.getMessage())
              .context(
                  new GhidraMcpError.ErrorContext(
                      request.ref() != null ? request.ref().identifier() : "unknown",
                      "completion",
                      null,
                      null,
                      Map.of("exception_type", iae.getClass().getSimpleName())))
              .build(),
          iae);
    }

    GhidraMcpError error =
        GhidraMcpError.execution()
            .errorCode(GhidraMcpError.ErrorCode.OPERATION_FAILED)
            .message(
                "Failed to compute completion for reference '"
                    + (request.ref() != null ? request.ref().identifier() : "unknown")
                    + "': "
                    + throwable.getMessage())
            .context(
                new GhidraMcpError.ErrorContext(
                    request.ref() != null ? request.ref().identifier() : "unknown",
                    "completion",
                    null,
                    null,
                    Map.of("exception_type", throwable.getClass().getSimpleName())))
            .build();

    return new GhidraMcpException(error, throwable);
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
