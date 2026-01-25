package com.themixednuts.prompts;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.themixednuts.annotation.GhidraMcpPrompt;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.utils.GhidraStateUtils;
import com.themixednuts.utils.JsonMapperHolder;
import ghidra.framework.model.Project;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.common.McpTransportContext;
import io.modelcontextprotocol.server.McpStatelessServerFeatures.AsyncPromptSpecification;
import io.modelcontextprotocol.spec.McpSchema.GetPromptRequest;
import io.modelcontextprotocol.spec.McpSchema.GetPromptResult;
import io.modelcontextprotocol.spec.McpSchema.Prompt;
import io.modelcontextprotocol.spec.McpSchema.PromptArgument;
import io.modelcontextprotocol.spec.McpSchema.PromptMessage;
import io.modelcontextprotocol.spec.McpSchema.Role;
import io.modelcontextprotocol.spec.McpSchema.TextContent;
import java.util.List;
import java.util.Map;
import reactor.core.publisher.Mono;

/**
 * Abstract base class for MCP prompts. Provides reverse engineering workflow prompts for AI
 * assistants.
 *
 * <p>Implementations should be annotated with @GhidraMcpPrompt and registered via ServiceLoader in
 * META-INF/services/com.themixednuts.prompts.BaseMcpPrompt.
 */
public abstract class BaseMcpPrompt {

  protected static final ObjectMapper mapper = JsonMapperHolder.getMapper();

  // =================== Abstract Methods ===================

  /** Gets the list of arguments this prompt accepts. */
  public abstract List<PromptArgument> getArguments();

  /**
   * Generates the prompt messages based on the provided arguments.
   *
   * @param context The MCP transport context
   * @param arguments The arguments provided by the client
   * @param tool The Ghidra plugin tool
   * @return Mono emitting the GetPromptResult
   */
  public abstract Mono<GetPromptResult> generate(
      McpTransportContext context, Map<String, Object> arguments, PluginTool tool);

  // =================== Annotation Accessors ===================

  /** Gets the annotation for this prompt. */
  protected GhidraMcpPrompt getAnnotation() {
    return this.getClass().getAnnotation(GhidraMcpPrompt.class);
  }

  /** Gets the unique name of this prompt. */
  public String getName() {
    GhidraMcpPrompt annotation = getAnnotation();
    return annotation != null ? annotation.name() : getClass().getSimpleName();
  }

  /** Gets a human-readable title for this prompt. */
  public String getTitle() {
    GhidraMcpPrompt annotation = getAnnotation();
    return annotation != null ? annotation.title() : getName();
  }

  /** Gets the description of what this prompt does. */
  public String getDescription() {
    GhidraMcpPrompt annotation = getAnnotation();
    return annotation != null ? annotation.description() : "";
  }

  // =================== Specification Generation ===================

  /** Creates an AsyncPromptSpecification for this prompt. */
  public AsyncPromptSpecification toPromptSpecification(PluginTool tool) {
    Prompt prompt = new Prompt(getName(), getTitle(), getDescription(), getArguments());

    return new AsyncPromptSpecification(
        prompt, (ctx, request) -> handleGetPrompt(ctx, request, tool));
  }

  /** Handles a get prompt request. */
  protected Mono<GetPromptResult> handleGetPrompt(
      McpTransportContext ctx, GetPromptRequest request, PluginTool tool) {
    return generate(ctx, request.arguments(), tool)
        .onErrorResume(
            t -> {
              String errorMsg =
                  t instanceof GhidraMcpException
                      ? t.getMessage()
                      : "Error generating prompt: " + t.getMessage();
              return Mono.error(new RuntimeException(errorMsg));
            });
  }

  // =================== Ghidra Helpers ===================

  /** Gets the active Ghidra project. */
  protected Project getActiveProject() throws GhidraMcpException {
    return GhidraStateUtils.getActiveProject();
  }

  /** Gets a program by name. */
  protected Program getProgramByName(String fileName) throws GhidraMcpException {
    return GhidraStateUtils.getProgramByName(fileName, this);
  }

  // =================== Argument Helpers ===================

  /** Gets a required string argument. */
  protected String getRequiredArgument(Map<String, Object> args, String name)
      throws GhidraMcpException {
    Object value = args.get(name);
    if (value == null || (value instanceof String && ((String) value).isBlank())) {
      throw new GhidraMcpException(
          GhidraMcpError.validation()
              .errorCode(GhidraMcpError.ErrorCode.MISSING_REQUIRED_ARGUMENT)
              .message("Missing required argument: " + name)
              .build());
    }
    return value.toString();
  }

  /** Gets an optional string argument. */
  protected String getOptionalArgument(Map<String, Object> args, String name, String defaultValue) {
    Object value = args.get(name);
    if (value == null || (value instanceof String && ((String) value).isBlank())) {
      return defaultValue;
    }
    return value.toString();
  }

  // =================== Message Helpers ===================

  /** Creates a user message. */
  protected PromptMessage createUserMessage(String text) {
    return new PromptMessage(Role.USER, new TextContent(text));
  }

  /** Creates an assistant message. */
  protected PromptMessage createAssistantMessage(String text) {
    return new PromptMessage(Role.ASSISTANT, new TextContent(text));
  }
}
