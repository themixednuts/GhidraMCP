package com.themixednuts;

import com.themixednuts.annotation.GhidraMcpCompletion;
import com.themixednuts.completions.BaseMcpCompletion;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.services.IGhidraMcpCompletionProvider;
import ghidra.framework.options.OptionType;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpStatelessServerFeatures.AsyncCompletionSpecification;
import io.modelcontextprotocol.spec.McpSchema.CompleteReference;
import io.modelcontextprotocol.spec.McpSchema.CompleteResult;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.ServiceLoader;
import java.util.stream.Collectors;
import reactor.core.publisher.Mono;

/** Provides MCP completion specifications discovered via ServiceLoader. */
public class GhidraMcpCompletions implements IGhidraMcpCompletionProvider {

  private static final String OPTIONS_ANCHOR = "GhidraMcpCompletions";

  private final PluginTool tool;
  private final ToolOptions options;

  public GhidraMcpCompletions(PluginTool tool) {
    this.tool = tool;
    this.options = tool.getOptions(GhidraMcpPlugin.OPTIONS_CATEGORY);
  }

  @Override
  public List<AsyncCompletionSpecification> getCompletionSpecifications() {
    List<BaseMcpCompletion> discovered = loadEnabledCompletions();
    Map<CompleteReference, List<BaseMcpCompletion>> grouped = new LinkedHashMap<>();

    for (BaseMcpCompletion completion : discovered) {
      try {
        CompleteReference reference = completion.getReference();
        if (reference == null) {
          Msg.warn(
              this,
              "Skipping completion with unresolved reference: "
                  + completion.getClass().getSimpleName());
          continue;
        }
        grouped.computeIfAbsent(reference, ignored -> new ArrayList<>()).add(completion);
      } catch (Exception e) {
        Msg.error(
            this,
            "Skipping completion due to invalid reference metadata: "
                + completion.getClass().getSimpleName(),
            e);
      }
    }

    List<AsyncCompletionSpecification> specs = new ArrayList<>();
    grouped.forEach(
        (reference, completionGroup) -> {
          specs.add(
              new AsyncCompletionSpecification(
                  reference,
                  (ctx, request) -> routeCompletionRequest(completionGroup, ctx, request)));
          Msg.debug(
              this,
              "Registered completion group for "
                  + reference.identifier()
                  + " with "
                  + completionGroup.size()
                  + " argument handler(s)");
        });

    Msg.info(this, "Loaded " + specs.size() + " completion reference groups");
    return specs;
  }

  private Mono<CompleteResult> routeCompletionRequest(
      List<BaseMcpCompletion> completionGroup,
      io.modelcontextprotocol.common.McpTransportContext ctx,
      io.modelcontextprotocol.spec.McpSchema.CompleteRequest request) {
    if (request.argument() == null || request.argument().name() == null) {
      return Mono.error(
          new GhidraMcpException(
              GhidraMcpError.invalid("argument", null, "completion argument name is required")));
    }

    String argumentName = request.argument().name();
    Optional<BaseMcpCompletion> matched =
        completionGroup.stream().filter(c -> argumentName.equals(c.getArgumentName())).findFirst();

    if (matched.isEmpty()) {
      List<String> supportedArguments =
          completionGroup.stream().map(BaseMcpCompletion::getArgumentName).toList();
      return Mono.error(
          new GhidraMcpException(
              GhidraMcpError.invalid(
                  "argument",
                  argumentName,
                  "unsupported completion argument; supported: "
                      + String.join(", ", supportedArguments))));
    }

    String value = request.argument().value() != null ? request.argument().value() : "";
    Map<String, String> completionContext =
        request.context() != null && request.context().arguments() != null
            ? request.context().arguments()
            : Map.of();
    return matched.get().complete(ctx, value, completionContext, tool);
  }

  private List<BaseMcpCompletion> loadEnabledCompletions() {
    return ServiceLoader.load(BaseMcpCompletion.class).stream()
        .map(
            provider -> {
              try {
                return provider.get();
              } catch (Exception e) {
                Msg.error(
                    this,
                    "Failed to instantiate completion: " + provider.type().getSimpleName(),
                    e);
                return null;
              }
            })
        .filter(completion -> completion != null)
        .filter(this::isCompletionEnabled)
        .collect(Collectors.toList());
  }

  private boolean isCompletionEnabled(BaseMcpCompletion completion) {
    GhidraMcpCompletion annotation = completion.getClass().getAnnotation(GhidraMcpCompletion.class);
    if (annotation == null) {
      Msg.warn(
          this,
          "Completion "
              + completion.getClass().getSimpleName()
              + " missing @GhidraMcpCompletion annotation; skipping");
      return false;
    }

    String optionKey = getOptionKey(annotation);
    boolean enabled = options.getBoolean(optionKey, true);
    if (!enabled) {
      Msg.info(this, "Completion disabled via options: " + optionKey);
    }
    return enabled;
  }

  public static void registerOptions(ToolOptions options, String topic) {
    HelpLocation help = new HelpLocation(topic, OPTIONS_ANCHOR);

    ServiceLoader.load(BaseMcpCompletion.class).stream()
        .forEach(
            provider -> {
              Class<? extends BaseMcpCompletion> completionClass = provider.type();
              GhidraMcpCompletion annotation =
                  completionClass.getAnnotation(GhidraMcpCompletion.class);
              if (annotation == null) {
                Msg.warn(
                    GhidraMcpCompletions.class,
                    "Completion "
                        + completionClass.getSimpleName()
                        + " missing @GhidraMcpCompletion annotation; skipping option"
                        + " registration");
                return;
              }

              String optionKey = getOptionKey(annotation);
              String description =
                  "Enable completion for "
                      + annotation.refType()
                      + " '"
                      + annotation.refName()
                      + "' argument '"
                      + annotation.argumentName()
                      + "'";
              options.registerOption(optionKey, OptionType.BOOLEAN_TYPE, true, help, description);
            });
  }

  private static String getOptionKey(GhidraMcpCompletion annotation) {
    return "Completion: "
        + annotation.refType()
        + ":"
        + annotation.refName()
        + ":"
        + annotation.argumentName();
  }
}
