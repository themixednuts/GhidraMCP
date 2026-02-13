package com.themixednuts;

import com.themixednuts.annotation.GhidraMcpResource;
import com.themixednuts.resources.BaseMcpResource;
import com.themixednuts.services.IGhidraMcpResourceProvider;
import ghidra.framework.options.OptionType;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpStatelessServerFeatures.AsyncResourceSpecification;
import io.modelcontextprotocol.server.McpStatelessServerFeatures.AsyncResourceTemplateSpecification;
import java.util.ArrayList;
import java.util.List;
import java.util.ServiceLoader;

/**
 * Provides MCP resource specifications for Ghidra data. Discovers resources via ServiceLoader from
 * META-INF/services.
 */
public class GhidraMcpResources implements IGhidraMcpResourceProvider {

  private static final String OPTIONS_ANCHOR = "GhidraMcpResources";

  private final PluginTool tool;
  private final ToolOptions options;

  public GhidraMcpResources(PluginTool tool) {
    this.tool = tool;
    this.options = tool.getOptions(GhidraMcpPlugin.OPTIONS_CATEGORY);
  }

  @Override
  public List<AsyncResourceSpecification> getResourceSpecifications() {
    List<AsyncResourceSpecification> specs = new ArrayList<>();

    ServiceLoader.load(BaseMcpResource.class)
        .forEach(
            resource -> {
              GhidraMcpResource annotation =
                  resource.getClass().getAnnotation(GhidraMcpResource.class);
              if (annotation == null) {
                Msg.warn(
                    this,
                    "Resource "
                        + resource.getClass().getSimpleName()
                        + " missing @GhidraMcpResource annotation");
                return;
              }

              if (!annotation.template()) {
                if (!isResourceEnabled(annotation)) {
                  return;
                }
                try {
                  specs.add(resource.toResourceSpecification(tool));
                  Msg.debug(this, "Registered static resource: " + annotation.name());
                } catch (Exception e) {
                  Msg.error(
                      this, "Failed to create specification for resource: " + annotation.name(), e);
                }
              }
            });

    Msg.info(this, "Loaded " + specs.size() + " static resources via ServiceLoader");
    return specs;
  }

  @Override
  public List<AsyncResourceTemplateSpecification> getResourceTemplateSpecifications() {
    List<AsyncResourceTemplateSpecification> specs = new ArrayList<>();

    ServiceLoader.load(BaseMcpResource.class)
        .forEach(
            resource -> {
              GhidraMcpResource annotation =
                  resource.getClass().getAnnotation(GhidraMcpResource.class);
              if (annotation == null) {
                return; // Warning already logged in getResourceSpecifications
              }

              if (annotation.template()) {
                if (!isResourceEnabled(annotation)) {
                  return;
                }
                try {
                  specs.add(resource.toTemplateSpecification(tool));
                  Msg.debug(this, "Registered template resource: " + annotation.name());
                } catch (Exception e) {
                  Msg.error(
                      this,
                      "Failed to create specification for template resource: " + annotation.name(),
                      e);
                }
              }
            });

    Msg.info(this, "Loaded " + specs.size() + " template resources via ServiceLoader");
    return specs;
  }

  private boolean isResourceEnabled(GhidraMcpResource annotation) {
    String optionKey = getOptionKey(annotation);
    boolean enabled = options.getBoolean(optionKey, true);
    if (!enabled) {
      Msg.info(this, "Resource disabled via options: " + optionKey);
    }
    return enabled;
  }

  public static void registerOptions(ToolOptions options, String topic) {
    HelpLocation help = new HelpLocation(topic, OPTIONS_ANCHOR);

    ServiceLoader.load(BaseMcpResource.class).stream()
        .forEach(
            provider -> {
              Class<? extends BaseMcpResource> resourceClass = provider.type();
              GhidraMcpResource annotation = resourceClass.getAnnotation(GhidraMcpResource.class);
              if (annotation == null) {
                Msg.warn(
                    GhidraMcpResources.class,
                    "Resource "
                        + resourceClass.getSimpleName()
                        + " missing @GhidraMcpResource annotation; skipping option"
                        + " registration");
                return;
              }

              String optionKey = getOptionKey(annotation);
              String description =
                  "Enable MCP resource '"
                      + annotation.name()
                      + "'"
                      + (annotation.template() ? " (template)" : "");
              options.registerOption(optionKey, OptionType.BOOLEAN_TYPE, true, help, description);
            });
  }

  private static String getOptionKey(GhidraMcpResource annotation) {
    return "Resource: " + annotation.name();
  }
}
