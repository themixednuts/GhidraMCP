package com.themixednuts;

import com.themixednuts.annotation.GhidraMcpResource;
import com.themixednuts.resources.BaseMcpResource;
import com.themixednuts.services.IGhidraMcpResourceProvider;
import ghidra.framework.plugintool.PluginTool;
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

  private final PluginTool tool;

  public GhidraMcpResources(PluginTool tool) {
    this.tool = tool;
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
}
