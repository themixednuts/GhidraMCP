package com.themixednuts.services;

import java.util.List;

import ghidra.framework.plugintool.ServiceInfo;
import io.modelcontextprotocol.server.McpStatelessServerFeatures.AsyncResourceSpecification;
import io.modelcontextprotocol.server.McpStatelessServerFeatures.AsyncResourceTemplateSpecification;

/**
 * Service interface for providing MCP resource specifications.
 * Implementations discover and configure available MCP resources.
 */
@ServiceInfo(defaultProvider = com.themixednuts.GhidraMcpPlugin.class)
public interface IGhidraMcpResourceProvider {

    /**
     * Gets the list of available static resource specifications.
     * Static resources have fixed URIs that can be listed directly.
     *
     * @return List of async resource specifications
     */
    List<AsyncResourceSpecification> getResourceSpecifications();

    /**
     * Gets the list of available resource template specifications.
     * Resource templates use URI templates with parameters (e.g., ghidra://program/{name}/functions).
     *
     * @return List of async resource template specifications
     */
    List<AsyncResourceTemplateSpecification> getResourceTemplateSpecifications();
}
