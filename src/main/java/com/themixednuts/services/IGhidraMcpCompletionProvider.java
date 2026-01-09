package com.themixednuts.services;

import java.util.List;

import ghidra.framework.plugintool.ServiceInfo;
import io.modelcontextprotocol.server.McpStatelessServerFeatures.AsyncCompletionSpecification;

/**
 * Service interface for providing MCP completion specifications.
 * Implementations provide auto-completion for prompt arguments and resource template parameters.
 */
@ServiceInfo(defaultProvider = com.themixednuts.GhidraMcpPlugin.class)
public interface IGhidraMcpCompletionProvider {

    /**
     * Gets the list of available completion specifications.
     * Each specification maps a reference (prompt or resource) to its completion handler.
     *
     * @return List of async completion specifications
     */
    List<AsyncCompletionSpecification> getCompletionSpecifications();
}
