package com.themixednuts.services;

import java.util.List;

import ghidra.framework.plugintool.ServiceInfo;
import io.modelcontextprotocol.server.McpStatelessServerFeatures.AsyncPromptSpecification;

/**
 * Service interface for providing MCP prompt specifications.
 * Implementations discover and configure available MCP prompts for reverse engineering workflows.
 */
@ServiceInfo(defaultProvider = com.themixednuts.GhidraMcpPlugin.class)
public interface IGhidraMcpPromptProvider {

    /**
     * Gets the list of available prompt specifications.
     *
     * @return List of async prompt specifications
     */
    List<AsyncPromptSpecification> getPromptSpecifications();
}
