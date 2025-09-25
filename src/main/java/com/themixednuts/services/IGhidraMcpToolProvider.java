package com.themixednuts.services;

import java.util.List;

import generic.stl.Pair;
import io.modelcontextprotocol.server.McpStatelessServerFeatures.AsyncToolSpecification;
import ghidra.framework.plugintool.ServiceInfo;

/**
 * Service interface for providing configured MCP tool specifications.
 */
@ServiceInfo(defaultProvider = com.themixednuts.GhidraMcpPlugin.class)
public interface IGhidraMcpToolProvider {

	/**
	 * Gets the list of currently enabled and configured MCP tool specifications.
	 * 
	 * @return A list of AsyncToolSpecification.
	 * @throws Exception If there's an error loading or configuring tools.
	 */
	List<Pair<String, AsyncToolSpecification>> getAvailableToolSpecifications() throws Exception;

}