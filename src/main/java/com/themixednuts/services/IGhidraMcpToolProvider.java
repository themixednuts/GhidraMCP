package com.themixednuts.services;

import ghidra.framework.plugintool.ServiceInfo;
import io.modelcontextprotocol.server.McpStatelessServerFeatures.AsyncToolSpecification;
import java.util.List;

/** Service interface for providing configured MCP tool specifications. */
@ServiceInfo(defaultProvider = com.themixednuts.GhidraMcpPlugin.class)
public interface IGhidraMcpToolProvider {

  /**
   * Gets the list of currently enabled and configured MCP tool specifications.
   *
   * @return A list of AsyncToolSpecification for all enabled tools.
   * @throws Exception If there's an error loading or configuring tools.
   */
  List<AsyncToolSpecification> getAvailableToolSpecifications() throws Exception;
}
