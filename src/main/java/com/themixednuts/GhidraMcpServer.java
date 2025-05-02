package com.themixednuts;

import java.util.concurrent.atomic.AtomicInteger;

import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import ghidra.framework.model.Project;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.Msg;

import io.modelcontextprotocol.server.McpAsyncServer;
import io.modelcontextprotocol.server.McpServer;
import io.modelcontextprotocol.server.transport.HttpServletSseServerTransportProvider;
import io.modelcontextprotocol.spec.McpSchema.ServerCapabilities;

public class GhidraMcpServer {
	private static Server jettyServer = null; // Jetty server instance
	private static McpAsyncServer mcpAsyncServer = null;
	private static GhidraMcpTools mcpTools = null;
	private static HttpServletSseServerTransportProvider transportProvider = null; // Hold the transport provider

	private static final Object lock = new Object();
	private static final AtomicInteger refCount = new AtomicInteger(0);
	private static final String MCP_PATH_SPEC = "/*"; // Path for Jetty to map the servlet
	private static Project project;

	public static void start(int port, PluginTool tool) {
		synchronized (lock) {
			Project currentProject = tool.getProject();

			if (currentProject != null && !currentProject.equals(project)) {
				Msg.info(GhidraMcpServer.class, "Project changed to " + currentProject.getName());
				project = currentProject;
				GhidraMcpServer.stop();
			}

			if (refCount.incrementAndGet() == 1) {
				if (project == null) {
					Msg.error(GhidraMcpServer.class, "Project is null");
					return;
				}

				Msg.info(GhidraMcpServer.class, "Starting MCP Server on port " + port);
				try {
					// 1. Create the Transport Provider (Servlet)
					transportProvider = new HttpServletSseServerTransportProvider(
							new ObjectMapper(), "/mcp/message"); // Internal MCP path

					// 2. Create MCP Server Logic
					mcpTools = new GhidraMcpTools(project);
					mcpAsyncServer = McpServer.async(transportProvider)
							.serverInfo("ghidra-mcp", "1.0.0")
							.capabilities(ServerCapabilities.builder()
									.tools(true)
									.logging()
									.build())
							.tools(mcpTools.getTools())
							.build();

					// 3. Create and Configure Jetty Server
					startJettyServer(port);

				} catch (JsonProcessingException e) {
					Msg.error(GhidraMcpServer.class, "MCP Server JSON configuration error: " + e.getMessage(), e);
					// Decrement ref count as startup failed
					refCount.decrementAndGet();
					cleanUpResources(); // Attempt cleanup
				} catch (Exception e) {
					Msg.error(GhidraMcpServer.class, "Failed to start Jetty server: " + e.getMessage(), e);
					// Decrement ref count as startup failed
					refCount.decrementAndGet();
					cleanUpResources(); // Attempt cleanup
				}
			} else {
				Msg.info(GhidraMcpServer.class, "MCP Server already running or starting (refCount=" + refCount.get() + ").");
			}
		}
	}

	private static void startJettyServer(int port) {
		try {

			jettyServer = new Server();

			// Configure Connector
			ServerConnector connector = new ServerConnector(jettyServer);
			connector.setPort(port);
			connector.setHost("127.0.0.1"); // Bind to localhost only for security
			jettyServer.addConnector(connector);

			// Configure Servlet Handler
			ServletContextHandler context = new ServletContextHandler(ServletContextHandler.SESSIONS);
			context.setContextPath("/"); // Root context path

			// Add the MCP Transport Provider Servlet to Jetty
			context.addServlet(new ServletHolder(transportProvider), MCP_PATH_SPEC);

			jettyServer.setHandler(context);

			// 4. Start Jetty
			jettyServer.start();
			Msg.info(GhidraMcpServer.class, "Jetty server started successfully at http://127.0.0.1:" + port + "/");

		} catch (Exception e) {
			Msg.error(GhidraMcpServer.class, "Failed to start Jetty server: " + e.getMessage(), e);
		}
	}

	public static void restartJettyServer(int port) {
		Msg.info(GhidraMcpServer.class, "Restarting Jetty server...");
		if (jettyServer != null) {
			try {
				jettyServer.stop();
				Msg.info(GhidraMcpServer.class, "Jetty server stopped.");
			} catch (Exception e) {
				Msg.error(GhidraMcpServer.class, "Failed to stop Jetty server: " + e.getMessage(), e);
				return;
			}
		}
		startJettyServer(port);
	}

	public static void dispose() {
		synchronized (lock) {
			int count = refCount.decrementAndGet();
			Msg.info(GhidraMcpServer.class, "dispose: " + count);
			if (count == 0) {
				Msg.info(GhidraMcpServer.class, "Stopping MCP Server...");
				cleanUpResources();
				Msg.info(GhidraMcpServer.class, "MCP Server stopped.");
			} else if (count < 0) {
				Msg.warn(GhidraMcpServer.class, "Stop server called but refCount was already zero or negative.");
				refCount.set(0); // Reset to zero just in case
			}
		}
	}

	public static void stop() {
		synchronized (lock) {
			cleanUpResources();
			refCount.set(0); // Reset to zero just in case
		}
	}

	// Helper method for cleanup
	private static void cleanUpResources() {
		// Stop MCP Async Server first
		if (mcpAsyncServer != null) {
			try {
				mcpAsyncServer.close();
				Msg.info(GhidraMcpServer.class, "McpAsyncServer closed.");
			} catch (Exception e) {
				Msg.error(GhidraMcpServer.class, "Error closing McpAsyncServer: " + e.getMessage(), e);
			} finally {
				mcpAsyncServer = null;
			}
		}

		// Stop Jetty Server
		if (jettyServer != null) {
			try {
				jettyServer.stop();
				Msg.info(GhidraMcpServer.class, "Jetty server stopped.");
			} catch (Exception e) {
				Msg.error(GhidraMcpServer.class, "Error stopping Jetty server: " + e.getMessage(), e);
			} finally {
				jettyServer = null;
			}
		}

		// Nullify transport provider
		transportProvider = null;
	}
}
