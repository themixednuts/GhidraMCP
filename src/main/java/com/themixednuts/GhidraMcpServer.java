package com.themixednuts;

import java.util.concurrent.atomic.AtomicInteger;

import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.ee10.servlet.ServletContextHandler;
import org.eclipse.jetty.ee10.servlet.ServletHolder;
import org.eclipse.jetty.ee10.servlet.FilterHolder;
import jakarta.servlet.DispatcherType;
import java.util.EnumSet;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import ghidra.framework.model.Project;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.Msg;

import io.modelcontextprotocol.server.McpAsyncServer;
import io.modelcontextprotocol.server.McpServer;
import io.modelcontextprotocol.server.transport.HttpServletSseServerTransportProvider;
import io.modelcontextprotocol.spec.McpSchema.ServerCapabilities;

// Import the service interface
import com.themixednuts.services.IGhidraMcpToolProvider;

/**
 * Manages the lifecycle of the embedded Jetty server and the MCP Async Server.
 * Handles starting, stopping, restarting, and reference counting for the server
 * components, ensuring they align with the Ghidra plugin and project context.
 */
public class GhidraMcpServer {
	/** The embedded Jetty Server instance. */
	private static Server jettyServer = null;
	/** The MCP Async Server instance responsible for MCP logic. */
	private static McpAsyncServer mcpAsyncServer = null;
	/** The MCP transport provider (Servlet) that bridges MCP and HTTP SSE. */
	private static HttpServletSseServerTransportProvider transportProvider = null;

	/** Synchronization lock for managing server state and reference counting. */
	private static final Object lock = new Object();
	/**
	 * Reference counter to manage server lifecycle across multiple plugin
	 * instances.
	 */
	private static final AtomicInteger refCount = new AtomicInteger(0);
	/** The HTTP path spec where the MCP transport servlet will be mounted. */
	private static final String MCP_PATH_SPEC = "/*";
	/** The last known active Ghidra project, used for change detection. */
	private static Project project;
	/**
	 * Reference to the PluginTool, used for accessing services and project context.
	 */
	private static PluginTool currentTool;
	private static long currentJettyIdleTimeoutMs; // Store current timeout
	private static long currentSseMaxKeepAliveSeconds; // Store current keep-alive

	/**
	 * Starts the MCP server if it's not already running.
	 * This method is reference-counted; the actual server startup only occurs when
	 * the count transitions from 0 to 1.
	 * It also handles project change detection, forcing a restart if the active
	 * project differs from the one the server was previously running with.
	 *
	 * @param port                   The port number for the embedded HTTP server.
	 * @param tool                   The Ghidra {@link PluginTool} providing the
	 *                               context (project,
	 *                               services).
	 * @param jettyIdleTimeoutMs     Jetty server idle connection timeout in
	 *                               milliseconds (0 for infinite).
	 * @param sseMaxKeepAliveSeconds Maximum duration in seconds for SSE keep-alive
	 *                               pings (0 for infinite).
	 */
	public static void start(int port, PluginTool tool, long jettyIdleTimeoutMs, long sseMaxKeepAliveSeconds) {
		synchronized (lock) {
			Project currentProject = tool.getProject();
			currentTool = tool;
			currentJettyIdleTimeoutMs = jettyIdleTimeoutMs;
			currentSseMaxKeepAliveSeconds = sseMaxKeepAliveSeconds;

			// Handle project changes: If the project context differs, force a full restart.
			if (project != null && currentProject != null && !currentProject.equals(project)) {
				Msg.info(GhidraMcpServer.class,
						"Project changed to " + currentProject.getName() + ". Forcing MCP server restart.");
				project = currentProject;
				stop(); // Force stop and cleanup
				refCount.set(0); // Reset ref count for a clean start
			}

			if (refCount.incrementAndGet() == 1) {
				// First reference - perform actual startup
				if (project == null) {
					project = currentProject; // Ensure project field is initialized
					if (project == null) {
						Msg.error(GhidraMcpServer.class,
								"Project is null and could not be retrieved from tool. MCP Server cannot start.");
						refCount.decrementAndGet(); // Abort startup
						return;
					}
				}

				Msg.info(GhidraMcpServer.class, "Starting MCP Server on port " + port + " for project " + project.getName());
				try {
					// Create the Transport Provider (Servlet)
					transportProvider = new HttpServletSseServerTransportProvider(
							new ObjectMapper(), "/mcp/message");

					// Get the Tool Provider Service
					IGhidraMcpToolProvider toolProvider = tool.getService(IGhidraMcpToolProvider.class);
					if (toolProvider == null) {
						Msg.error(GhidraMcpServer.class,
								"Fatal: Could not retrieve IGhidraMcpToolProvider service! MCP Server cannot start.");
						refCount.decrementAndGet(); // Abort startup
						cleanUpResources();
						return;
					}

					// Create MCP Server Logic
					mcpAsyncServer = McpServer.async(transportProvider)
							.serverInfo("ghidra-mcp", "0.1.0")
							.capabilities(ServerCapabilities.builder()
									.tools(true)
									.logging()
									.build())
							// Get tools via the service
							.tools(toolProvider.getAvailableToolSpecifications())
							.build();

					// Create and Configure Jetty Server
					startJettyServer(port, currentJettyIdleTimeoutMs, currentSseMaxKeepAliveSeconds);

				} catch (JsonProcessingException e) {
					Msg.error(GhidraMcpServer.class, "MCP Server JSON configuration error during startup: " + e.getMessage(), e);
					refCount.decrementAndGet(); // Abort startup
					cleanUpResources();
				} catch (Exception e) { // Catch broader exceptions (e.g., from getAvailableToolSpecifications)
					Msg.error(GhidraMcpServer.class, "Failed to start MCP server components: " + e.getMessage(), e);
					refCount.decrementAndGet(); // Abort startup
					cleanUpResources();
				}
			} else {
				Msg.info(GhidraMcpServer.class,
						"MCP Server already running (refCount=" + refCount.get() + ").");
			}
		}
	}

	/**
	 * Initializes and starts the embedded Jetty server on the specified port,
	 * binding only to localhost.
	 * Configures the MCP transport servlet.
	 *
	 * @param port                   The port number for the Jetty server.
	 * @param jettyIdleTimeoutMs     Jetty server idle connection timeout in
	 *                               milliseconds (0 for infinite).
	 * @param sseMaxKeepAliveSeconds Maximum duration in seconds for SSE keep-alive
	 *                               pings (0 for infinite).
	 */
	private static void startJettyServer(int port, long jettyIdleTimeoutMs, long sseMaxKeepAliveSeconds) {
		try {
			jettyServer = new Server();

			// Configure Connector
			ServerConnector connector = new ServerConnector(jettyServer);
			connector.setPort(port);
			connector.setHost("127.0.0.1"); // Bind to localhost only for security
			connector.setIdleTimeout(jettyIdleTimeoutMs); // Set idle timeout (0 means infinite)
			jettyServer.addConnector(connector);

			// Configure Servlet Handler
			ServletContextHandler context = new ServletContextHandler(ServletContextHandler.SESSIONS);
			context.setContextPath("/");

			// Add the KeepAliveSseFilter
			// It should run for requests and async dispatches to cover SSE.
			GhidraKeepAliveSseFilter keepAliveFilter = new GhidraKeepAliveSseFilter(sseMaxKeepAliveSeconds);
			FilterHolder filterHolder = new FilterHolder(keepAliveFilter);
			context.addFilter(filterHolder, MCP_PATH_SPEC, EnumSet.of(DispatcherType.REQUEST, DispatcherType.ASYNC));

			// Use the transportProvider created in the start() method
			// Ensure transportProvider is not null before using it
			if (transportProvider == null) {
				throw new IllegalStateException("MCP Transport Provider is null during MCP Server startup.");
			}
			// HttpServletSseServerTransportProvider likely acts as a servlet
			context.addServlet(new ServletHolder(transportProvider), MCP_PATH_SPEC);
			jettyServer.setHandler(context);

			// Start Jetty
			jettyServer.start();
			Msg.info(GhidraMcpServer.class, "MCP Server started successfully at http://127.0.0.1:" + port + "/");

		} catch (Exception e) {
			Msg.error(GhidraMcpServer.class, "Failed to start MCP Server on port " + port + ": " + e.getMessage(), e);
			// Ensure resources are cleaned up if Jetty fails to start
			cleanUpResources();
		}
	}

	/**
	 * Restarts only the Jetty server component, typically used for port changes.
	 * Stops the existing Jetty instance (if running) and starts a new one on the
	 * specified port.
	 *
	 * @param port                   The new port number for the Jetty server.
	 * @param jettyIdleTimeoutMs     The new Jetty idle timeout.
	 * @param sseMaxKeepAliveSeconds The new SSE max keep-alive duration.
	 */
	public static void restartJettyServer(int port, long jettyIdleTimeoutMs, long sseMaxKeepAliveSeconds) {
		Msg.info(GhidraMcpServer.class, "Restarting Jetty Server on port " + port + " with IdleTimeout="
				+ jettyIdleTimeoutMs + "ms, SSEKeepAlive=" + sseMaxKeepAliveSeconds + "s...");
		if (jettyServer != null) {
			try {
				jettyServer.stop();
			} catch (Exception e) {
				Msg.error(GhidraMcpServer.class, "Failed to stop existing Jetty Server during restart: " + e.getMessage(), e);
				// Attempt to continue starting the new server anyway, but log the error.
				// Consider if a more robust cleanup is needed here for jettyServer itself
				jettyServer = null; // Ensure we don't try to use a potentially broken instance
			}
		}
		// Start new Jetty instance with new parameters
		startJettyServer(port, jettyIdleTimeoutMs, sseMaxKeepAliveSeconds);
	}

	/**
	 * Performs a full restart of the MCP server (both MCP logic and Jetty).
	 * Used when configuration changes (like tool enablement or port/timeout
	 * changes) require reloading.
	 * Relies on the stored {@code currentTool} reference to re-initiate the start
	 * sequence.
	 *
	 * @param port                   The port number to restart the server on.
	 * @param jettyIdleTimeoutMs     The Jetty idle timeout in milliseconds.
	 * @param sseMaxKeepAliveSeconds The SSE max keep-alive duration in seconds.
	 */
	public static void restartMcpServer(int port, long jettyIdleTimeoutMs, long sseMaxKeepAliveSeconds) {
		synchronized (lock) {
			if (currentTool == null) {
				Msg.error(GhidraMcpServer.class,
						"Cannot restart MCP server: PluginTool reference missing. Server may not have started correctly or was already stopped.");
				return;
			}
			Msg.info(GhidraMcpServer.class, "Performing full MCP Server restart due to configuration change... Port: " + port
					+ ", JettyTimeout: " + jettyIdleTimeoutMs + "ms, SSEKeepAlive: " + sseMaxKeepAliveSeconds + "s");
			// Stop everything cleanly
			cleanUpResources();
			// Reset refCount to ensure start logic runs fully
			refCount.set(0);
			// Start again with current tool reference and new config
			start(port, currentTool, jettyIdleTimeoutMs, sseMaxKeepAliveSeconds);
		}
	}

	/**
	 * Decrements the reference count and stops the server if the count reaches
	 * zero.
	 * Called by the plugin during its dispose phase.
	 */
	public static void dispose() {
		synchronized (lock) {
			int count = refCount.decrementAndGet();
			if (count == 0) {
				Msg.info(GhidraMcpServer.class, "Reference count reached zero. Stopping MCP Server...");
				cleanUpResources();
				// Also clear context fields when fully stopped
				project = null;
				currentTool = null;
			} else if (count < 0) {
				Msg.warn(GhidraMcpServer.class,
						"Dispose called but reference count was already zero or negative. Resetting count to zero.");
				refCount.set(0); // Ensure count doesn't stay negative
				// Clear context if it wasn't already
				if (mcpAsyncServer != null || jettyServer != null) {
					cleanUpResources();
				}
				project = null;
				currentTool = null;
			}

		}
	}

	/**
	 * Forces an immediate stop and cleanup of the server resources, resetting the
	 * reference count.
	 * Primarily used internally during project changes.
	 */
	public static void stop() {
		synchronized (lock) {
			Msg.info(GhidraMcpServer.class, "Forcing immediate stop of MCP server.");
			cleanUpResources();
			refCount.set(0);
			project = null; // Clear context on forced stop
			currentTool = null;
		}
	}

	/**
	 * Safely stops and nullifies server components (MCP Async Server and Jetty).
	 * Logs errors if stopping fails but attempts to proceed.
	 */
	private static void cleanUpResources() {
		// Stop MCP Async Server first
		if (mcpAsyncServer != null) {
			try {
				mcpAsyncServer.close();
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
