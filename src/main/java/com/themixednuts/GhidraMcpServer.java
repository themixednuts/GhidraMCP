package com.themixednuts;

import java.util.List;
import java.util.ArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.ee10.servlet.ServletContextHandler;
import org.eclipse.jetty.ee10.servlet.ServletHolder;
import org.eclipse.jetty.ee10.servlet.FilterHolder;
import jakarta.servlet.DispatcherType;
import reactor.core.publisher.Mono;
import reactor.core.publisher.Flux;

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
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;

// Import the service interface
import com.themixednuts.services.IGhidraMcpToolProvider;

import generic.stl.Pair;

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
	private final static HttpServletSseServerTransportProvider transportProvider = new HttpServletSseServerTransportProvider(
			new ObjectMapper(), "/mcp/message");

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
	private static boolean currentEnableSseKeepAlive; // Store current enable state
	private static long currentSseMaxKeepAliveSeconds; // Store current keep-alive
	private static IGhidraMcpToolProvider toolProvider;
	private static List<Pair<String, AsyncToolSpecification>> currentActiveToolSpecs = new ArrayList<>();

	/**
	 * Creates a new McpAsyncServer instance (the shell, without tools initially).
	 *
	 * @return A new instance of {@link McpAsyncServer}.
	 * @throws Exception If there's an error building the server.
	 */
	private static McpAsyncServer createMcpAsyncServerShellInstance() throws Exception {
		if (transportProvider == null) {
			// Should not happen with final static initialization unless ObjectMapper failed
			throw new IllegalStateException("Static transportProvider is null. Cannot initialize MCP logic.");
		}

		Msg.info(GhidraMcpServer.class, "Creating new McpAsyncServer shell instance...");
		return McpServer.async(transportProvider)
				.serverInfo("ghidra-mcp", "0.1.1")
				.capabilities(ServerCapabilities.builder()
						.tools(true)
						.logging()
						.build())
				.tools(currentActiveToolSpecs.stream().map(spec -> spec.second).collect(Collectors.toList()))
				.build();

	}

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
	 * @param enableSseKeepAlive     Whether to enable SSE keep-alive pings.
	 * @param sseMaxKeepAliveSeconds Maximum duration in seconds for SSE keep-alive
	 *                               pings (if enabled).
	 */
	public static void start(int port, PluginTool tool, boolean enableSseKeepAlive, long sseMaxKeepAliveSeconds) {
		synchronized (lock) {
			Project currentProject = tool.getProject();
			currentTool = tool;
			currentEnableSseKeepAlive = enableSseKeepAlive;
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
					// Get the Tool Provider Service
					IGhidraMcpToolProvider retrievedToolProvider = tool.getService(IGhidraMcpToolProvider.class);
					if (retrievedToolProvider == null) {
						Msg.error(GhidraMcpServer.class,
								"Fatal: Could not retrieve IGhidraMcpToolProvider service! MCP Server cannot start.");
						refCount.decrementAndGet(); // Abort startup
						releaseServerResources();
						return;
					}
					GhidraMcpServer.toolProvider = retrievedToolProvider;
					currentActiveToolSpecs.clear();

					currentActiveToolSpecs = toolProvider.getAvailableToolSpecifications();
					mcpAsyncServer = createMcpAsyncServerShellInstance();

					Msg.info(GhidraMcpServer.class,
							"Initialized McpAsyncServer with " + currentActiveToolSpecs.size() + " tools.");

					// Create and Configure Jetty Server
					startHttpServer(port, currentEnableSseKeepAlive, currentSseMaxKeepAliveSeconds);

				} catch (JsonProcessingException e) {
					Msg.error(GhidraMcpServer.class, "MCP Server JSON configuration error during startup: " + e.getMessage(), e);
					refCount.decrementAndGet(); // Abort startup
					releaseServerResources();
				} catch (Exception e) { // Catch broader exceptions (e.g., from getAvailableToolSpecifications)
					Msg.error(GhidraMcpServer.class, "Failed to start MCP server components: " + e.getMessage(), e);
					refCount.decrementAndGet(); // Abort startup
					releaseServerResources();
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
	 * @param enableSseKeepAlive     Whether to enable SSE keep-alive pings.
	 * @param sseMaxKeepAliveSeconds Maximum duration in seconds for SSE keep-alive
	 *                               pings (if enabled).
	 */
	private static void startHttpServer(int port, boolean enableSseKeepAlive, long sseMaxKeepAliveSeconds) {
		try {
			jettyServer = new Server();

			// Configure Connector
			ServerConnector connector = new ServerConnector(jettyServer);
			connector.setPort(port);
			connector.setHost("127.0.0.1"); // Bind to localhost only for security
			jettyServer.addConnector(connector);

			// Configure Servlet Handler
			ServletContextHandler context = new ServletContextHandler(ServletContextHandler.SESSIONS);
			context.setContextPath("/");

			// Add the KeepAliveSseFilter only if enabled
			if (enableSseKeepAlive) {
				GhidraKeepAliveSseFilter keepAliveFilter = new GhidraKeepAliveSseFilter(sseMaxKeepAliveSeconds);
				FilterHolder filterHolder = new FilterHolder(keepAliveFilter);
				context.addFilter(filterHolder, MCP_PATH_SPEC, EnumSet.of(DispatcherType.REQUEST, DispatcherType.ASYNC));
				Msg.info(GhidraMcpServer.class, "SSE Keep-Alive Filter is ENABLED.");
			} else {
				Msg.info(GhidraMcpServer.class, "SSE Keep-Alive Filter is DISABLED.");
			}

			// Use the transportProvider created in the start() method
			// Ensure transportProvider is not null before using it
			// if (transportProvider == null) { // No longer strictly necessary due to final
			// static
			// throw new IllegalStateException("MCP Transport Provider is null during MCP
			// Server startup.");
			// }
			// HttpServletSseServerTransportProvider likely acts as a servlet
			context.addServlet(new ServletHolder(transportProvider), MCP_PATH_SPEC);
			jettyServer.setHandler(context);

			// Start Jetty
			jettyServer.start();
			Msg.info(GhidraMcpServer.class, "MCP Server started successfully at http://127.0.0.1:" + port + "/");

		} catch (Exception e) {
			Msg.error(GhidraMcpServer.class, "Failed to start MCP Server on port " + port + ": " + e.getMessage(), e);
			// Ensure resources are cleaned up if Jetty fails to start
			releaseServerResources();
		}
	}

	/**
	 * Restarts only the Jetty server component, typically used for port changes.
	 * Stops the existing Jetty instance (if running) and starts a new one on the
	 * specified port.
	 *
	 * @param port                   The new port number for the Jetty server.
	 * @param enableSseKeepAlive     Whether to enable SSE keep-alive pings for the
	 *                               new instance.
	 * @param sseMaxKeepAliveSeconds The new SSE max keep-alive duration (if
	 *                               enabled).
	 */
	public static void restartJettyServer(int port, boolean enableSseKeepAlive, long sseMaxKeepAliveSeconds) {
		Msg.info(GhidraMcpServer.class, "Restarting Jetty Server on port " + port
				+ " with SSE Keep-Alive: " + (enableSseKeepAlive ? "Enabled" : "Disabled")
				+ (enableSseKeepAlive ? " (Max Duration: " + sseMaxKeepAliveSeconds + "s)" : "") + "...");
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
		startHttpServer(port, enableSseKeepAlive, sseMaxKeepAliveSeconds);
	}

	/**
	 * Performs a full restart of the MCP server (both MCP logic and Jetty).
	 * Used when configuration changes (like tool enablement or port/timeout
	 * changes) require reloading.
	 * Relies on the stored {@code currentTool} reference to re-initiate the start
	 * sequence.
	 *
	 * @param port                   The port number to restart the server on.
	 * @param enableSseKeepAlive     Whether to enable SSE keep-alive pings.
	 * @param sseMaxKeepAliveSeconds The SSE max keep-alive duration in seconds (if
	 *                               enabled).
	 */
	public static void restartMcpServer(int port, boolean enableSseKeepAlive, long sseMaxKeepAliveSeconds) {
		synchronized (lock) {
			if (currentTool == null) {
				Msg.error(GhidraMcpServer.class,
						"Cannot restart MCP server: PluginTool reference missing. Server may not have started correctly or was already stopped.");
				return;
			}
			Msg.info(GhidraMcpServer.class, "Performing full MCP Server restart due to configuration change... Port: " + port
					+ ", SSE Keep-Alive: " + (enableSseKeepAlive ? "Enabled" : "Disabled")
					+ (enableSseKeepAlive ? " (Max Duration: " + sseMaxKeepAliveSeconds + "s)" : ""));
			// Stop everything cleanly
			releaseServerResources();
			// Reset refCount to ensure start logic runs fully
			refCount.set(0);
			// Start again with current tool reference and new config
			start(port, currentTool, enableSseKeepAlive, sseMaxKeepAliveSeconds);
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
				releaseServerResources();
				// Also clear context fields when fully stopped
				project = null;
				currentTool = null;
			} else if (count < 0) {
				Msg.warn(GhidraMcpServer.class,
						"Dispose called but reference count was already zero or negative. Resetting count to zero.");
				refCount.set(0); // Ensure count doesn't stay negative
				// Clear context if it wasn't already
				if (mcpAsyncServer != null || jettyServer != null) {
					releaseServerResources();
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
			releaseServerResources();
			refCount.set(0);
			project = null; // Clear context on forced stop
			currentTool = null;
		}
	}

	/**
	 * Safely stops and nullifies server components (MCP Async Server and Jetty).
	 * Logs errors if stopping fails but attempts to proceed.
	 */
	private static void releaseServerResources() {
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
		currentActiveToolSpecs.clear(); // Clear active specs when server stops
	}

	public static Mono<Void> notifyToolsListChanged() {
		return notifyListsChanged(true, false, false);
	}

	public static Mono<Void> notifyResourcesListChanged() {
		return notifyListsChanged(false, true, false);
	}

	public static Mono<Void> notifyPromptsListChanged() {
		return notifyListsChanged(false, false, true);
	}

	/**
	 * Synchronizes the live McpAsyncServer's toolset with the desired state from
	 * the tool provider
	 * and notifies clients if changes occurred.
	 * This method assumes McpAsyncServer has addTool(spec) and removeTool(toolId)
	 * methods.
	 */
	private static Mono<Void> notifyListsChanged(boolean toolsChanged, boolean resourcesChanged, boolean promptsChanged) {
		synchronized (lock) {
			if (mcpAsyncServer == null) {
				return Mono.error(new IllegalStateException("MCP Async Server is null. Cannot notify clients."));
			}

			List<Mono<Void>> notificationMonos = new ArrayList<>();

			if (toolsChanged) {
				if (toolProvider == null) {
					Msg.error(GhidraMcpServer.class, "ToolProvider is null. Cannot process tool changes.");
				} else {
					Mono<Void> toolsUpdateAndNotifyMono = Mono.defer(() -> {
						try {
							List<Pair<String, AsyncToolSpecification>> newSpecs = toolProvider.getAvailableToolSpecifications();
							final List<Pair<String, AsyncToolSpecification>> currentSpecsSnapshot = new ArrayList<>(
									currentActiveToolSpecs);

							List<Pair<String, AsyncToolSpecification>> pairsToAdd = newSpecs.stream()
									.filter(newPair -> currentSpecsSnapshot.stream()
											.noneMatch(oldPair -> oldPair.first.equals(newPair.first)))
									.collect(Collectors.toList());

							List<String> toolNamesToRemove = currentSpecsSnapshot.stream()
									.filter(oldPair -> newSpecs.stream().noneMatch(newPair -> newPair.first.equals(oldPair.first)))
									.map(oldPair -> oldPair.first)
									.collect(Collectors.toList());

							if (pairsToAdd.isEmpty() && toolNamesToRemove.isEmpty()) {
								Msg.info(GhidraMcpServer.class, "No tool changes detected to apply via SDK.");
								return Mono.empty();
							}

							Msg.info(GhidraMcpServer.class,
									"Attempting tool changes. To add: " + pairsToAdd.size() + ", To remove: " + toolNamesToRemove.size());

							List<Mono<String>> removalOpMonos = toolNamesToRemove.stream()
									.map(name -> mcpAsyncServer.removeTool(name)
											.thenReturn(name)
											.doOnSuccess(removedName -> Msg.info(GhidraMcpServer.class,
													"Successfully removed tool via SDK: " + removedName))
											.onErrorResume(e -> {
												Msg.error(GhidraMcpServer.class, "Failed to remove tool via SDK: " + name, e);
												return Mono.empty();
											}))
									.collect(Collectors.toList());

							List<Mono<Pair<String, AsyncToolSpecification>>> additionOpMonos = pairsToAdd.stream()
									.map(pair -> mcpAsyncServer.addTool(pair.second)
											.thenReturn(pair)
											.doOnSuccess(addedPair -> Msg.info(GhidraMcpServer.class,
													"Successfully added tool via SDK: " + addedPair.first))
											.onErrorResume(e -> {
												Msg.error(GhidraMcpServer.class, "Failed to add tool via SDK: " + pair.first, e);
												return Mono.empty();
											}))
									.collect(Collectors.toList());

							Mono<List<String>> allSuccessfulRemovals = Flux.merge(removalOpMonos).collectList();
							Mono<List<Pair<String, AsyncToolSpecification>>> allSuccessfulAdditions = Flux.merge(additionOpMonos)
									.collectList();

							return Mono.zip(allSuccessfulRemovals, allSuccessfulAdditions)
									.flatMap(tuple -> {
										List<String> successfullyRemovedNames = tuple.getT1();
										List<Pair<String, AsyncToolSpecification>> successfullyAddedPairs = tuple.getT2();

										boolean sdkChangesSuccessfullyApplied = !successfullyRemovedNames.isEmpty()
												|| !successfullyAddedPairs.isEmpty();

										if (sdkChangesSuccessfullyApplied) {
											List<Pair<String, AsyncToolSpecification>> updatedSpecs = new ArrayList<>(currentActiveToolSpecs);
											updatedSpecs.removeIf(p -> successfullyRemovedNames.contains(p.first));

											for (Pair<String, AsyncToolSpecification> pairToAdd : successfullyAddedPairs) {
												updatedSpecs.removeIf(p -> p.first.equals(pairToAdd.first));
												updatedSpecs.add(pairToAdd);
											}
											currentActiveToolSpecs = updatedSpecs;

											Msg.info(GhidraMcpServer.class,
													"Internal tool spec list updated. Successful SDK removals: " + successfullyRemovedNames.size()
															+ ", Successful SDK additions: " + successfullyAddedPairs.size() + ". Total active: "
															+ currentActiveToolSpecs.size());

											return mcpAsyncServer.notifyToolsListChanged()
													.doOnSuccess(v -> Msg.info(GhidraMcpServer.class,
															"Successfully notified MCP clients of tool list changes."))
													.doOnError(e_notify -> Msg.error(GhidraMcpServer.class,
															"Error during client notification for tool changes: " + e_notify.getMessage(), e_notify));
										} else {
											Msg.info(GhidraMcpServer.class,
													"No tool changes were successfully applied to SDK, though changes might have been detected. Not notifying clients for tool changes.");
											return Mono.empty();
										}
									})
									.doOnError(e_zip -> Msg.error(GhidraMcpServer.class,
											"Error in reactive chain for tool updates processing: " + e_zip.getMessage(), e_zip))
									.then();

						} catch (JsonProcessingException e_json) {
							Msg.error(GhidraMcpServer.class,
									"JSON processing error while getting tool specs for update: " + e_json.getMessage(), e_json);
							return Mono.error(e_json);
						} catch (Exception e_specs) {
							Msg.error(GhidraMcpServer.class,
									"Failed to get available tool specifications for update: " + e_specs.getMessage(), e_specs);
							return Mono.error(e_specs);
						}
					});
					notificationMonos.add(toolsUpdateAndNotifyMono);
				}
			}

			if (resourcesChanged) {
				// notificationMonos.add(Mono.defer(() -> {
				// if (mcpAsyncServer != null) {
				// mcpAsyncServer.notifyResourcesListChanged();
				// Msg.info(GhidraMcpServer.class, "Notified MCP clients of resource updates.");
				// }
				// }).onErrorResume(e -> {
				// Msg.error(GhidraMcpServer.class, "Error notifying resource changes: " +
				// e.getMessage(), e);
				// return Mono.empty();
				// }));
			}

			if (promptsChanged) {
				// notificationMonos.add(Mono.defer(() -> {
				// if (mcpAsyncServer != null) {
				// mcpAsyncServer.notifyPromptsListChanged();
				// Msg.info(GhidraMcpServer.class, "Notified MCP clients of prompt updates.");
				// }
				// }).onErrorResume(e -> {
				// Msg.error(GhidraMcpServer.class, "Error notifying prompt changes: " +
				// e.getMessage(), e);
				// return Mono.empty();
				// }));
			}
			return Mono.when(notificationMonos).then();
		}
	}
}
