package com.themixednuts;

import com.themixednuts.services.IGhidraMcpToolProvider;
import generic.stl.Pair;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpStatelessAsyncServer;
import io.modelcontextprotocol.server.McpServer;
import io.modelcontextprotocol.server.McpStatelessServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.server.transport.HttpServletStatelessServerTransport;
import io.modelcontextprotocol.spec.McpSchema.ServerCapabilities;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;
import org.eclipse.jetty.ee10.servlet.ServletContextHandler;
import org.eclipse.jetty.ee10.servlet.ServletHolder;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;

/**
 * Manages the lifecycle of the embedded Jetty server with a stateless MCP server.
 * Provides a simplified architecture suitable for stateless HTTP streamable transport.
 */
public class GhidraMcpServer {

    /** The embedded Jetty Server instance. */
    private static Server jettyServer = null;
    /** The MCP Stateless Async Server instance. */
    private static McpStatelessAsyncServer mcpServer = null;
    /** The MCP transport provider for stateless HTTP. */
    private static HttpServletStatelessServerTransport transportProvider = null;

    /** Synchronization lock for managing server state and reference counting. */
    private static final Object lock = new Object();
    /** Reference counter to manage server lifecycle across multiple plugin instances. */
    private static final AtomicInteger refCount = new AtomicInteger(0);
    /** The HTTP path spec where the MCP transport servlet will be mounted. */
    private static final String MCP_PATH_SPEC = "/*";

    /**
     * Starts the MCP server if it's not already running.
     * This method is reference-counted; the actual server startup only occurs when
     * the count transitions from 0 to 1.
     *
     * @param port The port number to start the HTTP server on.
     * @param tool The active Ghidra PluginTool instance for accessing services.
     * @return true if the server was started (or was already running), false otherwise.
     */
    public static boolean start(int port, PluginTool tool) {
        synchronized (lock) {
            int newCount = refCount.incrementAndGet();
            Msg.info(GhidraMcpServer.class, "MCP Server start requested. Reference count: " + newCount);

            if (newCount == 1) {
                // First reference - actually start the server
                try {
                    return startServer(port, tool);
                } catch (Exception e) {
                    Msg.error(GhidraMcpServer.class, "Failed to start MCP server", e);
                    refCount.decrementAndGet(); // Reset count on failure
                    return false;
                }
            } else {
                // Server already running
                Msg.info(GhidraMcpServer.class, "MCP server already running (ref count: " + newCount + ")");
                return jettyServer != null && jettyServer.isRunning();
            }
        }
    }

    /**
     * Stops the MCP server.
     * This method is reference-counted; the actual server shutdown only occurs when
     * the count transitions from some positive value to 0.
     *
     * @return true if the server was stopped (or was already stopped), false otherwise.
     */
    public static boolean stop() {
        synchronized (lock) {
            int newCount = refCount.decrementAndGet();
            Msg.info(GhidraMcpServer.class, "MCP Server stop requested. Reference count: " + newCount);

            if (newCount <= 0) {
                // Last reference - actually stop the server
                refCount.set(0); // Ensure it doesn't go negative
                return stopServer();
            } else {
                // Server still has references
                Msg.info(GhidraMcpServer.class, "MCP server still has references (count: " + newCount + ")");
                return true;
            }
        }
    }

    /**
     * Restarts the MCP server with a new port.
     *
     * @param port The new port number.
     * @param tool The active Ghidra PluginTool instance.
     * @return true if restart was successful, false otherwise.
     */
    public static boolean restart(int port, PluginTool tool) {
        Msg.info(GhidraMcpServer.class, "Restarting MCP server on port " + port);

        synchronized (lock) {
            // Stop the current server
            if (!stopServer()) {
                Msg.warn(GhidraMcpServer.class, "Failed to cleanly stop server during restart");
            }

            // Start with the new configuration
            try {
                return startServer(port, tool);
            } catch (Exception e) {
                Msg.error(GhidraMcpServer.class, "Failed to restart MCP server", e);
                return false;
            }
        }
    }

    /**
     * Actually starts the HTTP server and initializes the MCP components.
     */
    private static boolean startServer(int port, PluginTool tool) throws Exception {
        Msg.info(GhidraMcpServer.class, "Starting MCP server on port " + port);

        // Get the tool provider service
        IGhidraMcpToolProvider toolProvider = tool.getService(IGhidraMcpToolProvider.class);
        if (toolProvider == null) {
            throw new IllegalStateException("IGhidraMcpToolProvider service not available");
        }

        // Get available tools
        List<Pair<String, AsyncToolSpecification>> toolSpecs = toolProvider.getAvailableToolSpecifications();
        List<AsyncToolSpecification> activeToolSpecs = toolSpecs.stream()
            .map(spec -> spec.second)
            .filter(Objects::nonNull)
            .collect(Collectors.toList());

        Msg.info(GhidraMcpServer.class,
            "Loaded " + toolSpecs.size() + " MCP tools; " + activeToolSpecs.size() + " enabled");
        if (activeToolSpecs.isEmpty()) {
            Msg.warn(GhidraMcpServer.class, "No MCP tools enabled; server will start without tool endpoints");
        }

        // Create transport provider
        transportProvider = HttpServletStatelessServerTransport.builder()
            .build();

        // Create MCP server
        mcpServer = McpServer.async(transportProvider)
            .serverInfo("ghidra-mcp", "0.3.0")
            .capabilities(ServerCapabilities.builder().tools(true).build())
            .tools(activeToolSpecs)
            .build();

        Msg.info(GhidraMcpServer.class,
            "Initialized stateless MCP server with " + activeToolSpecs.size() + " tool endpoint(s)");

        // Create and configure Jetty server
        jettyServer = new Server();
        ServerConnector connector = new ServerConnector(jettyServer);
        connector.setHost("127.0.0.1");
        connector.setPort(port);
        jettyServer.addConnector(connector);

        // Create servlet context
        ServletContextHandler context = new ServletContextHandler(ServletContextHandler.SESSIONS);
        context.setContextPath("/");
        jettyServer.setHandler(context);

        // Register MCP transport servlet
        context.addServlet(new ServletHolder(transportProvider), MCP_PATH_SPEC);

        // Start the server
        jettyServer.start();

        Msg.info(GhidraMcpServer.class,
            "MCP server successfully started on port " + port +
            " with " + toolSpecs.size() + " tools available via stateless HTTP transport");

        return true;
    }

    /**
     * Actually stops the HTTP server and cleans up MCP components.
     */
    private static boolean stopServer() {
        Msg.info(GhidraMcpServer.class, "Stopping MCP server");

        boolean success = true;

        // Stop MCP server
        if (mcpServer != null) {
            try {
                mcpServer.close();
                Msg.info(GhidraMcpServer.class, "MCP server closed successfully");
            } catch (Exception e) {
                Msg.error(GhidraMcpServer.class, "Error closing MCP server", e);
                success = false;
            } finally {
                mcpServer = null;
            }
        }

        // Stop Jetty server
        if (jettyServer != null) {
            try {
                jettyServer.stop();
                jettyServer.join();
                Msg.info(GhidraMcpServer.class, "Jetty server stopped successfully");
            } catch (Exception e) {
                Msg.error(GhidraMcpServer.class, "Error stopping Jetty server", e);
                success = false;
            } finally {
                jettyServer = null;
            }
        }

        // Clear transport provider
        transportProvider = null;

        if (success) {
            Msg.info(GhidraMcpServer.class, "MCP server stopped successfully");
        }

        return success;
    }

    /**
     * Returns whether the MCP server is currently running.
     */
    public static boolean isRunning() {
        return jettyServer != null && jettyServer.isRunning() && mcpServer != null;
    }

    /**
     * Returns the current reference count.
     */
    public static int getReferenceCount() {
        return refCount.get();
    }
}

