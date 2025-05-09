package com.themixednuts;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletResponseWrapper;
import ghidra.util.Msg;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.time.Duration;

/**
 * A servlet filter that sends periodic keep-alive comments for Server-Sent
 * Events (SSE)
 * connections. This helps prevent proxies or other network intermediaries from
 * prematurely
 * closing idle SSE connections. It also manages a maximum duration for these
 * keep-alive pings.
 */
public class GhidraKeepAliveSseFilter implements Filter {
	private static final String CLASS_NAME = GhidraKeepAliveSseFilter.class.getSimpleName();
	private static final String SSE_CONTENT_TYPE = "text/event-stream";
	private static final String KEEP_ALIVE_COMMENT = ": keepalive\\n\\n";
	private static final Duration KEEP_ALIVE_INTERVAL = Duration.ofSeconds(25);

	private ScheduledExecutorService scheduler;
	private final ConcurrentMap<String, SseSessionDetails> activeSseSessions = new ConcurrentHashMap<>();
	private final Duration maxSessionKeepAliveDurationConfig;

	/**
	 * Holds details for an active SSE session, including its {@link PrintWriter}
	 * and registration timestamp.
	 */
	private static class SseSessionDetails {
		final PrintWriter writer;
		final long registrationTimestamp;

		/**
		 * Constructs SseSessionDetails.
		 * 
		 * @param writer The PrintWriter for the SSE connection.
		 */
		SseSessionDetails(PrintWriter writer) {
			this.writer = writer;
			this.registrationTimestamp = System.currentTimeMillis();
		}
	}

	/**
	 * Constructs a new GhidraKeepAliveSseFilter.
	 *
	 * @param maxKeepAliveSeconds The maximum duration in seconds to send keep-alive
	 *                            pings.
	 *                            A value of 0 means pings are sent indefinitely
	 *                            (using a
	 *                            very large practical limit).
	 */
	public GhidraKeepAliveSseFilter(long maxKeepAliveSeconds) {
		if (maxKeepAliveSeconds == 0) {
			this.maxSessionKeepAliveDurationConfig = Duration.ofMillis(Long.MAX_VALUE);
		} else {
			this.maxSessionKeepAliveDurationConfig = Duration.ofSeconds(maxKeepAliveSeconds);
		}
	}

	/**
	 * Initializes the filter and schedules the keep-alive task.
	 * 
	 * @param filterConfig The filter configuration object.
	 * @throws ServletException If an error occurs during initialization.
	 */
	@Override
	public void init(FilterConfig filterConfig) throws ServletException {
		scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
			Thread t = new Thread(r, "sse-keep-alive-scheduler");
			t.setDaemon(true);
			return t;
		});
		scheduler.scheduleAtFixedRate(this::sendKeepAlives,
				KEEP_ALIVE_INTERVAL.toMillis(),
				KEEP_ALIVE_INTERVAL.toMillis(),
				TimeUnit.MILLISECONDS);
		Msg.info(CLASS_NAME,
				"SSE Keep-Alive Filter initialized. Keep-alive interval: " + KEEP_ALIVE_INTERVAL.getSeconds() +
						" seconds. Max session ping duration: " +
						(maxSessionKeepAliveDurationConfig.toMillis() == Long.MAX_VALUE ? "Indefinite"
								: maxSessionKeepAliveDurationConfig.toHours() + " hours / "
										+ maxSessionKeepAliveDurationConfig.toSeconds() + " seconds."));
	}

	/**
	 * Periodically sends keep-alive comments to all registered SSE connections.
	 * If a connection has exceeded its maximum keep-alive duration or if an error
	 * occurs
	 * while sending, the connection is unregistered.
	 */
	private void sendKeepAlives() {
		if (activeSseSessions.isEmpty()) {
			return;
		}
		List<String> sessionsToUnregister = new ArrayList<>();
		long currentTime = System.currentTimeMillis();

		for (Map.Entry<String, SseSessionDetails> entry : activeSseSessions.entrySet()) {
			String connectionId = entry.getKey();
			SseSessionDetails sessionDetails = entry.getValue();

			if ((currentTime - sessionDetails.registrationTimestamp) > maxSessionKeepAliveDurationConfig.toMillis()) {
				Msg.info(CLASS_NAME, "Max keep-alive duration reached for session " + connectionId + ". Stopping pings.");
				sessionsToUnregister.add(connectionId);
				continue;
			}

			try {
				synchronized (sessionDetails.writer) {
					sessionDetails.writer.write(KEEP_ALIVE_COMMENT);
					sessionDetails.writer.flush();
					if (sessionDetails.writer.checkError()) {
						throw new IOException("PrintWriter encountered an error for connection " + connectionId);
					}
				}
			} catch (Exception e) {
				Msg.warn(CLASS_NAME,
						"Error sending keep-alive to connection " + connectionId + ", removing: " + e.getMessage());
				sessionsToUnregister.add(connectionId);
			}
		}
		sessionsToUnregister.forEach(this::unregisterSseWriter);
	}

	/**
	 * Filters requests to wrap SSE responses for keep-alive handling.
	 * Non-HTTP requests or responses are passed through unchanged.
	 *
	 * @param request  The ServletRequest.
	 * @param response The ServletResponse.
	 * @param chain    The FilterChain.
	 * @throws IOException      If an I/O error occurs.
	 * @throws ServletException If a servlet error occurs.
	 */
	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {

		if (!(request instanceof HttpServletRequest && response instanceof HttpServletResponse)) {
			chain.doFilter(request, response);
			return;
		}

		HttpServletRequest httpRequest = (HttpServletRequest) request;
		String remoteAddr = httpRequest.getRemoteAddr();
		String remoteHost = httpRequest.getRemoteHost();
		int remotePort = httpRequest.getRemotePort();
		String userAgent = httpRequest.getHeader("User-Agent");
		Msg.info(CLASS_NAME, "Client connection attempt from: " + remoteAddr + ":" + remotePort +
				" (Host: " + remoteHost + ", User-Agent: " + userAgent + ")");

		HttpServletResponse httpResponse = (HttpServletResponse) response;
		String connectionId = UUID.randomUUID().toString();

		SseResponseWrapper sseResponseWrapper = new SseResponseWrapper(httpResponse, connectionId, this);

		try {
			chain.doFilter(httpRequest, sseResponseWrapper);
		} catch (Throwable t) {
			Msg.error(CLASS_NAME,
					"Throwable caught while processing filter chain for " + connectionId + ": " + t.getMessage(), t);
			if (t instanceof IOException)
				throw (IOException) t;
			if (t instanceof ServletException)
				throw (ServletException) t;
			if (t instanceof RuntimeException)
				throw (RuntimeException) t;
			if (t instanceof Error)
				throw (Error) t;
			throw new ServletException("Unhandled throwable in filter chain: " + t.getMessage(), t);
		}
	}

	/**
	 * Registers an SSE {@link PrintWriter} to receive keep-alive messages.
	 *
	 * @param connectionId A unique identifier for the connection.
	 * @param writer       The PrintWriter associated with the SSE connection.
	 */
	public void registerSseWriter(String connectionId, PrintWriter writer) {
		SseSessionDetails sessionDetails = new SseSessionDetails(writer);
		activeSseSessions.putIfAbsent(connectionId, sessionDetails);
	}

	/**
	 * Unregisters an SSE {@link PrintWriter}, stopping keep-alive messages for it.
	 *
	 * @param connectionId The unique identifier for the connection to unregister.
	 */
	public void unregisterSseWriter(String connectionId) {
		activeSseSessions.remove(connectionId);
	}

	/**
	 * Cleans up resources used by the filter, primarily shutting down the
	 * keep-alive scheduler.
	 */
	@Override
	public void destroy() {
		Msg.info(CLASS_NAME, "Destroying SSE Keep-Alive Filter.");
		if (scheduler != null && !scheduler.isShutdown()) {
			scheduler.shutdown();
			try {
				if (!scheduler.awaitTermination(5, TimeUnit.SECONDS)) {
					scheduler.shutdownNow();
					Msg.warn(CLASS_NAME, "SSE keep-alive scheduler did not terminate gracefully, forcing shutdown.");
				}
			} catch (InterruptedException e) {
				Msg.error(CLASS_NAME, "Interrupted while waiting for SSE keep-alive scheduler to terminate.", e);
				scheduler.shutdownNow();
				Thread.currentThread().interrupt();
			}
		}
		activeSseSessions.clear();
		Msg.info(CLASS_NAME, "SSE Keep-Alive Filter destroyed. All active sessions cleared.");
	}

	/**
	 * A {@link HttpServletResponseWrapper} that detects SSE connections and
	 * facilitates their registration with the {@link GhidraKeepAliveSseFilter}.
	 * It also provides a wrapped {@link PrintWriter} that ensures registration
	 * before any writes occur on an SSE stream.
	 */
	private static class SseResponseWrapper extends HttpServletResponseWrapper {
		private final String connectionId;
		private final GhidraKeepAliveSseFilter filter;
		private PrintWriterWrapper writerWrapper;
		private boolean contentTypeSetToSse = false;
		private boolean sseStreamRegistered = false;

		/**
		 * Constructs an SseResponseWrapper.
		 *
		 * @param response     The original HttpServletResponse.
		 * @param connectionId A unique ID for this connection.
		 * @param filter       The parent GhidraKeepAliveSseFilter instance.
		 */
		public SseResponseWrapper(HttpServletResponse response, String connectionId, GhidraKeepAliveSseFilter filter) {
			super(response);
			this.connectionId = connectionId;
			this.filter = filter;
		}

		@Override
		public void setContentType(String type) {
			super.setContentType(type);
			if (type != null && type.toLowerCase().startsWith(SSE_CONTENT_TYPE.toLowerCase())) {
				this.contentTypeSetToSse = true;
			}
		}

		@Override
		public void addHeader(String name, String value) {
			super.addHeader(name, value);
			if ("Content-Type".equalsIgnoreCase(name) && value != null
					&& value.toLowerCase().startsWith(SSE_CONTENT_TYPE.toLowerCase())) {
				this.contentTypeSetToSse = true;
			}
		}

		@Override
		public void setHeader(String name, String value) {
			super.setHeader(name, value);
			if ("Content-Type".equalsIgnoreCase(name) && value != null
					&& value.toLowerCase().startsWith(SSE_CONTENT_TYPE.toLowerCase())) {
				this.contentTypeSetToSse = true;
			}
		}

		/**
		 * Returns a {@link PrintWriterWrapper} that ensures the SSE stream is
		 * registered
		 * with the filter before any write operations if the content type indicates an
		 * SSE stream.
		 * 
		 * @return A PrintWriter for sending text to the client.
		 * @throws IOException if an input or output exception occurred
		 */
		@Override
		public PrintWriter getWriter() throws IOException {
			if (writerWrapper == null) {
				PrintWriter originalWriter = super.getWriter();
				this.writerWrapper = new PrintWriterWrapper(originalWriter, connectionId, filter, this);
			}
			return this.writerWrapper;
		}

		/**
		 * Confirms if the current response is an SSE stream based on its content type
		 * and, if so, registers its writer with the {@link GhidraKeepAliveSseFilter}.
		 * This is called by the {@link PrintWriterWrapper} before any write operation.
		 *
		 * @param wrapperInstance The PrintWriterWrapper instance making the call.
		 */
		void confirmSseStreamAndRegisterWriter(PrintWriterWrapper wrapperInstance) {
			if (this.contentTypeSetToSse && !this.sseStreamRegistered) {
				filter.registerSseWriter(connectionId, wrapperInstance);
				this.sseStreamRegistered = true;
			}
		}
	}

	/**
	 * A {@link PrintWriter} wrapper that ensures an SSE stream is registered with
	 * the
	 * {@link GhidraKeepAliveSseFilter} before any data is written. It delegates
	 * actual write operations to the wrapped PrintWriter.
	 */
	private static class PrintWriterWrapper extends PrintWriter {
		private final String connectionId;
		private final GhidraKeepAliveSseFilter filter;
		private final SseResponseWrapper responseWrapper;

		/**
		 * Constructs a PrintWriterWrapper.
		 *
		 * @param out             The underlying PrintWriter to wrap.
		 * @param connectionId    A unique ID for this connection.
		 * @param filter          The parent GhidraKeepAliveSseFilter instance.
		 * @param responseWrapper The SseResponseWrapper associated with this writer.
		 */
		public PrintWriterWrapper(PrintWriter out, String connectionId, GhidraKeepAliveSseFilter filter,
				SseResponseWrapper responseWrapper) {
			super(out, false);
			this.connectionId = connectionId;
			this.filter = filter;
			this.responseWrapper = responseWrapper;
		}

		/**
		 * Checks and registers the SSE stream with the filter if it hasn't been
		 * already.
		 * This is called internally before any write operation.
		 */
		private void checkAndRegister() {
			responseWrapper.confirmSseStreamAndRegisterWriter(this);
		}

		@Override
		public void write(int c) {
			synchronized (this) {
				checkAndRegister();
				super.write(c);
			}
		}

		@Override
		public void write(char[] buf, int off, int len) {
			synchronized (this) {
				checkAndRegister();
				super.write(buf, off, len);
			}
		}

		@Override
		public void write(String s, int off, int len) {
			synchronized (this) {
				checkAndRegister();
				super.write(s, off, len);
			}
		}

		@Override
		public void write(String s) {
			synchronized (this) {
				checkAndRegister();
				super.write(s);
			}
		}

		@Override
		public void println() {
			synchronized (this) {
				checkAndRegister();
				super.println();
			}
		}

		@Override
		public void flush() {
			synchronized (this) {
				super.flush();
			}
		}

		/**
		 * Closes the underlying stream and unregisters this writer from the
		 * {@link GhidraKeepAliveSseFilter}.
		 */
		@Override
		public void close() {
			synchronized (this) {
				try {
					super.close();
				} finally {
					filter.unregisterSseWriter(connectionId);
				}
			}
		}
	}
}
