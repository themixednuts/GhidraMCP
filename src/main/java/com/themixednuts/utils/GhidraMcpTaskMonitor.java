package com.themixednuts.utils;

import ghidra.util.Msg;
import ghidra.util.task.TaskMonitorAdapter;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import io.modelcontextprotocol.spec.McpSchema.LoggingLevel;
import io.modelcontextprotocol.spec.McpSchema.LoggingMessageNotification;

/**
 * A TaskMonitor implementation that bridges Ghidra task progress/status updates
 * to MCP logging notifications by extending TaskMonitorAdapter.
 */
public class GhidraMcpTaskMonitor extends TaskMonitorAdapter {

	private final McpAsyncServerExchange exchange;
	private final String loggerName;

	/**
	 * Creates a bridge between Ghidra TaskMonitor and MCP logging.
	 *
	 * @param exchange   The MCP exchange to send notifications through.
	 * @param loggerName The name to use for the logger in MCP notifications.
	 */
	public GhidraMcpTaskMonitor(McpAsyncServerExchange exchange, String loggerName) {
		this.exchange = exchange;
		this.loggerName = loggerName != null ? loggerName : "GhidraMcpTaskMonitor";
	}

	private void sendLog(LoggingLevel level, String message) {
		exchange.loggingNotification(LoggingMessageNotification.builder()
				.level(level)
				.logger(this.loggerName)
				.data(message)
				.build())
				.subscribe(
						null, // No action needed on successful completion (Void)
						error -> {
							Msg.error(this.loggerName, "Failed to send MCP log notification: " + message, error);
						});
	}

	@Override
	public void initialize(long max) {
		super.initialize(max);
		setMessage("Initialized...");
	}

	@Override
	public void setMaximum(long max) {
		super.setMaximum(max);
		sendProgressUpdate();
	}

	@Override
	public void setProgress(long value) {
		super.setProgress(value);
		sendProgressUpdate();
	}

	@Override
	public void incrementProgress(long incrementAmount) {
		super.incrementProgress(incrementAmount);
		sendProgressUpdate();
	}

	@Override
	public void setMessage(String message) {
		super.setMessage(message);
		sendProgressUpdate();
	}

	private void sendProgressUpdate() {
		String progressString = "";
		if (!isIndeterminate() && getMaximum() > 0) {
			progressString = String.format(" [%d/%d]", getProgress(), getMaximum());
		}
		sendLog(LoggingLevel.INFO, getMessage() + progressString);
	}

	@Override
	public void setIndeterminate(boolean indeterminate) {
		super.setIndeterminate(indeterminate);
		if (indeterminate) {
			sendLog(LoggingLevel.INFO, getMessage() + " (Progress: Indeterminate)");
		} else {
			sendProgressUpdate();
		}
	}

	@Override
	public void cancel() {
		sendLog(LoggingLevel.WARNING, "Task cancellation requested internally within Ghidra.");
		super.cancel();
	}

}