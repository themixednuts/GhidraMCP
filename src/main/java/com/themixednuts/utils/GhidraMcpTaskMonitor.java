package com.themixednuts.utils;

import ghidra.util.Msg;
import ghidra.util.task.TaskMonitorAdapter;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import io.modelcontextprotocol.spec.McpSchema.LoggingLevel;
import io.modelcontextprotocol.spec.McpSchema.LoggingMessageNotification;

/**
 * A TaskMonitor implementation that bridges Ghidra task progress/status updates to MCP logging
 * notifications. This class now fully manages its own state for progress, message, maximum, and
 * indeterminacy, as TaskMonitorAdapter is a minimal stub for these.
 */
public class GhidraMcpTaskMonitor extends TaskMonitorAdapter {

  private final McpAsyncServerExchange exchange;
  private final String loggerName;
  private static final String DEFAULT_LOGGER_NAME = GhidraMcpTaskMonitor.class.getSimpleName();

  // Fields to store monitor state, as TaskMonitorAdapter does not store most of
  // these.
  private long currentProgress = 0;
  private long maximumProgress = 0;
  private String currentMessage = "";
  private boolean indeterminateState = false;

  /**
   * Creates a bridge between Ghidra TaskMonitor and MCP logging.
   *
   * @param exchange The MCP exchange to send notifications through.
   * @param loggerName The name to use for the logger in MCP notifications.
   */
  public GhidraMcpTaskMonitor(McpAsyncServerExchange exchange, String loggerName) {
    super(true); // Enable cancellation by default in the adapter
    this.exchange = exchange;
    this.loggerName = loggerName != null ? loggerName : DEFAULT_LOGGER_NAME;
  }

  public GhidraMcpTaskMonitor(McpAsyncServerExchange exchange) {
    this(exchange, DEFAULT_LOGGER_NAME);
  }

  private void sendLog(LoggingLevel level, String message) {
    if (exchange == null) {
      return;
    }
    exchange
        .loggingNotification(
            LoggingMessageNotification.builder()
                .level(level)
                .logger(this.loggerName)
                .data(message)
                .build())
        .subscribe(
            null,
            error -> {
              Msg.error(this.loggerName, "Failed to send MCP log notification: " + message);
            });
  }

  @Override
  public void initialize(long max) {
    // super.initialize(max); // TaskMonitorAdapter.initialize(long) does nothing.
    this.maximumProgress = max;
    this.currentProgress = 0;
    // this.currentMessage = "Initialized..."; // Do not set a default message here.
    // Let initialize(max, message) or setMessage handle it.
    this.indeterminateState = (max == 0);
    // sendProgressUpdate(); // Do not send update here. Let a subsequent setMessage
    // or setProgress trigger it,
    // or if initialize(max, message) is used, its call to setMessage will trigger.
  }

  @Override
  public void setMaximum(long max) {
    // super.setMaximum(max); // TaskMonitorAdapter.setMaximum(long) does nothing.
    this.maximumProgress = max;
    if (this.currentProgress > max) {
      this.currentProgress = max;
    }
    this.indeterminateState = (max == 0);
    sendProgressUpdate();
  }

  @Override
  public void setProgress(long value) {
    // super.setProgress(value); // TaskMonitorAdapter.setProgress(long) does
    // nothing.
    this.currentProgress = value;
    if (this.currentProgress > this.maximumProgress
        && this.maximumProgress > 0) { // only cap if max is not 0
      this.currentProgress = this.maximumProgress;
    }
    sendProgressUpdate();
  }

  @Override
  public void incrementProgress(long incrementAmount) {
    // super.incrementProgress(incrementAmount); //
    // TaskMonitorAdapter.incrementProgress(long) does nothing.
    this.currentProgress += incrementAmount;
    if (this.currentProgress > this.maximumProgress
        && this.maximumProgress > 0) { // only cap if max is not 0
      this.currentProgress = this.maximumProgress;
    }
    sendProgressUpdate();
  }

  @Override
  public void setMessage(String message) {
    // super.setMessage(message); // TaskMonitorAdapter.setMessage(String) does
    // nothing.
    this.currentMessage = (message == null) ? "" : message;
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
    // super.setIndeterminate(indeterminate); //
    // TaskMonitorAdapter.setIndeterminate(boolean) does nothing.
    this.indeterminateState = indeterminate;
    if (indeterminate) {
      sendLog(LoggingLevel.INFO, getMessage() + " (Progress: Indeterminate)");
    } else {
      sendProgressUpdate();
    }
  }

  @Override
  public void cancel() {
    sendLog(LoggingLevel.WARNING, "Task cancellation requested."); // More generic message
    super.cancel(); // Let TaskMonitorAdapter handle actual cancellation flag and listeners
  }

  // Implement getters to return the locally stored state
  @Override
  public long getProgress() {
    return this.currentProgress;
  }

  @Override
  public long getMaximum() {
    return this.maximumProgress;
  }

  @Override
  public String getMessage() {
    return this.currentMessage;
  }

  @Override
  public boolean isIndeterminate() {
    return this.indeterminateState;
  }

  // We can rely on TaskMonitorAdapter for isCancelled(), checkCancelled(),
  // setCancelEnabled(), isCancelEnabled(), addCancelledListener(),
  // removeCancelledListener(), clearCanceled()
  // as it correctly implements these.
}
