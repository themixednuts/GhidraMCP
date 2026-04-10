package com.themixednuts.utils;

import ghidra.util.Msg;
import ghidra.util.task.TaskMonitorAdapter;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import io.modelcontextprotocol.spec.McpSchema.LoggingLevel;
import io.modelcontextprotocol.spec.McpSchema.LoggingMessageNotification;
import io.modelcontextprotocol.spec.McpSchema.ProgressNotification;

/**
 * A TaskMonitor implementation that bridges Ghidra task progress/status updates to MCP logging
 * notifications. This class now fully manages its own state for progress, message, maximum, and
 * indeterminacy, as TaskMonitorAdapter is a minimal stub for these.
 */
public class GhidraMcpTaskMonitor extends TaskMonitorAdapter {

  private static final int LOG_PROGRESS_BUCKET_SIZE = 25;

  private final McpAsyncServerExchange exchange;
  private final Object progressToken;
  private final String loggerName;
  private static final String DEFAULT_LOGGER_NAME = GhidraMcpTaskMonitor.class.getSimpleName();

  // Fields to store monitor state, as TaskMonitorAdapter does not store most of
  // these.
  private long currentProgress = 0;
  private long maximumProgress = 0;
  private String currentMessage = "";
  private boolean indeterminateState = false;
  private Double lastProgressNotificationValue;
  private Double lastProgressNotificationTotal;
  private String lastProgressNotificationMessage;
  private String lastLoggedStatusMessage;
  private int lastLoggedProgressBucket = -1;

  /**
   * Creates a bridge between Ghidra TaskMonitor and MCP logging.
   *
   * @param exchange The MCP exchange to send notifications through.
   * @param loggerName The name to use for the logger in MCP notifications.
   */
  public GhidraMcpTaskMonitor(McpAsyncServerExchange exchange, String loggerName) {
    this(exchange, null, loggerName);
  }

  public GhidraMcpTaskMonitor(
      McpAsyncServerExchange exchange, Object progressToken, String loggerName) {
    super(true); // Enable cancellation by default in the adapter
    this.exchange = exchange;
    this.progressToken = progressToken;
    this.loggerName = loggerName != null ? loggerName : DEFAULT_LOGGER_NAME;
  }

  public GhidraMcpTaskMonitor(McpAsyncServerExchange exchange) {
    this(exchange, null, DEFAULT_LOGGER_NAME);
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

  public void logInfo(String message) {
    if (message == null || message.isBlank()) {
      return;
    }
    sendLog(LoggingLevel.INFO, message);
  }

  public void logWarning(String message) {
    if (message == null || message.isBlank()) {
      return;
    }
    sendLog(LoggingLevel.WARNING, message);
  }

  public void logError(String message) {
    if (message == null || message.isBlank()) {
      return;
    }
    sendLog(LoggingLevel.ERROR, message);
  }

  public void start(String message) {
    sendProgressIfChanged();
    logInfo(message);
  }

  public void complete(String message) {
    if (maximumProgress > 0) {
      currentProgress = maximumProgress;
    }
    if (currentMessage == null || currentMessage.isBlank()) {
      this.currentMessage = "Completed";
    }
    sendProgressIfChanged();
    logInfo(message);
  }

  public void fail(String message) {
    if (currentMessage == null || currentMessage.isBlank()) {
      this.currentMessage = "Failed";
    }
    sendProgressIfChanged();
    logError(message);
  }

  private void sendProgress(String message) {
    if (exchange == null || progressToken == null) {
      return;
    }

    Double total = (getMaximum() > 0) ? (double) getMaximum() : null;
    double progress = Math.max(0, getProgress());

    exchange
        .progressNotification(new ProgressNotification(progressToken, progress, total, message))
        .subscribe(
            null,
            error ->
                Msg.error(this.loggerName, "Failed to send MCP progress notification: " + message));
  }

  private void sendProgressIfChanged() {
    String statusMessage = formatStatusMessage();
    Double total = (getMaximum() > 0) ? (double) getMaximum() : null;
    Double progress = (double) Math.max(0, getProgress());

    if (java.util.Objects.equals(lastProgressNotificationValue, progress)
        && java.util.Objects.equals(lastProgressNotificationTotal, total)
        && java.util.Objects.equals(lastProgressNotificationMessage, statusMessage)) {
      return;
    }

    lastProgressNotificationValue = progress;
    lastProgressNotificationTotal = total;
    lastProgressNotificationMessage = statusMessage;
    sendProgress(statusMessage);
  }

  private String formatStatusMessage() {
    String message = getMessage();
    if (message == null || message.isBlank()) {
      message = "Working";
    }

    if (isIndeterminate() || getMaximum() <= 0) {
      return message;
    }

    return String.format("%s [%d/%d]", message, getProgress(), getMaximum());
  }

  private void publishStatus(boolean messageChanged, boolean stateChanged) {
    String statusMessage = formatStatusMessage();
    sendProgressIfChanged();

    if (progressToken != null) {
      if (messageChanged && !java.util.Objects.equals(lastLoggedStatusMessage, statusMessage)) {
        lastLoggedStatusMessage = statusMessage;
        sendLog(LoggingLevel.INFO, statusMessage);
      }
      return;
    }

    int progressBucket = getProgressBucket();
    boolean bucketChanged = progressBucket != -1 && progressBucket > lastLoggedProgressBucket;
    if (messageChanged || stateChanged || bucketChanged) {
      if (!java.util.Objects.equals(lastLoggedStatusMessage, statusMessage) || bucketChanged) {
        lastLoggedStatusMessage = statusMessage;
        lastLoggedProgressBucket = progressBucket;
        sendLog(LoggingLevel.INFO, statusMessage);
      }
    }
  }

  private int getProgressBucket() {
    if (maximumProgress <= 0) {
      return -1;
    }
    double percent = Math.min(100.0d, (currentProgress * 100.0d) / maximumProgress);
    return (int) (percent / LOG_PROGRESS_BUCKET_SIZE);
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
    publishStatus(false, false);
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
    publishStatus(false, false);
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
    publishStatus(false, false);
  }

  @Override
  public void setMessage(String message) {
    // super.setMessage(message); // TaskMonitorAdapter.setMessage(String) does
    // nothing.
    boolean changed =
        !java.util.Objects.equals(this.currentMessage, (message == null) ? "" : message);
    this.currentMessage = (message == null) ? "" : message;
    publishStatus(changed, false);
  }

  @Override
  public void setIndeterminate(boolean indeterminate) {
    // super.setIndeterminate(indeterminate); //
    // TaskMonitorAdapter.setIndeterminate(boolean) does nothing.
    boolean changed = this.indeterminateState != indeterminate;
    this.indeterminateState = indeterminate;
    publishStatus(false, changed);
  }

  @Override
  public void cancel() {
    logWarning("Task cancellation requested.");
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
