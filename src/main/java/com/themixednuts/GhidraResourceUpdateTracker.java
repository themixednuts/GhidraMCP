package com.themixednuts;

import com.themixednuts.utils.GhidraStateUtils;
import ghidra.app.events.ProgramActivatedPluginEvent;
import ghidra.app.events.ProgramClosedPluginEvent;
import ghidra.app.events.ProgramOpenedPluginEvent;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainObject;
import ghidra.framework.model.DomainObjectChangedEvent;
import ghidra.framework.model.DomainObjectClosedListener;
import ghidra.framework.model.DomainObjectListener;
import ghidra.framework.plugintool.PluginEvent;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;

/** Tracks Ghidra program changes and emits MCP resource update notifications. */
final class GhidraResourceUpdateTracker
    implements DomainObjectListener, DomainObjectClosedListener {

  private static final long NOTIFICATION_DEBOUNCE_MS = 250L;
  private static final String PROGRAM_LIST_KEY = "__program_list__";

  private final Map<Long, Program> trackedPrograms = new ConcurrentHashMap<>();
  private final Map<Long, String> trackedProgramNames = new ConcurrentHashMap<>();
  private final Map<String, ScheduledFuture<?>> pendingNotifications = new ConcurrentHashMap<>();
  private final ScheduledExecutorService notificationExecutor =
      Executors.newSingleThreadScheduledExecutor(new TrackerThreadFactory());

  void start() {
    try {
      for (DomainFile domainFile : GhidraStateUtils.getActiveProject().getOpenData()) {
        try {
          DomainObject domainObject = domainFile.getDomainObject(this, true, false, null);
          if (domainObject instanceof Program program) {
            trackProgram(program, true);
          } else if (domainObject != null) {
            domainObject.release(this);
          }
        } catch (Exception e) {
          Msg.warn(this, "Failed to start tracking open program: " + domainFile.getName(), e);
        }
      }
    } catch (Exception e) {
      Msg.warn(this, "Failed to enumerate open programs for MCP resource tracking", e);
    }
  }

  void stop() {
    List<Program> programs = new ArrayList<>(trackedPrograms.values());
    for (Program program : programs) {
      untrackProgram(program, true);
    }

    for (ScheduledFuture<?> future : pendingNotifications.values()) {
      future.cancel(false);
    }
    pendingNotifications.clear();
    notificationExecutor.shutdownNow();
  }

  void processEvent(PluginEvent event) {
    if (event instanceof ProgramOpenedPluginEvent openedEvent) {
      Program program = openedEvent.getProgram();
      if (program != null) {
        trackProgram(program, false);
        scheduleProgramListUpdate();
      }
      return;
    }

    if (event instanceof ProgramActivatedPluginEvent activatedEvent) {
      Program program = activatedEvent.getActiveProgram();
      if (program != null) {
        trackProgram(program, false);
      }
      return;
    }

    if (event instanceof ProgramClosedPluginEvent closedEvent) {
      Program program = closedEvent.getProgram();
      if (program != null) {
        untrackProgram(program, true);
        scheduleProgramListUpdate();
      }
    }
  }

  @Override
  public void domainObjectChanged(DomainObjectChangedEvent event) {
    if (!(event.getSource() instanceof Program program)) {
      return;
    }

    long programId = getProgramId(program);
    String currentName = program.getName();
    String previousName = trackedProgramNames.put(programId, currentName);

    if (previousName != null && !previousName.equals(currentName)) {
      GhidraMcpServer.renameTrackedResourceProgram(previousName, currentName);
      scheduleProgramUpdate(previousName);
      scheduleProgramListUpdate();
    }

    scheduleProgramUpdate(currentName);
  }

  @Override
  public void domainObjectClosed(DomainObject domainObject) {
    if (domainObject instanceof Program program) {
      untrackProgram(program, false);
      scheduleProgramListUpdate();
    }
  }

  private void trackProgram(Program program, boolean alreadyOwnedConsumer) {
    long programId = getProgramId(program);
    if (trackedPrograms.containsKey(programId)) {
      trackedProgramNames.put(programId, program.getName());
      return;
    }

    try {
      if (!alreadyOwnedConsumer && !program.isUsedBy(this) && !program.addConsumer(this)) {
        Msg.warn(this, "Failed to add MCP tracker as consumer for program: " + program.getName());
        return;
      }

      program.addListener(this);
      program.addCloseListener(this);
      trackedPrograms.put(programId, program);
      trackedProgramNames.put(programId, program.getName());
    } catch (Exception e) {
      Msg.warn(this, "Failed to track program for MCP resource updates: " + program.getName(), e);
      safeRelease(program);
    }
  }

  private void untrackProgram(Program program, boolean releaseConsumer) {
    long programId = getProgramId(program);
    trackedPrograms.remove(programId);
    trackedProgramNames.remove(programId);

    try {
      if (!program.isClosed()) {
        program.removeListener(this);
        program.removeCloseListener(this);
      }
    } catch (Exception e) {
      Msg.debug(this, "Ignoring failure while removing MCP program listeners", e);
    }

    if (releaseConsumer) {
      safeRelease(program);
    }
  }

  private void safeRelease(Program program) {
    try {
      if (!program.isClosed() && program.isUsedBy(this)) {
        program.release(this);
      }
    } catch (Exception e) {
      Msg.debug(this, "Ignoring failure while releasing tracked program consumer", e);
    }
  }

  private void scheduleProgramListUpdate() {
    scheduleNotification(PROGRAM_LIST_KEY, GhidraMcpServer::notifyProgramsResourceUpdated);
  }

  private void scheduleProgramUpdate(String programName) {
    if (programName == null || programName.isBlank()) {
      return;
    }
    scheduleNotification(
        programName, () -> GhidraMcpServer.notifyProgramResourcesUpdated(programName));
  }

  private void scheduleNotification(String key, Runnable task) {
    ScheduledFuture<?> previous = pendingNotifications.remove(key);
    if (previous != null) {
      previous.cancel(false);
    }

    ScheduledFuture<?> next =
        notificationExecutor.schedule(
            () -> {
              pendingNotifications.remove(key);
              task.run();
            },
            NOTIFICATION_DEBOUNCE_MS,
            TimeUnit.MILLISECONDS);
    pendingNotifications.put(key, next);
  }

  private long getProgramId(Program program) {
    return program.getUniqueProgramID();
  }

  private static final class TrackerThreadFactory implements ThreadFactory {
    @Override
    public Thread newThread(Runnable runnable) {
      Thread thread = new Thread(runnable, "ghidra-mcp-resource-updates");
      thread.setDaemon(true);
      return thread;
    }
  }
}
