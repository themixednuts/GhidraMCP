package com.themixednuts.tools.versiontracking;

import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.tools.BaseMcpTool;
import ghidra.feature.vt.api.db.VTSessionDB;
import ghidra.feature.vt.api.main.VTSession;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainObject;
import ghidra.framework.model.Project;
import ghidra.util.task.TaskMonitor;
import java.util.Map;
import java.util.Optional;

/**
 * Base class for Version Tracking tools. Provides shared methods for opening VT sessions, accessing
 * the active project, and parsing optional double arguments.
 *
 * <p>Subclasses can override {@link #openVTSession(String)} and {@link #getActiveProject()} for
 * testing purposes (e.g., injecting an in-memory VTSessionDB).
 */
public abstract class BaseVTTool extends BaseMcpTool {

  @FunctionalInterface
  protected interface VTSessionCallback<T> {
    T execute(VTSession session) throws GhidraMcpException;
  }

  @FunctionalInterface
  protected interface VTTransactionCallback<T> {
    T execute() throws Exception;
  }

  public static final String ARG_SESSION_NAME = "session_name";

  /**
   * Opens a VT session by name from the active project.
   *
   * @param sessionName the name or path of the VT session file
   * @return the opened VTSession
   * @throws GhidraMcpException if the session cannot be found or opened
   */
  protected VTSession openVTSession(String sessionName) throws GhidraMcpException {
    return openVTSession(sessionName, true);
  }

  protected VTSession openVTSession(String sessionName, boolean forUpdate)
      throws GhidraMcpException {
    Project project = getActiveProject();
    DomainFile sessionFile =
        VTDomainFileResolver.resolveSessionFile(project, sessionName, ARG_SESSION_NAME);

    try {
      DomainObject obj = sessionFile.getDomainObject(this, forUpdate, false, TaskMonitor.DUMMY);
      if (obj instanceof VTSession) {
        return (VTSession) obj;
      }
      if (obj != null) {
        obj.release(this);
      }
      throw new GhidraMcpException(
          GhidraMcpError.validation()
              .errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
              .message("File '" + sessionName + "' is not a VT session")
              .build());
    } catch (GhidraMcpException e) {
      throw e;
    } catch (Exception e) {
      throw new GhidraMcpException(
          GhidraMcpError.execution()
              .errorCode(GhidraMcpError.ErrorCode.UNEXPECTED_ERROR)
              .message("Failed to open VT session '" + sessionName + "': " + e.getMessage())
              .build());
    }
  }

  /**
   * Retrieves an optional double argument from the provided map.
   *
   * @param args the arguments map
   * @param argumentName the name of the argument to retrieve
   * @return an Optional containing the double value if present and parseable
   */
  protected Optional<Double> getOptionalDoubleArgument(
      Map<String, Object> args, String argumentName) {
    return Optional.ofNullable(args.get(argumentName))
        .flatMap(
            value -> {
              if (value instanceof Number) {
                return Optional.of(((Number) value).doubleValue());
              } else if (value instanceof String) {
                try {
                  return Optional.of(Double.parseDouble((String) value));
                } catch (NumberFormatException e) {
                  return Optional.empty();
                }
              }
              return Optional.empty();
            });
  }

  protected <T> T withSession(String sessionName, VTSessionCallback<T> callback)
      throws GhidraMcpException {
    return withSession(sessionName, true, callback);
  }

  protected <T> T withSession(String sessionName, boolean forUpdate, VTSessionCallback<T> callback)
      throws GhidraMcpException {
    VTSession session = openVTSession(sessionName, forUpdate);
    try {
      return callback.execute(session);
    } finally {
      // Save before release — must happen after all transactions are closed
      if (forUpdate && session.canSave()) {
        try {
          session.save("MCP", ghidra.util.task.TaskMonitor.DUMMY);
        } catch (Exception e) {
          ghidra.util.Msg.warn(this, "Failed to save VT session: " + e.getMessage());
        }
      }
      releaseSessionQuietly(session);
    }
  }

  protected Optional<Double> getOptionalDoubleArgumentStrict(
      Map<String, Object> args, String argumentName) throws GhidraMcpException {
    if (!args.containsKey(argumentName)) {
      return Optional.empty();
    }

    Object rawValue = args.get(argumentName);
    if (rawValue == null) {
      return Optional.empty();
    }

    double value;
    if (rawValue instanceof Number numberValue) {
      value = numberValue.doubleValue();
    } else if (rawValue instanceof String stringValue) {
      String trimmed = stringValue.trim();
      if (trimmed.isEmpty()) {
        throw new GhidraMcpException(
            GhidraMcpError.invalid(argumentName, rawValue, "must be a valid number"));
      }

      try {
        value = Double.parseDouble(trimmed);
      } catch (NumberFormatException e) {
        throw new GhidraMcpException(
            GhidraMcpError.invalid(argumentName, rawValue, "must be a valid number"));
      }
    } else {
      throw new GhidraMcpException(
          GhidraMcpError.invalid(argumentName, rawValue, "must be a valid number"));
    }

    if (!Double.isFinite(value)) {
      throw new GhidraMcpException(
          GhidraMcpError.invalid(argumentName, rawValue, "must be a finite number"));
    }

    return Optional.of(value);
  }

  protected Optional<Double> getOptionalBoundedDoubleArgument(
      Map<String, Object> args, String argumentName, Double minInclusive, Double maxInclusive)
      throws GhidraMcpException {
    Optional<Double> valueOpt = getOptionalDoubleArgumentStrict(args, argumentName);
    if (valueOpt.isEmpty()) {
      return Optional.empty();
    }

    double value = valueOpt.get();
    if (minInclusive != null && value < minInclusive) {
      throw new GhidraMcpException(
          GhidraMcpError.invalid(argumentName, value, "must be >= " + minInclusive));
    }
    if (maxInclusive != null && value > maxInclusive) {
      throw new GhidraMcpException(
          GhidraMcpError.invalid(argumentName, value, "must be <= " + maxInclusive));
    }

    return valueOpt;
  }

  protected VTSessionDB requireSessionDb(VTSession session) throws GhidraMcpException {
    if (session instanceof VTSessionDB sessionDb) {
      return sessionDb;
    }

    throw new GhidraMcpException(
        GhidraMcpError.execution()
            .errorCode(GhidraMcpError.ErrorCode.UNEXPECTED_ERROR)
            .message("Session is not a VTSessionDB instance")
            .build());
  }

  protected <T> T inSessionTransaction(
      VTSession session,
      String transactionName,
      String failureMessagePrefix,
      VTTransactionCallback<T> callback)
      throws GhidraMcpException {
    VTSessionDB sessionDb = requireSessionDb(session);
    int txId = sessionDb.startTransaction(transactionName);
    boolean commit = false;

    try {
      T result = callback.execute();
      commit = true;
      return result;
    } catch (GhidraMcpException e) {
      throw e;
    } catch (Exception e) {
      Throwable cause = e.getCause() != null ? e.getCause() : e;
      throw new GhidraMcpException(
          GhidraMcpError.execution()
              .errorCode(GhidraMcpError.ErrorCode.UNEXPECTED_ERROR)
              .message(failureMessagePrefix + cause.getMessage())
              .build());
    } finally {
      sessionDb.endTransaction(txId, commit);
    }
  }

  protected void releaseSessionQuietly(VTSession session) {
    if (session == null) {
      return;
    }
    try {
      session.release(this);
    } catch (Exception ignored) {
    }
  }
}
