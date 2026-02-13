package com.themixednuts.utils;

import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Stores oversized tool outputs in temp files so agents can fetch them in smaller chunks.
 *
 * <p>Storage is organized by session ID and output ID. Sessions automatically expire and older
 * entries are evicted to keep disk usage bounded.
 */
public final class ToolOutputStore {

  public static final int DEFAULT_LIST_PAGE_SIZE = 25;
  public static final int MAX_LIST_PAGE_SIZE = 200;
  public static final int DEFAULT_READ_CHUNK_CHARS = 12_000;
  public static final int MAX_READ_CHUNK_CHARS = 24_000;

  private static final long SESSION_TTL_MS = Duration.ofHours(6).toMillis();
  private static final int MAX_SESSIONS = 100;
  private static final int MAX_OUTPUTS_PER_SESSION = 100;
  private static final AtomicLong OUTPUT_SEQUENCE = new AtomicLong(0);
  private static final Path ROOT_DIRECTORY =
      Paths.get(System.getProperty("java.io.tmpdir"), "ghidra-mcp-tool-output");

  private static final Object LOCK = new Object();
  private static final Map<String, SessionBucket> SESSIONS = new LinkedHashMap<>();

  /** Reference information returned when output is stored out-of-band. */
  public record StoredOutputRef(
      String sessionId,
      String outputId,
      String fileName,
      String toolName,
      String operation,
      int totalChars,
      long createdAtMs) {}

  /** Summary information for listing available output sessions. */
  public record SessionInfo(
      String sessionId, int outputCount, long createdAtMs, long lastAccessedAtMs) {}

  /** Summary information for listing outputs in a session. */
  public record OutputInfo(
      String sessionId,
      String outputId,
      String fileName,
      String toolName,
      String operation,
      int totalChars,
      long createdAtMs) {}

  /** A chunk of stored output content. */
  public record OutputChunk(
      String sessionId,
      String outputId,
      String fileName,
      String toolName,
      String operation,
      int offset,
      int requestedChars,
      int returnedChars,
      int totalChars,
      boolean hasMore,
      Integer nextOffset,
      String content) {}

  private static final class SessionBucket {
    private final String sessionId;
    private final long createdAtMs;
    private long lastAccessedAtMs;
    private final LinkedHashMap<String, OutputMetadata> outputs = new LinkedHashMap<>();

    SessionBucket(String sessionId, long createdAtMs) {
      this.sessionId = sessionId;
      this.createdAtMs = createdAtMs;
      this.lastAccessedAtMs = createdAtMs;
    }

    void touch(long now) {
      this.lastAccessedAtMs = now;
    }
  }

  private static final class OutputMetadata {
    private final String outputId;
    private final String fileName;
    private final String toolName;
    private final String operation;
    private final int totalChars;
    private final long createdAtMs;
    private final Path filePath;

    OutputMetadata(
        String outputId,
        String fileName,
        String toolName,
        String operation,
        int totalChars,
        long createdAtMs,
        Path filePath) {
      this.outputId = outputId;
      this.fileName = fileName;
      this.toolName = toolName;
      this.operation = operation;
      this.totalChars = totalChars;
      this.createdAtMs = createdAtMs;
      this.filePath = filePath;
    }
  }

  private ToolOutputStore() {
    // Utility class
  }

  /** Stores output content in the backing temp directory. */
  public static StoredOutputRef store(
      String requestedSessionId, String toolName, String operation, String content) {
    String sessionId =
        Optional.ofNullable(requestedSessionId)
            .map(String::trim)
            .filter(value -> !value.isEmpty())
            .map(value -> sanitizeSegment(value, 64))
            .orElseGet(ToolOutputStore::generateSessionId);

    long now = System.currentTimeMillis();

    ensureRootDirectory();
    Path sessionDirectory = ROOT_DIRECTORY.resolve(sessionId);
    createDirectory(sessionDirectory);

    String outputId = "out_" + Long.toString(OUTPUT_SEQUENCE.incrementAndGet(), 36);
    String safeTool = sanitizeSegment(toolName, 32);
    String safeOperation = sanitizeSegment(operation, 32);
    String fileName = safeTool + "-" + safeOperation + "-" + outputId + ".json";
    Path outputFile = sessionDirectory.resolve(fileName);

    String payload = Objects.requireNonNullElse(content, "");
    writeFile(outputFile, payload);

    OutputMetadata metadata =
        new OutputMetadata(
            outputId, fileName, toolName, operation, payload.length(), now, outputFile);

    synchronized (LOCK) {
      cleanupExpiredSessionsLocked();

      SessionBucket bucket = SESSIONS.computeIfAbsent(sessionId, id -> new SessionBucket(id, now));
      bucket.touch(now);
      bucket.outputs.put(outputId, metadata);

      while (bucket.outputs.size() > MAX_OUTPUTS_PER_SESSION) {
        removeOldestOutput(bucket);
      }

      while (SESSIONS.size() > MAX_SESSIONS) {
        removeOldestSession();
      }

      return new StoredOutputRef(
          bucket.sessionId,
          metadata.outputId,
          metadata.fileName,
          metadata.toolName,
          metadata.operation,
          metadata.totalChars,
          metadata.createdAtMs);
    }
  }

  /** Lists sessions with cursor-based pagination. */
  public static PaginatedResult<SessionInfo> listSessions(String cursor, int pageSize) {
    int effectivePageSize = normalizePageSize(pageSize, DEFAULT_LIST_PAGE_SIZE, MAX_LIST_PAGE_SIZE);
    List<SessionInfo> sessions;

    synchronized (LOCK) {
      cleanupExpiredSessionsLocked();
      sessions =
          SESSIONS.values().stream()
              .sorted(
                  Comparator.comparingLong((SessionBucket bucket) -> bucket.lastAccessedAtMs)
                      .reversed())
              .map(
                  bucket ->
                      new SessionInfo(
                          bucket.sessionId,
                          bucket.outputs.size(),
                          bucket.createdAtMs,
                          bucket.lastAccessedAtMs))
              .toList();
    }

    return paginateByCursor(sessions, cursor, effectivePageSize, SessionInfo::sessionId);
  }

  /** Lists outputs in a session with cursor-based pagination. */
  public static PaginatedResult<OutputInfo> listOutputs(
      String sessionId, String cursor, int pageSize) {
    int effectivePageSize = normalizePageSize(pageSize, DEFAULT_LIST_PAGE_SIZE, MAX_LIST_PAGE_SIZE);
    List<OutputInfo> outputs;

    synchronized (LOCK) {
      cleanupExpiredSessionsLocked();
      SessionBucket bucket = getRequiredSession(sessionId);
      bucket.touch(System.currentTimeMillis());

      outputs =
          bucket.outputs.values().stream()
              .sorted(
                  Comparator.comparingLong((OutputMetadata metadata) -> metadata.createdAtMs)
                      .reversed())
              .map(
                  metadata ->
                      new OutputInfo(
                          bucket.sessionId,
                          metadata.outputId,
                          metadata.fileName,
                          metadata.toolName,
                          metadata.operation,
                          metadata.totalChars,
                          metadata.createdAtMs))
              .toList();
    }

    return paginateByCursor(outputs, cursor, effectivePageSize, OutputInfo::outputId);
  }

  /** Reads a chunk from a stored output entry. */
  public static OutputChunk readOutput(
      String sessionId, String outputId, String fileName, int offset, int maxChars)
      throws GhidraMcpException {
    SessionBucket bucket;
    OutputMetadata metadata;

    synchronized (LOCK) {
      cleanupExpiredSessionsLocked();
      bucket = getRequiredSession(sessionId);
      bucket.touch(System.currentTimeMillis());
      metadata = resolveOutput(bucket, outputId, fileName);
    }

    int effectiveOffset = Math.max(0, offset);
    int effectiveMaxChars =
        normalizePageSize(maxChars, DEFAULT_READ_CHUNK_CHARS, MAX_READ_CHUNK_CHARS);

    String allContent;
    try {
      allContent = readFile(metadata.filePath);
    } catch (IllegalStateException e) {
      throw new GhidraMcpException(
          GhidraMcpError.notFound("tool output file", bucket.sessionId + "/" + metadata.fileName));
    }
    int totalChars = allContent.length();

    if (effectiveOffset > totalChars) {
      effectiveOffset = totalChars;
    }

    int endIndex = Math.min(totalChars, effectiveOffset + effectiveMaxChars);
    String chunk = allContent.substring(effectiveOffset, endIndex);
    boolean hasMore = endIndex < totalChars;
    Integer nextOffset = hasMore ? endIndex : null;

    return new OutputChunk(
        bucket.sessionId,
        metadata.outputId,
        metadata.fileName,
        metadata.toolName,
        metadata.operation,
        effectiveOffset,
        effectiveMaxChars,
        chunk.length(),
        totalChars,
        hasMore,
        nextOffset,
        chunk);
  }

  private static SessionBucket getRequiredSession(String sessionId) throws GhidraMcpException {
    String normalizedSessionId =
        Optional.ofNullable(sessionId)
            .map(String::trim)
            .filter(value -> !value.isEmpty())
            .orElseThrow(() -> new GhidraMcpException(GhidraMcpError.missing("session_id")));

    SessionBucket bucket = SESSIONS.get(normalizedSessionId);
    if (bucket == null) {
      throw new GhidraMcpException(
          GhidraMcpError.notFound("tool output session", normalizedSessionId));
    }
    return bucket;
  }

  private static OutputMetadata resolveOutput(
      SessionBucket bucket, String outputId, String fileName) throws GhidraMcpException {
    if (outputId == null || outputId.isBlank()) {
      if (fileName == null || fileName.isBlank()) {
        throw new GhidraMcpException(GhidraMcpError.missing("output_id or output_file_name"));
      }

      return bucket.outputs.values().stream()
          .filter(metadata -> metadata.fileName.equals(fileName))
          .findFirst()
          .orElseThrow(
              () ->
                  new GhidraMcpException(
                      GhidraMcpError.notFound(
                          "tool output file", bucket.sessionId + "/" + fileName)));
    }

    OutputMetadata metadata = bucket.outputs.get(outputId);
    if (metadata == null) {
      throw new GhidraMcpException(
          GhidraMcpError.notFound("tool output", bucket.sessionId + "/" + outputId));
    }
    return metadata;
  }

  private static void cleanupExpiredSessionsLocked() {
    long cutoff = System.currentTimeMillis() - SESSION_TTL_MS;
    List<String> expiredSessions = new ArrayList<>();

    for (Map.Entry<String, SessionBucket> entry : SESSIONS.entrySet()) {
      if (entry.getValue().lastAccessedAtMs < cutoff) {
        expiredSessions.add(entry.getKey());
      }
    }

    for (String sessionId : expiredSessions) {
      SessionBucket removed = SESSIONS.remove(sessionId);
      if (removed != null) {
        deleteDirectoryQuietly(ROOT_DIRECTORY.resolve(sessionId));
      }
    }
  }

  private static void removeOldestSession() {
    String oldestSessionId =
        SESSIONS.values().stream()
            .min(Comparator.comparingLong(bucket -> bucket.lastAccessedAtMs))
            .map(bucket -> bucket.sessionId)
            .orElse(null);

    if (oldestSessionId != null) {
      SESSIONS.remove(oldestSessionId);
      deleteDirectoryQuietly(ROOT_DIRECTORY.resolve(oldestSessionId));
    }
  }

  private static void removeOldestOutput(SessionBucket bucket) {
    if (bucket.outputs.isEmpty()) {
      return;
    }

    String oldestOutputId = bucket.outputs.keySet().iterator().next();
    OutputMetadata removed = bucket.outputs.remove(oldestOutputId);
    if (removed != null) {
      deleteFileQuietly(removed.filePath);
    }
  }

  private static <T> PaginatedResult<T> paginateByCursor(
      List<T> items, String cursor, int pageSize, java.util.function.Function<T, String> keyFn) {
    int startIndex = 0;
    boolean cursorProvided = cursor != null && !cursor.isBlank();
    boolean cursorMatched = false;

    if (cursor != null && !cursor.isBlank()) {
      for (int i = 0; i < items.size(); i++) {
        if (Objects.equals(keyFn.apply(items.get(i)), cursor)) {
          startIndex = i + 1;
          cursorMatched = true;
          break;
        }
      }
    }

    if (cursorProvided && !cursorMatched) {
      throw new GhidraMcpException(
          GhidraMcpError.invalid(
              "cursor",
              cursor,
              "cursor is invalid or expired; restart pagination without a cursor"));
    }

    if (startIndex >= items.size()) {
      return new PaginatedResult<>(List.of(), null);
    }

    int endIndex = Math.min(items.size(), startIndex + pageSize);
    List<T> page = new ArrayList<>(items.subList(startIndex, endIndex));
    String nextCursor =
        endIndex < items.size() && !page.isEmpty() ? keyFn.apply(page.get(page.size() - 1)) : null;

    return new PaginatedResult<>(page, nextCursor);
  }

  private static int normalizePageSize(int value, int defaultValue, int maxValue) {
    int effective = value <= 0 ? defaultValue : value;
    return Math.min(effective, maxValue);
  }

  private static String generateSessionId() {
    return "ses_" + UUID.randomUUID().toString().replace("-", "").substring(0, 16);
  }

  private static String sanitizeSegment(String value, int maxLength) {
    String sanitized = value == null ? "unknown" : value.replaceAll("[^a-zA-Z0-9._-]", "_");
    if (sanitized.isBlank()) {
      sanitized = "unknown";
    }
    return sanitized.substring(0, Math.min(maxLength, sanitized.length()));
  }

  private static void ensureRootDirectory() {
    createDirectory(ROOT_DIRECTORY);
  }

  private static void createDirectory(Path directory) {
    try {
      Files.createDirectories(directory);
    } catch (IOException e) {
      throw new IllegalStateException("Failed to create tool output directory: " + directory, e);
    }
  }

  private static void writeFile(Path filePath, String content) {
    try {
      Files.writeString(filePath, content, StandardCharsets.UTF_8);
    } catch (IOException e) {
      throw new IllegalStateException("Failed to write tool output file: " + filePath, e);
    }
  }

  private static String readFile(Path filePath) {
    try {
      return Files.readString(filePath, StandardCharsets.UTF_8);
    } catch (IOException e) {
      throw new IllegalStateException("Failed to read tool output file: " + filePath, e);
    }
  }

  private static void deleteDirectoryQuietly(Path directory) {
    try {
      if (!Files.exists(directory)) {
        return;
      }

      try (var stream = Files.walk(directory)) {
        stream.sorted(Comparator.reverseOrder()).forEach(ToolOutputStore::deleteFileQuietly);
      }
    } catch (IOException ignored) {
      // Best effort cleanup
    }
  }

  private static void deleteFileQuietly(Path path) {
    try {
      Files.deleteIfExists(path);
    } catch (IOException ignored) {
      // Best effort cleanup
    }
  }
}
