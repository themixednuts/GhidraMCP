package com.themixednuts.tools;

import ghidra.program.model.listing.Program;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/** Bounded, immutable decompilation results for explicit follow-up reads. */
final class DecompilationSnapshots {
  static final int MAX_ENTRIES = 32;
  static final int MAX_SOURCE_CHARS = 16_000_000;
  private static final long LIFETIME_NANOS = Duration.ofMinutes(20).toNanos();

  record Snapshot(
      String id,
      Program program,
      String targetName,
      String entryAddress,
      String code,
      int bodySize,
      Integer basicBlockCount,
      List<Map<String, Object>> pcodeOperations,
      long expiresAtNanos) {}

  private final LinkedHashMap<String, Snapshot> entries = new LinkedHashMap<>(16, 0.75f, true);
  private int sourceChars;

  synchronized Snapshot put(
      Program program,
      String targetName,
      String entryAddress,
      String code,
      int bodySize,
      Integer basicBlockCount,
      List<Map<String, Object>> pcodeOperations) {
    long now = System.nanoTime();
    purgeExpired(now);
    if (code.length() > MAX_SOURCE_CHARS) {
      return new Snapshot(
          null,
          program,
          targetName,
          entryAddress,
          code,
          bodySize,
          basicBlockCount,
          pcodeOperations,
          now);
    }
    while (!entries.isEmpty()
        && (entries.size() >= MAX_ENTRIES || sourceChars + code.length() > MAX_SOURCE_CHARS)) {
      removeEldest();
    }
    Snapshot snapshot =
        new Snapshot(
            UUID.randomUUID().toString(),
            program,
            targetName,
            entryAddress,
            code,
            bodySize,
            basicBlockCount,
            pcodeOperations == null ? null : List.copyOf(pcodeOperations),
            now + LIFETIME_NANOS);
    entries.put(snapshot.id(), snapshot);
    sourceChars += code.length();
    return snapshot;
  }

  synchronized Snapshot get(String id, Program program) {
    purgeExpired(System.nanoTime());
    Snapshot snapshot = entries.get(id);
    return snapshot != null && snapshot.program() == program ? snapshot : null;
  }

  private void purgeExpired(long now) {
    var iterator = entries.values().iterator();
    while (iterator.hasNext()) {
      Snapshot snapshot = iterator.next();
      if (now - snapshot.expiresAtNanos() >= 0 || snapshot.program().isClosed()) {
        sourceChars -= snapshot.code().length();
        iterator.remove();
      }
    }
  }

  private void removeEldest() {
    var iterator = entries.values().iterator();
    Snapshot snapshot = iterator.next();
    sourceChars -= snapshot.code().length();
    iterator.remove();
  }
}
