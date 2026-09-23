package com.themixednuts.tools;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;

import ghidra.program.model.listing.Program;
import org.junit.jupiter.api.Test;

class DecompilationSnapshotsTest {

  @Test
  void evictsTheLeastRecentlyUsedSnapshotAndRejectsOtherPrograms() {
    Program program = mock(Program.class);
    Program otherProgram = mock(Program.class);
    DecompilationSnapshots snapshots = new DecompilationSnapshots();
    String first = snapshots.put(program, "first", "0x1000", "code", 4, null, null).id();
    String second = snapshots.put(program, "second", "0x1001", "code", 4, null, null).id();
    assertNotNull(snapshots.get(first, program));
    assertNull(snapshots.get(first, otherProgram));

    for (int index = 2; index <= DecompilationSnapshots.MAX_ENTRIES; index++) {
      snapshots.put(program, "name" + index, "0x" + index, "code", 4, null, null);
    }
    assertNotNull(snapshots.get(first, program));
    assertNull(snapshots.get(second, program));
  }

  @Test
  void oversizeSourceStillReturnsTheCompletedCodeWithoutCachingIt() {
    Program program = mock(Program.class);
    DecompilationSnapshots.Snapshot snapshot =
        new DecompilationSnapshots()
            .put(
                program,
                "large",
                "0x1000",
                "x".repeat(DecompilationSnapshots.MAX_SOURCE_CHARS + 1),
                1,
                null,
                null);
    assertNull(snapshot.id());
    assertEquals(DecompilationSnapshots.MAX_SOURCE_CHARS + 1, snapshot.code().length());
  }
}
