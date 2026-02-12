package com.themixednuts.utils;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class ToolOutputStoreTest {

  @Test
  void shouldStoreAndReadOutputByOutputId() throws Exception {
    String sessionId = "ses_test_" + UUID.randomUUID().toString().replace("-", "");
    ToolOutputStore.StoredOutputRef ref =
        ToolOutputStore.store(sessionId, "unit_test_tool", "execute", "abcdefghijklmnopqrstuvwxyz");

    ToolOutputStore.OutputChunk chunk =
        ToolOutputStore.readOutput(sessionId, ref.outputId(), null, 0, 5);

    assertEquals(sessionId, chunk.sessionId());
    assertEquals(ref.outputId(), chunk.outputId());
    assertEquals("abcde", chunk.content());
    assertTrue(chunk.hasMore());
    assertEquals(5, chunk.nextOffset());
  }

  @Test
  void shouldReadOutputByFileName() throws Exception {
    String sessionId = "ses_test_" + UUID.randomUUID().toString().replace("-", "");
    ToolOutputStore.StoredOutputRef ref =
        ToolOutputStore.store(sessionId, "unit_test_tool", "execute", "0123456789");

    ToolOutputStore.OutputChunk chunk =
        ToolOutputStore.readOutput(sessionId, null, ref.fileName(), 3, 4);

    assertEquals("3456", chunk.content());
    assertTrue(chunk.hasMore());
    assertEquals(7, chunk.nextOffset());
  }

  @Test
  void shouldPaginateOutputsWithinSession() {
    String sessionId = "ses_test_" + UUID.randomUUID().toString().replace("-", "");

    ToolOutputStore.store(sessionId, "unit_test_tool", "one", "payload-1");
    ToolOutputStore.store(sessionId, "unit_test_tool", "two", "payload-2");
    ToolOutputStore.store(sessionId, "unit_test_tool", "three", "payload-3");

    PaginatedResult<ToolOutputStore.OutputInfo> firstPage =
        ToolOutputStore.listOutputs(sessionId, null, 2);

    assertEquals(2, firstPage.results.size());
    assertNotNull(firstPage.nextCursor);

    PaginatedResult<ToolOutputStore.OutputInfo> secondPage =
        ToolOutputStore.listOutputs(sessionId, firstPage.nextCursor, 2);

    assertEquals(1, secondPage.results.size());
    assertNull(secondPage.nextCursor);
  }

  @Test
  void shouldListSessions() {
    String sessionId = "ses_test_" + UUID.randomUUID().toString().replace("-", "");
    ToolOutputStore.store(sessionId, "unit_test_tool", "execute", "payload");

    PaginatedResult<ToolOutputStore.SessionInfo> sessions = ToolOutputStore.listSessions(null, 100);
    List<String> sessionIds =
        sessions.results.stream().map(ToolOutputStore.SessionInfo::sessionId).toList();

    assertTrue(sessionIds.contains(sessionId));
  }
}
