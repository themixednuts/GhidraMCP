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
        ToolOutputStore.readOutput(sessionId, ref.outputId(), null, "auto", 0, 5);

    // OutputChunk only carries content + nextOffset on the wire. Per-output metadata
    // (sessionId, outputId, view, contentFormat, view_total_chars) is exposed via
    // StoredOutputRef and list_outputs instead.
    assertEquals("abcde", chunk.content());
    assertEquals(5, chunk.nextOffset());
    assertEquals(26, ref.viewTotalChars().get(ToolOutputStore.VIEW_JSON));
    assertEquals(26, ref.viewTotalChars().get(ToolOutputStore.VIEW_ENVELOPE_JSON));
  }

  @Test
  void shouldReadOutputByFileName() throws Exception {
    String sessionId = "ses_test_" + UUID.randomUUID().toString().replace("-", "");
    ToolOutputStore.StoredOutputRef ref =
        ToolOutputStore.store(sessionId, "unit_test_tool", "execute", "0123456789");

    ToolOutputStore.OutputChunk chunk =
        ToolOutputStore.readOutput(sessionId, null, ref.fileName(), "auto", 3, 4);

    assertEquals("3456", chunk.content());
    assertEquals(7, chunk.nextOffset());
  }

  @Test
  void shouldPreferTextViewWhenAvailable() throws Exception {
    String sessionId = "ses_test_" + UUID.randomUUID().toString().replace("-", "");
    ToolOutputStore.StoredOutputRef ref =
        ToolOutputStore.store(
            sessionId,
            "unit_test_tool",
            "execute",
            ToolOutputStore.StoredOutputViews.withEnvelope(
                "{\"kind\":\"payload\"}",
                "{\"success\":true,\"data\":{\"kind\":\"payload\"}}",
                "plain text payload"));

    assertEquals(ToolOutputStore.VIEW_TEXT, ref.preferredView());
    assertEquals(3, ref.availableViews().size());
    assertEquals(18, ref.viewTotalChars().get(ToolOutputStore.VIEW_TEXT));

    // Each view returns only its content (the chunk record is just content + nextOffset).
    // What 'auto' resolves to and what content-format each view uses is metadata of the
    // StoredOutputRef, not of every chunk.
    ToolOutputStore.OutputChunk autoChunk =
        ToolOutputStore.readOutput(sessionId, ref.outputId(), null, "auto", 0, 100);
    assertEquals("plain text payload", autoChunk.content());

    ToolOutputStore.OutputChunk jsonChunk =
        ToolOutputStore.readOutput(sessionId, ref.outputId(), null, "json", 0, 100);
    assertEquals("{\"kind\":\"payload\"}", jsonChunk.content());

    ToolOutputStore.OutputChunk envelopeChunk =
        ToolOutputStore.readOutput(sessionId, ref.outputId(), null, "envelope_json", 0, 100);
    assertEquals("{\"success\":true,\"data\":{\"kind\":\"payload\"}}", envelopeChunk.content());
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
