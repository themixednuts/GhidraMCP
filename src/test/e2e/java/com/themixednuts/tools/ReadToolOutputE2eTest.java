package com.themixednuts.tools;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.models.FunctionInfo;
import com.themixednuts.models.McpResponse;
import com.themixednuts.models.SymbolInfo;
import com.themixednuts.utils.JsonMapperHolder;
import com.themixednuts.utils.PaginatedResult;
import com.themixednuts.utils.ToolOutputStore;
import ghidra.program.model.listing.Program;
import java.nio.file.Paths;
import java.util.Map;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/**
 * End-to-end tests for ReadToolOutputTool verifying that output produced by other tools can be
 * stored and faithfully retrieved through the chunked read workflow.
 */
class ReadToolOutputE2eTest {

  private static final ObjectMapper mapper = JsonMapperHolder.getMapper();

  private ReadToolOutputTool readOutputTool;

  @BeforeAll
  static void initRuntime() {
    assumeTrue(
        Boolean.getBoolean("e2e.integration"), "Set -De2e.integration=true to run e2e tests");
    GhidraE2eRuntimeSupport.ensureGhidraRuntimeInitialized(Paths.get("").toAbsolutePath());
  }

  @BeforeEach
  void setUp() {
    readOutputTool = new ReadToolOutputTool();
  }

  // ---------------------------------------------------------------------------
  // FunctionsTool output → store → read payload back → assert exact match
  // ---------------------------------------------------------------------------

  @Test
  void readFunctionsOutput_storedAndRetrievedFaithfully() throws Exception {
    InMemoryProgramFixtureSupport.ProgramFixture fixture =
        InMemoryProgramFixtureSupport.createReadAndManageFixtureProgram();
    try {
      FunctionsTool funcTool = new InMemoryFunctionsTool(fixture.program());

      // Execute the real tool to get a real paginated result
      Object rawResult =
          funcTool
              .execute(
                  null, Map.of("file_name", "fixture", "action", "list", "page_size", 10), null)
              .block();
      @SuppressWarnings("unchecked")
      PaginatedResult<FunctionInfo> funcResult = assertInstanceOf(PaginatedResult.class, rawResult);
      assertFalse(funcResult.results.isEmpty(), "Fixture should have functions");

      // Build payload + envelope exactly as executeWithEnvelope would
      String payloadJson = mapper.writeValueAsString(funcResult.results);
      McpResponse<?> envelope =
          McpResponse.paginated(
              "functions", "execute", funcResult.results, funcResult.nextCursor, null, 42L);
      String envelopeJson = mapper.writeValueAsString(envelope);

      // Store it (simulating the oversized-output path)
      String sessionId = "ses_e2e_func_output";
      ToolOutputStore.StoredOutputRef ref =
          ToolOutputStore.store(
              sessionId,
              "functions",
              "execute",
              ToolOutputStore.StoredOutputViews.withEnvelope(payloadJson, envelopeJson, null));
      assertEquals(payloadJson.length(), ref.viewTotalChars().get(ToolOutputStore.VIEW_JSON));

      // Use ReadToolOutputTool to read the actual payload back
      Object chunkRaw =
          readOutputTool
              .execute(
                  null,
                  Map.of("action", "read", "session_id", sessionId, "output_id", ref.outputId()),
                  null)
              .block();
      ToolOutputStore.OutputChunk chunk =
          assertInstanceOf(ToolOutputStore.OutputChunk.class, chunkRaw);

      // Assert exact JSON payload match. View / content-format / total-size metadata is on
      // StoredOutputRef now; the chunk record itself is just content + nextOffset.
      assertEquals(payloadJson, chunk.content(), "Stored and retrieved JSON must be identical");
      assertNull(chunk.nextOffset(), "Full content should fit in one chunk");
      assertEquals(ToolOutputStore.VIEW_JSON, ref.preferredView());
      assertEquals(payloadJson.length(), ref.viewTotalChars().get(ToolOutputStore.VIEW_JSON));

      // Parse retrieved JSON payload and verify structure
      JsonNode retrieved = mapper.readTree(chunk.content());
      assertTrue(retrieved.isArray());
      assertEquals(funcResult.results.size(), retrieved.size());

      // Verify each function entry has expected fields
      for (int i = 0; i < funcResult.results.size(); i++) {
        FunctionInfo expected = funcResult.results.get(i);
        JsonNode actual = retrieved.get(i);
        assertEquals(expected.getName(), actual.get("name").asText());
        assertEquals(expected.getEntryPoint(), actual.get("entry_point").asText());
      }

      Object envelopeChunkRaw =
          readOutputTool
              .execute(
                  null,
                  Map.of(
                      "action",
                      "read",
                      "session_id",
                      sessionId,
                      "output_id",
                      ref.outputId(),
                      "view",
                      ToolOutputStore.VIEW_ENVELOPE_JSON),
                  null)
              .block();
      ToolOutputStore.OutputChunk envelopeChunk =
          assertInstanceOf(ToolOutputStore.OutputChunk.class, envelopeChunkRaw);
      assertEquals(envelopeJson, envelopeChunk.content());
      assertTrue(ref.availableViews().contains(ToolOutputStore.VIEW_ENVELOPE_JSON));
    } finally {
      fixture.close();
    }
  }

  // ---------------------------------------------------------------------------
  // SymbolsTool output → store → chunked read → reassemble → assert match
  // ---------------------------------------------------------------------------

  @Test
  void readSymbolsOutput_chunkedRetrievalReassemblesCorrectly() throws Exception {
    InMemoryProgramFixtureSupport.ProgramFixture fixture =
        InMemoryProgramFixtureSupport.createReadAndManageFixtureProgram();
    try {
      SymbolsTool symbolTool = new InMemorySymbolsTool(fixture.program());

      // Execute real tool
      Object rawResult =
          symbolTool
              .execute(
                  null,
                  Map.of(
                      "file_name",
                      "fixture",
                      "action",
                      "list",
                      "name_pattern",
                      "entry_.*",
                      "page_size",
                      10),
                  null)
              .block();
      @SuppressWarnings("unchecked")
      PaginatedResult<SymbolInfo> symbolResult = assertInstanceOf(PaginatedResult.class, rawResult);
      assertFalse(symbolResult.results.isEmpty());

      // Build payload + envelope
      String payloadJson = mapper.writeValueAsString(symbolResult.results);
      McpResponse<?> envelope =
          McpResponse.paginated(
              "symbols", "execute", symbolResult.results, symbolResult.nextCursor, null, 7L);
      String envelopeJson = mapper.writeValueAsString(envelope);

      // Store
      String sessionId = "ses_e2e_symbol_output";
      ToolOutputStore.StoredOutputRef ref =
          ToolOutputStore.store(
              sessionId,
              "symbols",
              "execute",
              ToolOutputStore.StoredOutputViews.withEnvelope(payloadJson, envelopeJson, null));

      // Read back in small chunks to exercise pagination
      int chunkSize = Math.max(50, payloadJson.length() / 3);
      StringBuilder reassembled = new StringBuilder();
      int offset = 0;

      while (true) {
        Object chunkRaw =
            readOutputTool
                .execute(
                    null,
                    Map.of(
                        "action", "read",
                        "session_id", sessionId,
                        "output_id", ref.outputId(),
                        "offset", offset,
                        "max_chars", chunkSize),
                    null)
                .block();
        ToolOutputStore.OutputChunk chunk =
            assertInstanceOf(ToolOutputStore.OutputChunk.class, chunkRaw);
        reassembled.append(chunk.content());

        if (chunk.nextOffset() == null) {
          break;
        }
        offset = chunk.nextOffset();
      }
      assertEquals(payloadJson.length(), ref.viewTotalChars().get(ToolOutputStore.VIEW_JSON));

      // Verify reassembled content is byte-identical to original
      assertEquals(payloadJson, reassembled.toString());

      // Parse and verify symbol data integrity
      JsonNode retrieved = mapper.readTree(reassembled.toString());
      assertTrue(retrieved.isArray());
      assertEquals(symbolResult.results.size(), retrieved.size());

      for (int i = 0; i < symbolResult.results.size(); i++) {
        SymbolInfo expected = symbolResult.results.get(i);
        JsonNode actual = retrieved.get(i);
        assertEquals(expected.getName(), actual.get("name").asText());
        assertEquals(expected.getAddress(), actual.get("address").asText());
      }
    } finally {
      fixture.close();
    }
  }

  // ---------------------------------------------------------------------------
  // list_sessions + list_outputs → verify metadata from stored tool output
  // ---------------------------------------------------------------------------

  @Test
  void listSessionsAndOutputs_reflectsStoredToolMetadata() throws Exception {
    InMemoryProgramFixtureSupport.ProgramFixture fixture =
        InMemoryProgramFixtureSupport.createReadAndManageFixtureProgram();
    try {
      FunctionsTool funcTool = new InMemoryFunctionsTool(fixture.program());

      Object rawResult =
          funcTool
              .execute(
                  null, Map.of("file_name", "fixture", "action", "list", "page_size", 10), null)
              .block();
      @SuppressWarnings("unchecked")
      PaginatedResult<FunctionInfo> funcResult = assertInstanceOf(PaginatedResult.class, rawResult);

      String payloadJson = mapper.writeValueAsString(funcResult.results);
      McpResponse<?> envelope =
          McpResponse.success("functions", "execute", funcResult.results, 15L);
      String envelopeJson = mapper.writeValueAsString(envelope);

      String sessionId = "ses_e2e_metadata";
      ToolOutputStore.StoredOutputRef ref =
          ToolOutputStore.store(
              sessionId,
              "functions",
              "execute",
              ToolOutputStore.StoredOutputViews.withEnvelope(payloadJson, envelopeJson, null));

      // list_sessions — find our session
      Object sessionsRaw =
          readOutputTool.execute(null, Map.of("action", "list_sessions"), null).block();
      @SuppressWarnings("unchecked")
      PaginatedResult<ToolOutputStore.SessionInfo> sessions =
          assertInstanceOf(PaginatedResult.class, sessionsRaw);
      ToolOutputStore.SessionInfo ourSession =
          sessions.results.stream()
              .filter(s -> s.sessionId().equals(sessionId))
              .findFirst()
              .orElseThrow(() -> new AssertionError("Session not found: " + sessionId));
      assertTrue(ourSession.outputCount() >= 1);

      // list_outputs — verify tool name and operation are preserved
      Object outputsRaw =
          readOutputTool
              .execute(null, Map.of("action", "list_outputs", "session_id", sessionId), null)
              .block();
      @SuppressWarnings("unchecked")
      PaginatedResult<ToolOutputStore.OutputInfo> outputs =
          assertInstanceOf(PaginatedResult.class, outputsRaw);
      ToolOutputStore.OutputInfo ourOutput =
          outputs.results.stream()
              .filter(o -> o.outputId().equals(ref.outputId()))
              .findFirst()
              .orElseThrow(() -> new AssertionError("Output not found: " + ref.outputId()));

      assertEquals("functions", ourOutput.toolName());
      assertEquals("execute", ourOutput.operation());
      assertEquals(ToolOutputStore.VIEW_JSON, ourOutput.preferredView());
      assertEquals(payloadJson.length(), ourOutput.viewTotalChars().get(ToolOutputStore.VIEW_JSON));
      assertEquals(
          envelopeJson.length(),
          ourOutput.viewTotalChars().get(ToolOutputStore.VIEW_ENVELOPE_JSON));
      assertEquals(ref.fileName(), ourOutput.fileName());

      // read by file name — alternative lookup path
      Object byNameRaw =
          readOutputTool
              .execute(
                  null,
                  Map.of(
                      "action",
                      "read",
                      "session_id",
                      sessionId,
                      "output_file_name",
                      ref.fileName()),
                  null)
              .block();
      ToolOutputStore.OutputChunk byName =
          assertInstanceOf(ToolOutputStore.OutputChunk.class, byNameRaw);
      assertEquals(payloadJson, byName.content());
    } finally {
      fixture.close();
    }
  }

  @Test
  void readOutputPrefersStoredPlainTextViewWhenAvailable() throws Exception {
    String sessionId = "ses_e2e_text_pref";
    ToolOutputStore.StoredOutputRef ref =
        ToolOutputStore.store(
            sessionId,
            "inspect",
            "decompile",
            ToolOutputStore.StoredOutputViews.withEnvelope(
                "{\"decompiled_code\":\"int main(){}\"}",
                "{\"success\":true,\"data\":{\"decompiled_code\":\"int main(){}\"}}",
                "int main(){}"));

    Object chunkRaw =
        readOutputTool
            .execute(
                null,
                Map.of("action", "read", "session_id", sessionId, "output_id", ref.outputId()),
                null)
            .block();
    ToolOutputStore.OutputChunk chunk =
        assertInstanceOf(ToolOutputStore.OutputChunk.class, chunkRaw);

    // Auto-view selects the agent-friendly text rendering when one was stored. The chunk record
    // itself is content + nextOffset; the resolved view is on StoredOutputRef / list_outputs.
    assertEquals(ToolOutputStore.VIEW_TEXT, ref.preferredView());
    assertEquals("int main(){}", chunk.content());

    Object jsonChunkRaw =
        readOutputTool
            .execute(
                null,
                Map.of(
                    "action",
                    "read",
                    "session_id",
                    sessionId,
                    "output_id",
                    ref.outputId(),
                    "view",
                    ToolOutputStore.VIEW_JSON),
                null)
            .block();
    ToolOutputStore.OutputChunk jsonChunk =
        assertInstanceOf(ToolOutputStore.OutputChunk.class, jsonChunkRaw);
    assertEquals("{\"decompiled_code\":\"int main(){}\"}", jsonChunk.content());
  }

  // ---------------------------------------------------------------------------
  // In-memory tool stubs
  // ---------------------------------------------------------------------------

  private static final class InMemoryFunctionsTool extends FunctionsTool {
    private final Program program;

    InMemoryFunctionsTool(Program program) {
      this.program = program;
    }

    @Override
    protected Mono<Program> getProgram(
        Map<String, Object> args, ghidra.framework.plugintool.PluginTool tool) {
      return Mono.just(program);
    }
  }

  @GhidraMcpTool(
      name = "Symbols Test",
      description = "In-memory symbols test wrapper",
      mcpName = "symbols",
      mcpDescription = "In-memory wrapper for symbols")
  private static final class InMemorySymbolsTool extends SymbolsTool {
    private final Program program;

    InMemorySymbolsTool(Program program) {
      this.program = program;
    }

    @Override
    protected Mono<Program> getProgram(
        Map<String, Object> args, ghidra.framework.plugintool.PluginTool tool) {
      return Mono.just(program);
    }
  }
}
