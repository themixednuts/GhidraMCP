package com.themixednuts.tools;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.themixednuts.models.FunctionInfo;
import com.themixednuts.utils.JsonMapperHolder;
import com.themixednuts.models.McpResponse;
import com.themixednuts.models.SymbolInfo;
import com.themixednuts.utils.PaginatedResult;
import com.themixednuts.utils.ToolOutputStore;
import ghidra.program.model.listing.Program;
import java.nio.file.Paths;
import java.util.Map;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;

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
  // ReadFunctionsTool output → store → read back → assert exact match
  // ---------------------------------------------------------------------------

  @Test
  void readFunctionsOutput_storedAndRetrievedFaithfully() throws Exception {
    InMemoryProgramFixtureSupport.ProgramFixture fixture =
        InMemoryProgramFixtureSupport.createReadAndManageFixtureProgram();
    try {
      ReadFunctionsTool funcTool = new InMemoryReadFunctionsTool(fixture.program());

      // Execute the real tool to get a real paginated result
      Object rawResult =
          funcTool.execute(null, Map.of("file_name", "fixture", "page_size", 10), null).block();
      @SuppressWarnings("unchecked")
      PaginatedResult<FunctionInfo> funcResult =
          assertInstanceOf(PaginatedResult.class, rawResult);
      assertFalse(funcResult.results.isEmpty(), "Fixture should have functions");

      // Wrap in McpResponse exactly as executeWithEnvelope does for PaginatedResult
      McpResponse<?> envelope =
          McpResponse.paginated(
              "read_functions",
              "execute",
              funcResult.results,
              funcResult.nextCursor,
              null,
              42L);
      String originalJson = mapper.writeValueAsString(envelope);

      // Store it (simulating the oversized-output path)
      String sessionId = "ses_e2e_func_output";
      ToolOutputStore.StoredOutputRef ref =
          ToolOutputStore.store(sessionId, "read_functions", "execute", originalJson);
      assertEquals(originalJson.length(), ref.totalChars());

      // Use ReadToolOutputTool to read it back
      Object chunkRaw =
          readOutputTool
              .execute(
                  null,
                  Map.of(
                      "action", "read",
                      "session_id", sessionId,
                      "output_id", ref.outputId()),
                  null)
              .block();
      ToolOutputStore.OutputChunk chunk =
          assertInstanceOf(ToolOutputStore.OutputChunk.class, chunkRaw);

      // Assert exact JSON match
      assertEquals(originalJson, chunk.content(), "Stored and retrieved JSON must be identical");
      assertFalse(chunk.hasMore(), "Full content should fit in one chunk");
      assertEquals(originalJson.length(), chunk.totalChars());

      // Parse retrieved JSON and verify structure
      JsonNode retrieved = mapper.readTree(chunk.content());
      assertTrue(retrieved.get("success").asBoolean());
      assertNotNull(retrieved.get("data"));
      assertTrue(retrieved.get("data").isArray());
      assertEquals(funcResult.results.size(), retrieved.get("data").size());

      // Verify each function entry has expected fields
      for (int i = 0; i < funcResult.results.size(); i++) {
        FunctionInfo expected = funcResult.results.get(i);
        JsonNode actual = retrieved.get("data").get(i);
        assertEquals(expected.getName(), actual.get("name").asText());
        assertEquals(expected.getEntryPoint(), actual.get("entry_point").asText());
      }
    } finally {
      fixture.close();
    }
  }

  // ---------------------------------------------------------------------------
  // ReadSymbolsTool output → store → chunked read → reassemble → assert match
  // ---------------------------------------------------------------------------

  @Test
  void readSymbolsOutput_chunkedRetrievalReassemblesCorrectly() throws Exception {
    InMemoryProgramFixtureSupport.ProgramFixture fixture =
        InMemoryProgramFixtureSupport.createReadAndManageFixtureProgram();
    try {
      ReadSymbolsTool symbolTool = new InMemoryReadSymbolsTool(fixture.program());

      // Execute real tool
      Object rawResult =
          symbolTool
              .execute(
                  null,
                  Map.of("file_name", "fixture", "name_filter", "entry_", "page_size", 10),
                  null)
              .block();
      @SuppressWarnings("unchecked")
      PaginatedResult<SymbolInfo> symbolResult =
          assertInstanceOf(PaginatedResult.class, rawResult);
      assertFalse(symbolResult.results.isEmpty());

      // Wrap and serialize
      McpResponse<?> envelope =
          McpResponse.paginated(
              "read_symbols",
              "execute",
              symbolResult.results,
              symbolResult.nextCursor,
              null,
              7L);
      String originalJson = mapper.writeValueAsString(envelope);

      // Store
      String sessionId = "ses_e2e_symbol_output";
      ToolOutputStore.StoredOutputRef ref =
          ToolOutputStore.store(sessionId, "read_symbols", "execute", originalJson);

      // Read back in small chunks to exercise pagination
      int chunkSize = Math.max(50, originalJson.length() / 3);
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

        assertEquals(offset, chunk.offset());
        assertEquals(originalJson.length(), chunk.totalChars());
        reassembled.append(chunk.content());

        if (!chunk.hasMore()) {
          assertNull(chunk.nextOffset());
          break;
        }
        assertNotNull(chunk.nextOffset());
        offset = chunk.nextOffset();
      }

      // Verify reassembled content is byte-identical to original
      assertEquals(originalJson, reassembled.toString());

      // Parse and verify symbol data integrity
      JsonNode retrieved = mapper.readTree(reassembled.toString());
      assertTrue(retrieved.get("success").asBoolean());
      JsonNode dataArray = retrieved.get("data");
      assertEquals(symbolResult.results.size(), dataArray.size());

      for (int i = 0; i < symbolResult.results.size(); i++) {
        SymbolInfo expected = symbolResult.results.get(i);
        JsonNode actual = dataArray.get(i);
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
      ReadFunctionsTool funcTool = new InMemoryReadFunctionsTool(fixture.program());

      Object rawResult =
          funcTool.execute(null, Map.of("file_name", "fixture", "page_size", 10), null).block();
      @SuppressWarnings("unchecked")
      PaginatedResult<FunctionInfo> funcResult =
          assertInstanceOf(PaginatedResult.class, rawResult);

      McpResponse<?> envelope =
          McpResponse.success("read_functions", "execute", funcResult.results, 15L);
      String json = mapper.writeValueAsString(envelope);

      String sessionId = "ses_e2e_metadata";
      ToolOutputStore.StoredOutputRef ref =
          ToolOutputStore.store(sessionId, "read_functions", "execute", json);

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
              .execute(
                  null, Map.of("action", "list_outputs", "session_id", sessionId), null)
              .block();
      @SuppressWarnings("unchecked")
      PaginatedResult<ToolOutputStore.OutputInfo> outputs =
          assertInstanceOf(PaginatedResult.class, outputsRaw);
      ToolOutputStore.OutputInfo ourOutput =
          outputs.results.stream()
              .filter(o -> o.outputId().equals(ref.outputId()))
              .findFirst()
              .orElseThrow(() -> new AssertionError("Output not found: " + ref.outputId()));

      assertEquals("read_functions", ourOutput.toolName());
      assertEquals("execute", ourOutput.operation());
      assertEquals(json.length(), ourOutput.totalChars());
      assertEquals(ref.fileName(), ourOutput.fileName());

      // read by file name — alternative lookup path
      Object byNameRaw =
          readOutputTool
              .execute(
                  null,
                  Map.of(
                      "action", "read",
                      "session_id", sessionId,
                      "output_file_name", ref.fileName()),
                  null)
              .block();
      ToolOutputStore.OutputChunk byName =
          assertInstanceOf(ToolOutputStore.OutputChunk.class, byNameRaw);
      assertEquals(json, byName.content());
    } finally {
      fixture.close();
    }
  }

  // ---------------------------------------------------------------------------
  // In-memory tool stubs
  // ---------------------------------------------------------------------------

  private static final class InMemoryReadFunctionsTool extends ReadFunctionsTool {
    private final Program program;

    InMemoryReadFunctionsTool(Program program) {
      this.program = program;
    }

    @Override
    protected Mono<Program> getProgram(
        Map<String, Object> args, ghidra.framework.plugintool.PluginTool tool) {
      return Mono.just(program);
    }
  }

  private static final class InMemoryReadSymbolsTool extends ReadSymbolsTool {
    private final Program program;

    InMemoryReadSymbolsTool(Program program) {
      this.program = program;
    }

    @Override
    protected Mono<Program> getProgram(
        Map<String, Object> args, ghidra.framework.plugintool.PluginTool tool) {
      return Mono.just(program);
    }
  }
}
