package com.themixednuts.tools;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.BatchOperationResult;
import com.themixednuts.models.OperationResult;
import com.themixednuts.models.SymbolInfo;
import com.themixednuts.tools.AnalyzeTool.DemangleResult;
import com.themixednuts.tools.ExecuteScriptTool.ScriptGuidance;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;

class UtilityToolsE2eTest {

  @Test
  void demangleSymbolReturnsStructuredResultForMangledInput() throws Exception {
    assumeTrue(
        Boolean.getBoolean("e2e.integration"), "Set -De2e.integration=true to run e2e tests");

    InMemoryProgramFixtureSupport.ProgramFixture fixture =
        InMemoryProgramFixtureSupport.createReadAndManageFixtureProgram();
    try {
      AnalyzeTool tool = new InMemoryAnalyzeTool(fixture.program());

      String mangled = "_Z3fooi";
      Object raw;
      try {
        raw =
            tool.execute(
                    null,
                    Map.of(
                        "file_name", "fixture",
                        "action", "demangle",
                        "mangled_symbol", mangled),
                    null)
                .block();
      } catch (Exception thrown) {
        // The fixture environment may not have the Itanium demangler wired up; if it isn't, the
        // tool should surface a structured error with a "No demangler" message instead of
        // returning a degraded payload.
        Throwable cause = thrown;
        while (cause.getCause() != null && cause != cause.getCause()) {
          cause = cause.getCause();
        }
        assertTrue(
            cause.getMessage() != null && cause.getMessage().contains("No demangler"),
            "Expected a 'no demangler' message; got: " + cause.getMessage());
        return;
      }

      // Happy path: success returns the demangled string plus pre-parsed components.
      DemangleResult result = assertInstanceOf(DemangleResult.class, raw);
      assertNotNull(result.getDemangled());
      assertTrue(result.getDemangled().toLowerCase().contains("foo"));
    } finally {
      fixture.close();
    }
  }

  @Test
  void demangleSymbolHandlesMsvcMethodNames() throws Exception {
    assumeTrue(
        Boolean.getBoolean("e2e.integration"), "Set -De2e.integration=true to run e2e tests");

    InMemoryProgramFixtureSupport.ProgramFixture fixture =
        InMemoryProgramFixtureSupport.createReadAndManageFixtureProgram();
    try {
      AnalyzeTool tool = new InMemoryAnalyzeTool(fixture.program());

      Object raw =
          tool.execute(
                  null,
                  Map.of(
                      "file_name", "fixture",
                      "action", "demangle",
                      "mangled_symbol", "?GetName@CanvasAsset@@UEBAPEBDXZ"),
                  null)
              .block();
      DemangleResult result = assertInstanceOf(DemangleResult.class, raw);

      assertTrue(result.getDemangled().contains("CanvasAsset::GetName"));
      assertEquals("CanvasAsset", result.getClassName());
      assertEquals("GetName", result.getFunctionName());
    } finally {
      fixture.close();
    }
  }

  @Test
  void analyzeGraphAndCallGraphResolveFunctionAddresses() throws Exception {
    assumeTrue(
        Boolean.getBoolean("e2e.integration"), "Set -De2e.integration=true to run e2e tests");

    InMemoryProgramFixtureSupport.ProgramFixture fixture =
        InMemoryProgramFixtureSupport.createReadAndManageFixtureProgram();
    try {
      AnalyzeTool tool = new InMemoryAnalyzeTool(fixture.program());

      Object graphRaw =
          tool.execute(
                  null,
                  Map.of("file_name", "fixture", "action", "graph", "address", "0x401000"),
                  null)
              .block();
      @SuppressWarnings("unchecked")
      Map<String, Object> graph = assertInstanceOf(Map.class, graphRaw);
      assertEquals("entry_main", graph.get("function_name"));
      assertTrue(((List<?>) graph.get("nodes")).size() > 0);

      Object callGraphRaw =
          tool.execute(
                  null,
                  Map.of(
                      "file_name", "fixture",
                      "action", "call_graph",
                      "address", "0x401000",
                      "depth", 2,
                      "direction", "both",
                      "max_results", 10),
                  null)
              .block();
      @SuppressWarnings("unchecked")
      Map<String, Object> callGraph = assertInstanceOf(Map.class, callGraphRaw);
      assertTrue(((List<?>) callGraph.get("nodes")).size() > 0);
    } finally {
      fixture.close();
    }
  }

  @Test
  void undoRedoRevertsAndRestoresSymbolMutationWithStateChecks() throws Exception {
    assumeTrue(
        Boolean.getBoolean("e2e.integration"), "Set -De2e.integration=true to run e2e tests");

    InMemoryProgramFixtureSupport.ProgramFixture fixture =
        InMemoryProgramFixtureSupport.createReadAndManageFixtureProgram();
    try {
      SymbolsTool manageSymbolsTool = new InMemorySymbolsTool(fixture.program());
      ProjectTool undoRedoTool = new InMemoryProjectTool(fixture.program());

      Object createdRaw =
          manageSymbolsTool
              .execute(
                  null,
                  Map.of(
                      "file_name", "fixture",
                      "action", "create",
                      "symbol_type", "label",
                      "address", "0x401090",
                      "name", "undo_redo_label"),
                  null)
              .block();
      SymbolInfo created = assertInstanceOf(SymbolInfo.class, createdRaw);
      assertEquals("undo_redo_label", created.getName());

      Object infoRaw =
          undoRedoTool
              .execute(null, Map.of("file_name", "fixture", "action", "history"), null)
              .block();
      @SuppressWarnings("unchecked")
      Map<String, Object> info = assertInstanceOf(Map.class, infoRaw);
      assertEquals("history", info.get("action"));
      assertTrue(Boolean.TRUE.equals(info.get("can_undo")));

      Object undoRaw =
          undoRedoTool
              .execute(null, Map.of("file_name", "fixture", "action", "undo"), null)
              .block();
      @SuppressWarnings("unchecked")
      Map<String, Object> undoResult = assertInstanceOf(Map.class, undoRaw);
      assertEquals("undo", undoResult.get("action"));
      assertNotNull(undoResult.get("undone_operation"));

      Address address = fixture.program().getAddressFactory().getAddress("0x401090");
      Symbol[] afterUndo = fixture.program().getSymbolTable().getSymbols(address);
      assertTrue(
          Arrays.stream(afterUndo).noneMatch(symbol -> "undo_redo_label".equals(symbol.getName())));

      Object redoRaw =
          undoRedoTool
              .execute(null, Map.of("file_name", "fixture", "action", "redo"), null)
              .block();
      @SuppressWarnings("unchecked")
      Map<String, Object> redoResult = assertInstanceOf(Map.class, redoRaw);
      assertEquals("redo", redoResult.get("action"));
      assertNotNull(redoResult.get("redone_operation"));

      Symbol[] afterRedo = fixture.program().getSymbolTable().getSymbols(address);
      assertTrue(
          Arrays.stream(afterRedo).anyMatch(symbol -> "undo_redo_label".equals(symbol.getName())));
    } finally {
      fixture.close();
    }
  }

  @Test
  void projectRebaseSetsExplicitImageBase() throws Exception {
    assumeTrue(
        Boolean.getBoolean("e2e.integration"), "Set -De2e.integration=true to run e2e tests");

    InMemoryProgramFixtureSupport.ProgramFixture fixture =
        InMemoryProgramFixtureSupport.createReadAndManageFixtureProgram();
    try {
      ProjectTool tool = new InMemoryProjectTool(fixture.program());
      Address originalBase = fixture.program().getImageBase();
      Address targetBase = originalBase.addNoWrap(0x100000L);

      Object raw =
          tool.execute(
                  null,
                  Map.of(
                      "file_name",
                      "fixture",
                      "action",
                      "rebase",
                      "image_base",
                      "0x" + Long.toHexString(targetBase.getOffset())),
                  null)
              .block();

      OperationResult result = assertInstanceOf(OperationResult.class, raw);
      assertEquals("rebase", result.getOperation());
      assertEquals(targetBase, fixture.program().getImageBase());
      assertEquals(Boolean.TRUE, result.getMetadata().get("changed"));
      assertEquals("explicit", result.getMetadata().get("source"));
    } finally {
      fixture.close();
    }
  }

  @Test
  void projectRebaseCanUsePeOptionalHeaderImageBase() throws Exception {
    assumeTrue(
        Boolean.getBoolean("e2e.integration"), "Set -De2e.integration=true to run e2e tests");

    Path pePath = createMinimalPeWithImageBase(0x180000000L);
    InMemoryProgramFixtureSupport.ProgramFixture fixture =
        InMemoryProgramFixtureSupport.createReadAndManageFixtureProgram();
    try {
      setExecutablePath(fixture.program(), pePath);

      ProjectTool tool = new InMemoryProjectTool(fixture.program());
      Object raw =
          tool.execute(
                  null,
                  Map.of("file_name", "fixture", "action", "rebase", "use_stated_image_base", true),
                  null)
              .block();

      OperationResult result = assertInstanceOf(OperationResult.class, raw);
      Address expected = fixture.program().getAddressFactory().getAddress("0x180000000");
      assertEquals(expected, fixture.program().getImageBase());
      assertEquals("pe_optional_header", result.getMetadata().get("source"));
      assertEquals("0x180000000", result.getMetadata().get("stated_image_base"));
    } finally {
      fixture.close();
      Files.deleteIfExists(pePath);
    }
  }

  @Test
  void batchOperationsExecutesMutationsAndReturnsPerOperationResults() throws Exception {
    assumeTrue(
        Boolean.getBoolean("e2e.integration"), "Set -De2e.integration=true to run e2e tests");

    InMemoryProgramFixtureSupport.ProgramFixture fixture =
        InMemoryProgramFixtureSupport.createReadAndManageFixtureProgram();
    try {
      BatchOperationsTool tool = new InMemoryBatchOperationsTool(fixture.program());

      Object raw =
          tool.execute(
                  null,
                  Map.of(
                      "file_name",
                      "fixture",
                      "operations",
                      List.of(
                          Map.of(
                              "tool",
                              "symbols",
                              "arguments",
                              Map.of(
                                  "action",
                                  "create",
                                  "symbol_type",
                                  "label",
                                  "address",
                                  "0x4010a0",
                                  "name",
                                  "batch_created_label_one")),
                          Map.of(
                              "tool",
                              "symbols",
                              "arguments",
                              Map.of(
                                  "action",
                                  "create",
                                  "symbol_type",
                                  "label",
                                  "address",
                                  "0x4010a2",
                                  "name",
                                  "batch_created_label_two")))),
                  null)
              .block();

      BatchOperationResult result = assertInstanceOf(BatchOperationResult.class, raw);
      assertEquals(2, result.getOperations().size());
      assertEquals(2, result.getSuccessfulOperations());
      assertEquals(0, result.getFailedOperations());
      assertTrue(
          result.getOperations().stream()
              .allMatch(BatchOperationResult.IndividualOperationResult::isSuccess));

      Address labelAddress = fixture.program().getAddressFactory().getAddress("0x4010a0");
      Symbol[] symbols = fixture.program().getSymbolTable().getSymbols(labelAddress);
      assertTrue(
          Arrays.stream(symbols)
              .anyMatch(symbol -> "batch_created_label_one".equals(symbol.getName())));

      Address secondLabelAddress = fixture.program().getAddressFactory().getAddress("0x4010a2");
      Symbol[] secondSymbols = fixture.program().getSymbolTable().getSymbols(secondLabelAddress);
      assertTrue(
          Arrays.stream(secondSymbols)
              .anyMatch(symbol -> "batch_created_label_two".equals(symbol.getName())));
    } finally {
      fixture.close();
    }
  }

  @Test
  void batchOperationsRollsBackEarlierChangesWhenLaterOperationFails() throws Exception {
    assumeTrue(
        Boolean.getBoolean("e2e.integration"), "Set -De2e.integration=true to run e2e tests");

    InMemoryProgramFixtureSupport.ProgramFixture fixture =
        InMemoryProgramFixtureSupport.createReadAndManageFixtureProgram();
    try {
      BatchOperationsTool tool = new InMemoryBatchOperationsTool(fixture.program());

      assertThrows(
          GhidraMcpException.class,
          () ->
              tool.execute(
                      null,
                      Map.of(
                          "file_name",
                          "fixture",
                          "operations",
                          List.of(
                              Map.of(
                                  "tool",
                                  "symbols",
                                  "arguments",
                                  Map.of(
                                      "action",
                                      "create",
                                      "symbol_type",
                                      "label",
                                      "address",
                                      "0x4010b0",
                                      "name",
                                      "batch_rollback_label")),
                              Map.of(
                                  "tool",
                                  "memory",
                                  "arguments",
                                  Map.of(
                                      "action",
                                      "write",
                                      "address",
                                      "0x401000",
                                      "bytes_hex",
                                      "aaaa")))),
                      null)
                  .block());

      Address address = fixture.program().getAddressFactory().getAddress("0x4010b0");
      Symbol[] symbols = fixture.program().getSymbolTable().getSymbols(address);
      assertTrue(
          Arrays.stream(symbols)
              .noneMatch(symbol -> "batch_rollback_label".equals(symbol.getName())));
    } finally {
      fixture.close();
    }
  }

  @Test
  void scriptGuidanceReturnsDemangleAllUsageAndTroubleshooting() throws Exception {
    assumeTrue(
        Boolean.getBoolean("e2e.integration"), "Set -De2e.integration=true to run e2e tests");

    InMemoryProgramFixtureSupport.ProgramFixture fixture =
        InMemoryProgramFixtureSupport.createReadAndManageFixtureProgram();
    try {
      ExecuteScriptTool tool = new InMemoryExecuteScriptTool(fixture.program());

      Object raw =
          tool.execute(
                  null,
                  Map.of(
                      "file_name", "fixture",
                      "script_name", "DemangleAllScript",
                      "guidance_type", "all"),
                  null)
              .block();
      ScriptGuidance guidance = assertInstanceOf(ScriptGuidance.class, raw);

      assertEquals("DemangleAllScript", guidance.getScriptName());
      assertEquals("all", guidance.getGuidanceType());
      assertNotNull(guidance.getInstructions());
      assertTrue(guidance.getInstructions().contains("Script Manager"));
      assertNotNull(guidance.getTips());
      assertFalse(guidance.getTips().isBlank());
      assertTrue(guidance.getTips().toLowerCase().contains("script"));
      assertNotNull(guidance.getTroubleshooting());
      assertFalse(guidance.getTroubleshooting().isBlank());
      assertTrue(guidance.getTroubleshooting().contains("Common Issues"));
    } finally {
      fixture.close();
    }
  }

  private static void setExecutablePath(Program program, Path executablePath) {
    int txId = program.startTransaction("Set executable path");
    boolean commit = false;
    try {
      program.setExecutablePath(executablePath.toString());
      commit = true;
    } finally {
      program.endTransaction(txId, commit);
    }
  }

  private static Path createMinimalPeWithImageBase(long imageBase) throws Exception {
    byte[] bytes = new byte[0x200];
    bytes[0] = 'M';
    bytes[1] = 'Z';
    putIntLE(bytes, 0x3c, 0x80);

    bytes[0x80] = 'P';
    bytes[0x81] = 'E';
    bytes[0x82] = 0;
    bytes[0x83] = 0;

    putShortLE(bytes, 0x84, 0x8664);
    putShortLE(bytes, 0x86, 0);
    putShortLE(bytes, 0x94, 0xf0);
    putShortLE(bytes, 0x96, 0x2022);

    int optionalHeader = 0x98;
    putShortLE(bytes, optionalHeader, 0x20b);
    putLongLE(bytes, optionalHeader + 24, imageBase);
    putIntLE(bytes, optionalHeader + 32, 0x1000);
    putIntLE(bytes, optionalHeader + 36, 0x200);
    putIntLE(bytes, optionalHeader + 56, 0x1000);
    putIntLE(bytes, optionalHeader + 60, 0x200);
    putShortLE(bytes, optionalHeader + 68, 3);
    putLongLE(bytes, optionalHeader + 72, 0x100000L);
    putLongLE(bytes, optionalHeader + 80, 0x1000L);
    putLongLE(bytes, optionalHeader + 88, 0x100000L);
    putLongLE(bytes, optionalHeader + 96, 0x1000L);
    putIntLE(bytes, optionalHeader + 108, 16);

    Path path = Files.createTempFile("ghidra-mcp-imagebase", ".exe");
    Files.write(path, bytes);
    return path;
  }

  private static void putShortLE(byte[] bytes, int offset, int value) {
    bytes[offset] = (byte) (value & 0xff);
    bytes[offset + 1] = (byte) ((value >>> 8) & 0xff);
  }

  private static void putIntLE(byte[] bytes, int offset, int value) {
    bytes[offset] = (byte) (value & 0xff);
    bytes[offset + 1] = (byte) ((value >>> 8) & 0xff);
    bytes[offset + 2] = (byte) ((value >>> 16) & 0xff);
    bytes[offset + 3] = (byte) ((value >>> 24) & 0xff);
  }

  private static void putLongLE(byte[] bytes, int offset, long value) {
    for (int i = 0; i < Long.BYTES; i++) {
      bytes[offset + i] = (byte) ((value >>> (8 * i)) & 0xff);
    }
  }

  @GhidraMcpTool(
      name = "Analyze Test",
      description = "In-memory analyze test wrapper",
      mcpName = "analyze",
      mcpDescription = "In-memory wrapper for analyze")
  private static final class InMemoryAnalyzeTool extends AnalyzeTool {
    private final Program program;

    InMemoryAnalyzeTool(Program program) {
      this.program = program;
    }

    @Override
    protected Mono<Program> getProgram(
        Map<String, Object> args, ghidra.framework.plugintool.PluginTool tool) {
      return Mono.just(program);
    }
  }

  @GhidraMcpTool(
      name = "Project Test",
      description = "In-memory project test wrapper",
      mcpName = "project",
      mcpDescription = "In-memory wrapper for project")
  private static final class InMemoryProjectTool extends ProjectTool {
    private final Program program;

    InMemoryProjectTool(Program program) {
      this.program = program;
    }

    @Override
    protected Mono<Program> getProgram(
        Map<String, Object> args, ghidra.framework.plugintool.PluginTool tool) {
      return Mono.just(program);
    }
  }

  @GhidraMcpTool(
      name = "Manage Symbols Test",
      description = "In-memory manage symbols test wrapper",
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

  @GhidraMcpTool(
      name = "Script Guidance Test",
      description = "In-memory script guidance test wrapper",
      mcpName = "script_guidance",
      mcpDescription = "In-memory wrapper for script_guidance")
  private static final class InMemoryExecuteScriptTool extends ExecuteScriptTool {
    private final Program program;

    InMemoryExecuteScriptTool(Program program) {
      this.program = program;
    }

    @Override
    protected Mono<Program> getProgram(
        Map<String, Object> args, ghidra.framework.plugintool.PluginTool tool) {
      return Mono.just(program);
    }
  }

  @GhidraMcpTool(
      name = "Memory Test",
      description = "In-memory memory test wrapper",
      mcpName = "memory",
      mcpDescription = "In-memory wrapper for memory")
  private static final class InMemoryMemoryTool extends MemoryTool {
    private final Program program;

    InMemoryMemoryTool(Program program) {
      this.program = program;
    }

    @Override
    protected Mono<Program> getProgram(
        Map<String, Object> args, ghidra.framework.plugintool.PluginTool tool) {
      return Mono.just(program);
    }
  }

  @GhidraMcpTool(
      name = "Batch Operations Test",
      description = "In-memory batch operations test wrapper",
      mcpName = "batch_operations",
      mcpDescription = "In-memory wrapper for batch_operations")
  private static final class InMemoryBatchOperationsTool extends BatchOperationsTool {
    private final Program program;
    private final Map<String, BaseMcpTool> availableTools;

    InMemoryBatchOperationsTool(Program program) {
      this.program = program;
      this.availableTools =
          Map.of(
              "symbols", new InMemorySymbolsTool(program),
              "memory", new InMemoryMemoryTool(program));
    }

    @Override
    public Mono<? extends Object> execute(
        io.modelcontextprotocol.common.McpTransportContext context,
        Map<String, Object> args,
        ghidra.framework.plugintool.PluginTool tool) {
      @SuppressWarnings("unchecked")
      List<Map<String, Object>> operations = (List<Map<String, Object>>) args.get("operations");
      if (operations == null || operations.isEmpty()) {
        return Mono.error(new IllegalArgumentException("operations are required"));
      }

      return Mono.fromCallable(
          () -> invokeBatchExecution(context, args, operations, availableTools, tool));
    }

    private Object invokeBatchExecution(
        io.modelcontextprotocol.common.McpTransportContext context,
        Map<String, Object> args,
        List<Map<String, Object>> operations,
        Map<String, BaseMcpTool> tools,
        ghidra.framework.plugintool.PluginTool tool) {
      try {
        Method method =
            BatchOperationsTool.class.getDeclaredMethod(
                "executeBatchInSingleTransaction",
                Program.class,
                io.modelcontextprotocol.common.McpTransportContext.class,
                Map.class,
                List.class,
                Map.class,
                ghidra.framework.plugintool.PluginTool.class);
        method.setAccessible(true);
        return method.invoke(this, program, context, args, operations, tools, tool);
      } catch (InvocationTargetException e) {
        Throwable cause = e.getCause();
        if (cause instanceof RuntimeException runtimeException) {
          throw runtimeException;
        }
        throw new RuntimeException(cause);
      } catch (ReflectiveOperationException e) {
        throw new RuntimeException(e);
      }
    }
  }
}
