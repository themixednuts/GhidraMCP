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
import com.themixednuts.models.SymbolInfo;
import com.themixednuts.tools.DemanglerTool.DemangleResult;
import com.themixednuts.tools.ExecuteScriptTool.ScriptGuidance;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;

class UtilityToolsE2eTest {

  @Test
  void demangleSymbolReturnsStructuredResultForMangledInput() throws Exception {
    assumeTrue(Boolean.getBoolean("e2e.integration"), "Set -De2e.integration=true to run e2e tests");

    InMemoryProgramFixtureSupport.ProgramFixture fixture =
        InMemoryProgramFixtureSupport.createReadAndManageFixtureProgram();
    try {
      DemanglerTool tool = new InMemoryDemanglerTool(fixture.program());

      String mangled = "_Z3fooi";
      Object raw =
          tool.execute(null, Map.of("file_name", "fixture", "mangled_symbol", mangled), null).block();
      DemangleResult result = assertInstanceOf(DemangleResult.class, raw);

      assertEquals(mangled, result.getOriginalSymbol());
      assertNotNull(result.getSymbolAnalysis());
      assertTrue(result.getSymbolAnalysis().contains("Itanium"));
      if (result.isValid()) {
        assertNotNull(result.getDemangledSymbol());
        assertTrue(result.getDemangledSymbol().toLowerCase().contains("foo"));
      } else {
        assertNotNull(result.getErrorMessage());
        assertTrue(result.getErrorMessage().contains("No demangler"));
      }
    } finally {
      fixture.close();
    }
  }

  @Test
  void undoRedoRevertsAndRestoresSymbolMutationWithStateChecks() throws Exception {
    assumeTrue(Boolean.getBoolean("e2e.integration"), "Set -De2e.integration=true to run e2e tests");

    InMemoryProgramFixtureSupport.ProgramFixture fixture =
        InMemoryProgramFixtureSupport.createReadAndManageFixtureProgram();
    try {
      ManageSymbolsTool manageSymbolsTool = new InMemoryManageSymbolsTool(fixture.program());
      UndoRedoTool undoRedoTool = new InMemoryUndoRedoTool(fixture.program());

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

      Object infoRaw = undoRedoTool.execute(null, Map.of("file_name", "fixture", "action", "info"), null).block();
      @SuppressWarnings("unchecked")
      Map<String, Object> info = assertInstanceOf(Map.class, infoRaw);
      assertEquals("info", info.get("action"));
      assertTrue(Boolean.TRUE.equals(info.get("can_undo")));

      Object undoRaw = undoRedoTool.execute(null, Map.of("file_name", "fixture", "action", "undo"), null).block();
      @SuppressWarnings("unchecked")
      Map<String, Object> undoResult = assertInstanceOf(Map.class, undoRaw);
      assertEquals("undo", undoResult.get("action"));
      assertTrue(Boolean.TRUE.equals(undoResult.get("success")));

      Address address = fixture.program().getAddressFactory().getAddress("0x401090");
      Symbol[] afterUndo = fixture.program().getSymbolTable().getSymbols(address);
      assertTrue(Arrays.stream(afterUndo).noneMatch(symbol -> "undo_redo_label".equals(symbol.getName())));

      Object redoRaw = undoRedoTool.execute(null, Map.of("file_name", "fixture", "action", "redo"), null).block();
      @SuppressWarnings("unchecked")
      Map<String, Object> redoResult = assertInstanceOf(Map.class, redoRaw);
      assertEquals("redo", redoResult.get("action"));
      assertTrue(Boolean.TRUE.equals(redoResult.get("success")));

      Symbol[] afterRedo = fixture.program().getSymbolTable().getSymbols(address);
      assertTrue(Arrays.stream(afterRedo).anyMatch(symbol -> "undo_redo_label".equals(symbol.getName())));
    } finally {
      fixture.close();
    }
  }

  @Test
  void batchOperationsExecutesMutationsAndReturnsPerOperationResults() throws Exception {
    assumeTrue(Boolean.getBoolean("e2e.integration"), "Set -De2e.integration=true to run e2e tests");

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
                              "manage_symbols",
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
                              "manage_symbols",
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
      assertTrue(result.isSuccess());
      assertEquals(2, result.getTotalOperations());
      assertEquals(2, result.getSuccessfulOperations());
      assertEquals(0, result.getFailedOperations());
      assertTrue(result.getOperations().stream().allMatch(BatchOperationResult.IndividualOperationResult::isSuccess));

      Address labelAddress = fixture.program().getAddressFactory().getAddress("0x4010a0");
      Symbol[] symbols = fixture.program().getSymbolTable().getSymbols(labelAddress);
      assertTrue(Arrays.stream(symbols).anyMatch(symbol -> "batch_created_label_one".equals(symbol.getName())));

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
    assumeTrue(Boolean.getBoolean("e2e.integration"), "Set -De2e.integration=true to run e2e tests");

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
                                  "manage_symbols",
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
                                  "manage_memory",
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
      assertTrue(Arrays.stream(symbols).noneMatch(symbol -> "batch_rollback_label".equals(symbol.getName())));
    } finally {
      fixture.close();
    }
  }

  @Test
  void scriptGuidanceReturnsDemangleAllUsageAndTroubleshooting() throws Exception {
    assumeTrue(Boolean.getBoolean("e2e.integration"), "Set -De2e.integration=true to run e2e tests");

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

  @GhidraMcpTool(
      name = "Demangle Symbol Test",
      description = "In-memory demangle symbol test wrapper",
      mcpName = "demangle_symbol",
      mcpDescription = "In-memory wrapper for demangle_symbol")
  private static final class InMemoryDemanglerTool extends DemanglerTool {
    private final Program program;

    InMemoryDemanglerTool(Program program) {
      this.program = program;
    }

    @Override
    protected Mono<Program> getProgram(
        Map<String, Object> args, ghidra.framework.plugintool.PluginTool tool) {
      return Mono.just(program);
    }
  }

  @GhidraMcpTool(
      name = "Undo Redo Test",
      description = "In-memory undo redo test wrapper",
      mcpName = "undo_redo",
      mcpDescription = "In-memory wrapper for undo_redo")
  private static final class InMemoryUndoRedoTool extends UndoRedoTool {
    private final Program program;

    InMemoryUndoRedoTool(Program program) {
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
      mcpName = "manage_symbols",
      mcpDescription = "In-memory wrapper for manage_symbols")
  private static final class InMemoryManageSymbolsTool extends ManageSymbolsTool {
    private final Program program;

    InMemoryManageSymbolsTool(Program program) {
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
      name = "Manage Memory Test",
      description = "In-memory manage memory test wrapper",
      mcpName = "manage_memory",
      mcpDescription = "In-memory wrapper for manage_memory")
  private static final class InMemoryManageMemoryTool extends ManageMemoryTool {
    private final Program program;

    InMemoryManageMemoryTool(Program program) {
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
              "manage_symbols", new InMemoryManageSymbolsTool(program),
              "manage_memory", new InMemoryManageMemoryTool(program));
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
