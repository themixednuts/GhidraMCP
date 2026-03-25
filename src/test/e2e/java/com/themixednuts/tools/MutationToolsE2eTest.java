package com.themixednuts.tools;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.models.DataTypeReadResult;
import com.themixednuts.models.FunctionInfo;
import com.themixednuts.models.MemoryBlockInfo;
import com.themixednuts.models.MemoryReadResult;
import com.themixednuts.models.MemoryWriteResult;
import com.themixednuts.models.OperationResult;
import com.themixednuts.models.ProgramInfo;
import com.themixednuts.models.SymbolInfo;
import com.themixednuts.utils.PaginatedResult;
import ghidra.program.model.listing.Program;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;

class MutationToolsE2eTest {

  @Test
  void memoryToolSupportsReadWriteAndBlockListing() throws Exception {
    assumeTrue(
        Boolean.getBoolean("e2e.integration"), "Set -De2e.integration=true to run e2e tests");

    InMemoryProgramFixtureSupport.ProgramFixture fixture =
        InMemoryProgramFixtureSupport.createReadAndManageFixtureProgram();
    try {
      MemoryTool tool = new InMemoryMemoryTool(fixture.program());

      Object readBeforeRaw =
          tool.execute(
                  null,
                  Map.of(
                      "file_name", "fixture",
                      "action", "read",
                      "address", "0x402000",
                      "length", 3),
                  null)
              .block();
      MemoryReadResult readBefore = assertInstanceOf(MemoryReadResult.class, readBeforeRaw);
      assertEquals("112233", readBefore.getHexData());

      Object writeRaw =
          tool.execute(
                  null,
                  Map.of(
                      "file_name", "fixture",
                      "action", "write",
                      "address", "0x402000",
                      "bytes_hex", "909090"),
                  null)
              .block();
      MemoryWriteResult writeResult = assertInstanceOf(MemoryWriteResult.class, writeRaw);
      assertTrue(writeResult.isSuccess());
      assertEquals(3, writeResult.getBytesWritten());

      Object readAfterRaw =
          tool.execute(
                  null,
                  Map.of(
                      "file_name", "fixture",
                      "action", "read",
                      "address", "0x402000",
                      "length", 3),
                  null)
              .block();
      MemoryReadResult readAfter = assertInstanceOf(MemoryReadResult.class, readAfterRaw);
      assertEquals("909090", readAfter.getHexData());

      Object blocksRaw =
          tool.execute(null, Map.of("file_name", "fixture", "action", "list_blocks"), null).block();
      @SuppressWarnings("unchecked")
      PaginatedResult<MemoryBlockInfo> blocks = assertInstanceOf(PaginatedResult.class, blocksRaw);
      assertTrue(!blocks.results.isEmpty());
      assertTrue(blocks.results.stream().anyMatch(block -> block.getName().contains(".text")));
    } finally {
      fixture.close();
    }
  }

  @Test
  void manageSymbolsSupportsCreateAndUpdate() throws Exception {
    assumeTrue(
        Boolean.getBoolean("e2e.integration"), "Set -De2e.integration=true to run e2e tests");

    InMemoryProgramFixtureSupport.ProgramFixture fixture =
        InMemoryProgramFixtureSupport.createReadAndManageFixtureProgram();
    try {
      SymbolsTool tool = new InMemorySymbolsTool(fixture.program());

      Object createdRaw =
          tool.execute(
                  null,
                  Map.of(
                      "file_name", "fixture",
                      "action", "create",
                      "symbol_type", "label",
                      "address", "0x401060",
                      "name", "custom_label"),
                  null)
              .block();
      SymbolInfo created = assertInstanceOf(SymbolInfo.class, createdRaw);
      assertEquals("custom_label", created.getName());

      Object updatedRaw =
          tool.execute(
                  null,
                  Map.of(
                      "file_name", "fixture",
                      "action", "update",
                      "current_name", "custom_label",
                      "new_name", "custom_label_renamed"),
                  null)
              .block();
      SymbolInfo updated = assertInstanceOf(SymbolInfo.class, updatedRaw);
      assertEquals("custom_label_renamed", updated.getName());
    } finally {
      fixture.close();
    }
  }

  @Test
  void manageFunctionsSupportsCreateAtAddress() throws Exception {
    assumeTrue(
        Boolean.getBoolean("e2e.integration"), "Set -De2e.integration=true to run e2e tests");

    InMemoryProgramFixtureSupport.ProgramFixture fixture =
        InMemoryProgramFixtureSupport.createReadAndManageFixtureProgram();
    try {
      FunctionsTool tool = new InMemoryFunctionsTool(fixture.program());

      Object createdRaw =
          tool.execute(
                  null,
                  Map.of(
                      "file_name", "fixture",
                      "action", "create",
                      "address", "0x401040",
                      "function_name", "new_func"),
                  null)
              .block();
      FunctionInfo created = assertInstanceOf(FunctionInfo.class, createdRaw);
      assertNotNull(created.getEntryPoint());
      assertTrue(created.getEntryPoint().toLowerCase().contains("401040"));
    } finally {
      fixture.close();
    }
  }

  @Test
  void manageDataTypesSupportsCreateAndUpdateWithReadBackValidation() throws Exception {
    assumeTrue(
        Boolean.getBoolean("e2e.integration"), "Set -De2e.integration=true to run e2e tests");

    InMemoryProgramFixtureSupport.ProgramFixture fixture =
        InMemoryProgramFixtureSupport.createReadAndManageFixtureProgram();
    try {
      DataTypesTool tool = new InMemoryDataTypesTool(fixture.program());

      Object createdRaw =
          tool.execute(
                  null,
                  Map.of(
                      "file_name",
                      "fixture",
                      "action",
                      "create",
                      "data_type_kind",
                      "enum",
                      "name",
                      "ColorMode",
                      "size",
                      4,
                      "entries",
                      List.of(
                          Map.of("name", "RED", "value", 1), Map.of("name", "GREEN", "value", 2))),
                  null)
              .block();
      OperationResult created = assertInstanceOf(OperationResult.class, createdRaw);
      assertTrue(created.isSuccess());
      assertEquals("create_data_type", created.getOperation());
      assertEquals("enum", created.getTarget());

      Object updatedRaw =
          tool.execute(
                  null,
                  Map.of(
                      "file_name",
                      "fixture",
                      "action",
                      "update",
                      "data_type_kind",
                      "enum",
                      "name",
                      "ColorMode",
                      "entries",
                      List.of(
                          Map.of("name", "RED", "value", 1),
                          Map.of("name", "GREEN", "value", 2),
                          Map.of("name", "BLUE", "value", 3))),
                  null)
              .block();
      OperationResult updated = assertInstanceOf(OperationResult.class, updatedRaw);
      assertTrue(updated.isSuccess());
      assertEquals("update_data_type", updated.getOperation());
      assertEquals("enum", updated.getTarget());

      Object readBackRaw =
          tool.execute(
                  null,
                  Map.of(
                      "file_name", "fixture",
                      "action", "get",
                      "data_type_kind", "enum",
                      "name", "ColorMode"),
                  null)
              .block();
      DataTypeReadResult readBack = assertInstanceOf(DataTypeReadResult.class, readBackRaw);
      assertEquals("ColorMode", readBack.getName());
      assertEquals(3, readBack.getValueCount());
      assertTrue(
          readBack.getEnumValues().stream()
              .anyMatch(v -> "BLUE".equals(v.name()) && v.value() == 3));
    } finally {
      fixture.close();
    }
  }

  @Test
  void projectToolSupportsInfoAction() throws Exception {
    assumeTrue(
        Boolean.getBoolean("e2e.integration"), "Set -De2e.integration=true to run e2e tests");

    InMemoryProgramFixtureSupport.ProgramFixture fixture =
        InMemoryProgramFixtureSupport.createReadAndManageFixtureProgram();
    try {
      ProjectTool tool = new InMemoryProjectTool(fixture.program());

      Object infoRaw =
          tool.execute(null, Map.of("file_name", "fixture", "action", "info"), null).block();
      ProgramInfo info = assertInstanceOf(ProgramInfo.class, infoRaw);
      assertNotNull(info.getName());
      assertTrue(
          info.getMemoryBlocks().stream().anyMatch(block -> block.getName().contains(".text")));
    } finally {
      fixture.close();
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
      name = "Functions Test",
      description = "In-memory functions test wrapper",
      mcpName = "functions",
      mcpDescription = "In-memory wrapper for functions")
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
      name = "Data Types Test",
      description = "In-memory data types test wrapper",
      mcpName = "data_types",
      mcpDescription = "In-memory wrapper for data_types")
  private static final class InMemoryDataTypesTool extends DataTypesTool {
    private final Program program;

    InMemoryDataTypesTool(Program program) {
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
}
