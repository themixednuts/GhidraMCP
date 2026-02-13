package com.themixednuts.tools;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.models.DataTypeReadResult;
import com.themixednuts.models.FunctionInfo;
import com.themixednuts.models.MemoryReadResult;
import com.themixednuts.models.MemorySegmentsOverview;
import com.themixednuts.models.MemoryWriteResult;
import com.themixednuts.models.OperationResult;
import com.themixednuts.models.ProgramInfo;
import com.themixednuts.models.SymbolInfo;
import ghidra.program.model.listing.Program;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;

class ManageToolsE2eTest {

  @Test
  void manageMemorySupportsReadWriteAndSegmentListing() throws Exception {
    assumeTrue(Boolean.getBoolean("e2e.integration"), "Set -De2e.integration=true to run e2e tests");

    InMemoryProgramFixtureSupport.ProgramFixture fixture =
        InMemoryProgramFixtureSupport.createReadAndManageFixtureProgram();
    try {
      ManageMemoryTool tool = new InMemoryManageMemoryTool(fixture.program());

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

      Object segmentsRaw =
          tool.execute(
                  null,
                  Map.of("file_name", "fixture", "action", "list_segments"),
                  null)
              .block();
      MemorySegmentsOverview segments = assertInstanceOf(MemorySegmentsOverview.class, segmentsRaw);
      assertTrue(segments.getTotalSegments() >= 1);
      assertTrue(segments.getSegments().stream().anyMatch(segment -> segment.getName().contains(".text")));
    } finally {
      fixture.close();
    }
  }

  @Test
  void manageSymbolsSupportsCreateAndUpdate() throws Exception {
    assumeTrue(Boolean.getBoolean("e2e.integration"), "Set -De2e.integration=true to run e2e tests");

    InMemoryProgramFixtureSupport.ProgramFixture fixture =
        InMemoryProgramFixtureSupport.createReadAndManageFixtureProgram();
    try {
      ManageSymbolsTool tool = new InMemoryManageSymbolsTool(fixture.program());

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
    assumeTrue(Boolean.getBoolean("e2e.integration"), "Set -De2e.integration=true to run e2e tests");

    InMemoryProgramFixtureSupport.ProgramFixture fixture =
        InMemoryProgramFixtureSupport.createReadAndManageFixtureProgram();
    try {
      ManageFunctionsTool tool = new InMemoryManageFunctionsTool(fixture.program());

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
    assumeTrue(Boolean.getBoolean("e2e.integration"), "Set -De2e.integration=true to run e2e tests");

    InMemoryProgramFixtureSupport.ProgramFixture fixture =
        InMemoryProgramFixtureSupport.createReadAndManageFixtureProgram();
    try {
      ManageDataTypesTool manageTool = new InMemoryManageDataTypesTool(fixture.program());
      ReadDataTypesTool readTool = new InMemoryReadDataTypesTool(fixture.program());

      Object createdRaw =
          manageTool
              .execute(
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
                          Map.of("name", "RED", "value", 1),
                          Map.of("name", "GREEN", "value", 2))),
                  null)
              .block();
      OperationResult created = assertInstanceOf(OperationResult.class, createdRaw);
      assertTrue(created.isSuccess());
      assertEquals("create_data_type", created.getOperation());
      assertEquals("enum", created.getTarget());

      Object updatedRaw =
          manageTool
              .execute(
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
          readTool
              .execute(
                  null,
                  Map.of(
                      "file_name", "fixture",
                      "data_type_kind", "enum",
                      "name", "ColorMode"),
                  null)
              .block();
      DataTypeReadResult readBack = assertInstanceOf(DataTypeReadResult.class, readBackRaw);
      assertEquals("ColorMode", readBack.getName());
      assertEquals(3, readBack.getValueCount());
      assertTrue(readBack.getEnumValues().stream().anyMatch(v -> "BLUE".equals(v.name()) && v.value() == 3));
    } finally {
      fixture.close();
    }
  }

  @Test
  void manageProjectSupportsBookmarkMutationWithStateValidation() throws Exception {
    assumeTrue(Boolean.getBoolean("e2e.integration"), "Set -De2e.integration=true to run e2e tests");

    InMemoryProgramFixtureSupport.ProgramFixture fixture =
        InMemoryProgramFixtureSupport.createReadAndManageFixtureProgram();
    try {
      ManageProjectTool tool = new InMemoryManageProjectTool(fixture.program());

      Object createdRaw =
          tool.execute(
                  null,
                  Map.of(
                      "file_name",
                      "fixture",
                      "action",
                      "create_bookmark",
                      "address",
                      "0x401020",
                      "bookmark_type",
                      "Note",
                      "bookmark_category",
                      "E2E",
                      "comment",
                      "verify bookmark mutation"),
                  null)
              .block();
      OperationResult created = assertInstanceOf(OperationResult.class, createdRaw);
      assertTrue(created.isSuccess());
      assertEquals("create_bookmark", created.getOperation());
      assertEquals("E2E", created.getMetadata().get("bookmark_category"));

      ghidra.program.model.address.Address addr = fixture.program().getAddressFactory().getAddress("0x401020");
      ghidra.program.model.listing.Bookmark[] bookmarks = fixture.program().getBookmarkManager().getBookmarks(addr);
      assertTrue(bookmarks.length >= 1);
      assertTrue(
          java.util.Arrays.stream(bookmarks)
              .anyMatch(
                  b ->
                      "Note".equals(b.getTypeString())
                          && "E2E".equals(b.getCategory())
                          && "verify bookmark mutation".equals(b.getComment())));

      Object infoRaw =
          tool.execute(
                  null,
                  Map.of("file_name", "fixture", "action", "get_program_info"),
                  null)
              .block();
      ProgramInfo info = assertInstanceOf(ProgramInfo.class, infoRaw);
      assertNotNull(info.getName());
      assertTrue(info.getMemoryBlocks().stream().anyMatch(block -> block.getName().contains(".text")));
    } finally {
      fixture.close();
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
      name = "Manage Functions Test",
      description = "In-memory manage functions test wrapper",
      mcpName = "manage_functions",
      mcpDescription = "In-memory wrapper for manage_functions")
  private static final class InMemoryManageFunctionsTool extends ManageFunctionsTool {
    private final Program program;

    InMemoryManageFunctionsTool(Program program) {
      this.program = program;
    }

    @Override
    protected Mono<Program> getProgram(
        Map<String, Object> args, ghidra.framework.plugintool.PluginTool tool) {
      return Mono.just(program);
    }
  }

  @GhidraMcpTool(
      name = "Manage Data Types Test",
      description = "In-memory manage data types test wrapper",
      mcpName = "manage_data_types",
      mcpDescription = "In-memory wrapper for manage_data_types")
  private static final class InMemoryManageDataTypesTool extends ManageDataTypesTool {
    private final Program program;

    InMemoryManageDataTypesTool(Program program) {
      this.program = program;
    }

    @Override
    protected Mono<Program> getProgram(
        Map<String, Object> args, ghidra.framework.plugintool.PluginTool tool) {
      return Mono.just(program);
    }
  }

  @GhidraMcpTool(
      name = "Read Data Types Test",
      description = "In-memory read data types test wrapper",
      mcpName = "read_data_types",
      mcpDescription = "In-memory wrapper for read_data_types")
  private static final class InMemoryReadDataTypesTool extends ReadDataTypesTool {
    private final Program program;

    InMemoryReadDataTypesTool(Program program) {
      this.program = program;
    }

    @Override
    protected Mono<Program> getProgram(
        Map<String, Object> args, ghidra.framework.plugintool.PluginTool tool) {
      return Mono.just(program);
    }
  }

  @GhidraMcpTool(
      name = "Manage Project Test",
      description = "In-memory manage project test wrapper",
      mcpName = "manage_project",
      mcpDescription = "In-memory wrapper for manage_project")
  private static final class InMemoryManageProjectTool extends ManageProjectTool {
    private final Program program;

    InMemoryManageProjectTool(Program program) {
      this.program = program;
    }

    @Override
    protected Mono<Program> getProgram(
        Map<String, Object> args, ghidra.framework.plugintool.PluginTool tool) {
      return Mono.just(program);
    }
  }
}
