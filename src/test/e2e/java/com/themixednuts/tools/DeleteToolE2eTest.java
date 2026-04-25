package com.themixednuts.tools;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.models.DataTypeDeleteResult;
import com.themixednuts.models.FunctionInfo;
import com.themixednuts.models.OperationResult;
import com.themixednuts.models.SymbolInfo;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;

class DeleteToolE2eTest {

  @Test
  void deleteFunctionRemovesCreatedFunctionAndProgramState() throws Exception {
    assumeTrue(
        Boolean.getBoolean("e2e.integration"), "Set -De2e.integration=true to run e2e tests");

    InMemoryProgramFixtureSupport.ProgramFixture fixture =
        InMemoryProgramFixtureSupport.createReadAndManageFixtureProgram();
    try {
      FunctionsTool manageTool = new InMemoryFunctionsTool(fixture.program());
      DeleteTool deleteTool = new InMemoryDeleteTool(fixture.program());

      Object createdRaw =
          manageTool
              .execute(
                  null,
                  Map.of(
                      "file_name", "fixture",
                      "action", "create",
                      "address", "0x401040",
                      "function_name", "temp_delete_function"),
                  null)
              .block();
      FunctionInfo created = assertInstanceOf(FunctionInfo.class, createdRaw);
      assertTrue(created.getEntryPoint().toLowerCase().contains("401040"));

      Object deletedRaw =
          deleteTool
              .execute(
                  null,
                  Map.of("file_name", "fixture", "action", "function", "address", "0x401040"),
                  null)
              .block();
      OperationResult deleted = assertInstanceOf(OperationResult.class, deletedRaw);
      assertEquals("delete_function", deleted.getOperation());
      assertEquals("temp_delete_function", deleted.getMetadata().get("name"));

      Address functionAddress = fixture.program().getAddressFactory().getAddress("0x401040");
      assertNull(fixture.program().getFunctionManager().getFunctionAt(functionAddress));
    } finally {
      fixture.close();
    }
  }

  @Test
  void deleteSymbolRemovesCreatedLabelAndProgramState() throws Exception {
    assumeTrue(
        Boolean.getBoolean("e2e.integration"), "Set -De2e.integration=true to run e2e tests");

    InMemoryProgramFixtureSupport.ProgramFixture fixture =
        InMemoryProgramFixtureSupport.createReadAndManageFixtureProgram();
    try {
      SymbolsTool manageTool = new InMemorySymbolsTool(fixture.program());
      DeleteTool deleteTool = new InMemoryDeleteTool(fixture.program());

      Object createdRaw =
          manageTool
              .execute(
                  null,
                  Map.of(
                      "file_name", "fixture",
                      "action", "create",
                      "symbol_type", "label",
                      "address", "0x401060",
                      "name", "temp_delete_symbol"),
                  null)
              .block();
      SymbolInfo created = assertInstanceOf(SymbolInfo.class, createdRaw);
      assertEquals("temp_delete_symbol", created.getName());

      Object deletedRaw =
          deleteTool
              .execute(
                  null,
                  Map.of("file_name", "fixture", "action", "symbol", "name", "temp_delete_symbol"),
                  null)
              .block();
      OperationResult deleted = assertInstanceOf(OperationResult.class, deletedRaw);
      assertEquals("delete_symbol", deleted.getOperation());
      assertEquals("temp_delete_symbol", deleted.getMetadata().get("name"));

      Address symbolAddress = fixture.program().getAddressFactory().getAddress("0x401060");
      Symbol[] symbols = fixture.program().getSymbolTable().getSymbols(symbolAddress);
      assertTrue(
          Arrays.stream(symbols)
              .noneMatch(symbol -> "temp_delete_symbol".equals(symbol.getName())));
    } finally {
      fixture.close();
    }
  }

  @Test
  void deleteDataTypeRemovesCreatedEnumAndProgramState() throws Exception {
    assumeTrue(
        Boolean.getBoolean("e2e.integration"), "Set -De2e.integration=true to run e2e tests");

    InMemoryProgramFixtureSupport.ProgramFixture fixture =
        InMemoryProgramFixtureSupport.createReadAndManageFixtureProgram();
    try {
      DataTypesTool dataTypesTool = new InMemoryDataTypesTool(fixture.program());
      DeleteTool deleteTool = new InMemoryDeleteTool(fixture.program());

      dataTypesTool
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
                  "TempDeleteEnum",
                  "size",
                  4,
                  "entries",
                  List.of(Map.of("name", "ALPHA", "value", 1), Map.of("name", "BETA", "value", 2))),
              null)
          .block();

      DataType beforeDelete =
          fixture
              .program()
              .getDataTypeManager()
              .getDataType(new CategoryPath("/"), "TempDeleteEnum");
      assertNotNull(beforeDelete);

      Object deletedRaw =
          deleteTool
              .execute(
                  null,
                  Map.of(
                      "file_name", "fixture",
                      "action", "data_type",
                      "data_type_kind", "enum",
                      "name", "TempDeleteEnum"),
                  null)
              .block();
      DataTypeDeleteResult deleted = assertInstanceOf(DataTypeDeleteResult.class, deletedRaw);
      assertEquals("TempDeleteEnum", deleted.getDeletedType());

      DataType afterDelete =
          fixture
              .program()
              .getDataTypeManager()
              .getDataType(new CategoryPath("/"), "TempDeleteEnum");
      assertNull(afterDelete);
    } finally {
      fixture.close();
    }
  }

  @Test
  void deleteBookmarkRemovesMatchingBookmarkAndProgramState() throws Exception {
    assumeTrue(
        Boolean.getBoolean("e2e.integration"), "Set -De2e.integration=true to run e2e tests");

    InMemoryProgramFixtureSupport.ProgramFixture fixture =
        InMemoryProgramFixtureSupport.createReadAndManageFixtureProgram();
    try {
      AnnotateTool manageTool = new InMemoryAnnotateTool(fixture.program());
      DeleteTool deleteTool = new InMemoryDeleteTool(fixture.program());

      Object createdRaw =
          manageTool
              .execute(
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
                      "E2E_DELETE",
                      "comment",
                      "bookmark slated for deletion"),
                  null)
              .block();
      OperationResult created = assertInstanceOf(OperationResult.class, createdRaw);

      Object deletedRaw =
          deleteTool
              .execute(
                  null,
                  Map.of(
                      "file_name",
                      "fixture",
                      "action",
                      "bookmark",
                      "address",
                      "0x401020",
                      "bookmark_type",
                      "Note",
                      "bookmark_category",
                      "E2E_DELETE",
                      "comment_contains",
                      "slated"),
                  null)
              .block();
      OperationResult deleted = assertInstanceOf(OperationResult.class, deletedRaw);
      assertEquals("delete_bookmark", deleted.getOperation());
      assertEquals(1, deleted.getMetadata().get("deleted_count"));

      Address bookmarkAddress = fixture.program().getAddressFactory().getAddress("0x401020");
      Bookmark[] bookmarks = fixture.program().getBookmarkManager().getBookmarks(bookmarkAddress);
      assertTrue(
          Arrays.stream(bookmarks)
              .noneMatch(
                  bookmark ->
                      "Note".equals(bookmark.getTypeString())
                          && "E2E_DELETE".equals(bookmark.getCategory())
                          && "bookmark slated for deletion".equals(bookmark.getComment())));
    } finally {
      fixture.close();
    }
  }

  @GhidraMcpTool(
      name = "Functions Test",
      description = "In-memory functions test wrapper",
      mcpName = "manage_functions",
      mcpDescription = "In-memory wrapper for manage_functions")
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
      name = "Delete Test",
      description = "In-memory delete test wrapper",
      mcpName = "delete",
      destructiveHint = true,
      mcpDescription = "In-memory wrapper for delete")
  private static final class InMemoryDeleteTool extends DeleteTool {
    private final Program program;

    InMemoryDeleteTool(Program program) {
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
      name = "Annotate Test",
      description = "In-memory annotate test wrapper",
      mcpName = "annotate",
      mcpDescription = "In-memory wrapper for annotate")
  private static final class InMemoryAnnotateTool extends AnnotateTool {
    private final Program program;

    InMemoryAnnotateTool(Program program) {
      this.program = program;
    }

    @Override
    protected Mono<Program> getProgram(
        Map<String, Object> args, ghidra.framework.plugintool.PluginTool tool) {
      return Mono.just(program);
    }
  }
}
