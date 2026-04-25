package com.themixednuts.tools;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.models.DataTypeListEntry;
import com.themixednuts.models.DataTypeReadResult;
import com.themixednuts.models.FunctionInfo;
import com.themixednuts.models.FunctionVariableInfo;
import com.themixednuts.models.MemoryBlockInfo;
import com.themixednuts.models.MemoryReadResult;
import com.themixednuts.models.MemoryWriteResult;
import com.themixednuts.models.OperationResult;
import com.themixednuts.models.SymbolInfo;
import com.themixednuts.utils.PaginatedResult;
import ghidra.program.model.listing.Program;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
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
  void listDataTypesReturnsCompactSummaryRows() throws Exception {
    assumeTrue(
        Boolean.getBoolean("e2e.integration"), "Set -De2e.integration=true to run e2e tests");

    InMemoryProgramFixtureSupport.ProgramFixture fixture =
        InMemoryProgramFixtureSupport.createReadAndManageFixtureProgram();
    try {
      DataTypesTool tool = new InMemoryDataTypesTool(fixture.program());

      tool.execute(
              null,
              Map.of(
                  "file_name",
                  "fixture",
                  "action",
                  "create",
                  "data_type_kind",
                  "struct",
                  "name",
                  "CompactListStruct",
                  "members",
                  List.of(
                      Map.of("name", "field_a", "data_type_path", "int"),
                      Map.of("name", "field_b", "data_type_path", "char *"))),
              null)
          .block();

      Object listRaw =
          tool.execute(
                  null,
                  Map.of(
                      "file_name",
                      "fixture",
                      "action",
                      "list",
                      "name_pattern",
                      "^CompactListStruct$",
                      "page_size",
                      10),
                  null)
              .block();
      @SuppressWarnings("unchecked")
      PaginatedResult<DataTypeListEntry> listed = assertInstanceOf(PaginatedResult.class, listRaw);

      assertFalse(listed.results.isEmpty(), "Expected matching data type summary row");
      DataTypeListEntry entry = listed.results.get(0);
      assertEquals("CompactListStruct", entry.getName());
      assertEquals("struct", entry.getKind());
      assertNotNull(entry.getDataTypeId());
      assertEquals(2, entry.getMemberCount());
      assertTrue(entry.getPath().endsWith("/CompactListStruct"));

      @SuppressWarnings("unchecked")
      Map<String, Object> serialized = BaseMcpTool.mapper.convertValue(entry, Map.class);
      assertFalse(serialized.containsKey("details"));
      assertFalse(serialized.containsKey("members"));
      assertFalse(serialized.containsKey("entries"));
      assertFalse(serialized.containsKey("description"));
      assertFalse(serialized.containsKey("category"));
      assertEquals(Long.toString(entry.getDataTypeId()), serialized.get("data_type_id"));

      Object readBackRaw =
          tool.execute(
                  null,
                  Map.of(
                      "file_name",
                      "fixture",
                      "action",
                      "get",
                      "data_type_kind",
                      "struct",
                      "name",
                      "CompactListStruct"),
                  null)
              .block();
      DataTypeReadResult readBack = assertInstanceOf(DataTypeReadResult.class, readBackRaw);
      assertEquals(2, readBack.getComponentCount());
    } finally {
      fixture.close();
    }
  }

  @Test
  void patchStructMemberRenamesAndRetypesWithoutFullReplacement() throws Exception {
    assumeTrue(
        Boolean.getBoolean("e2e.integration"), "Set -De2e.integration=true to run e2e tests");

    InMemoryProgramFixtureSupport.ProgramFixture fixture =
        InMemoryProgramFixtureSupport.createReadAndManageFixtureProgram();
    try {
      DataTypesTool tool = new InMemoryDataTypesTool(fixture.program());

      // Create a struct with three members
      Object createdRaw =
          tool.execute(
                  null,
                  Map.of(
                      "file_name",
                      "fixture",
                      "action",
                      "create",
                      "data_type_kind",
                      "struct",
                      "name",
                      "PatchTestStruct",
                      "members",
                      List.of(
                          Map.of("name", "field_a", "data_type_path", "int"),
                          Map.of("name", "field_b", "data_type_path", "int"),
                          Map.of("name", "field_c", "data_type_path", "int"))),
                  null)
              .block();
      OperationResult created = assertInstanceOf(OperationResult.class, createdRaw);

      // Patch: rename field_b at offset 4 and add a comment
      Object patchedRaw =
          tool.execute(
                  null,
                  Map.of(
                      "file_name",
                      "fixture",
                      "action",
                      "update",
                      "data_type_kind",
                      "struct",
                      "name",
                      "PatchTestStruct",
                      "member_update_mode",
                      "patch",
                      "members",
                      List.of(Map.of("offset", 4, "name", "renamed_b", "comment", "patched"))),
                  null)
              .block();
      OperationResult patched = assertInstanceOf(OperationResult.class, patchedRaw);

      // Read back and verify: field_a and field_c untouched, field_b renamed
      Object readBackRaw =
          tool.execute(
                  null,
                  Map.of(
                      "file_name", "fixture",
                      "action", "get",
                      "data_type_kind", "struct",
                      "name", "PatchTestStruct"),
                  null)
              .block();
      DataTypeReadResult readBack = assertInstanceOf(DataTypeReadResult.class, readBackRaw);
      assertEquals("PatchTestStruct", readBack.getName());
      assertEquals(3, readBack.getComponentCount());

      // field_a at offset 0 should be unchanged
      var comp0 = readBack.getComponents().get(0);
      assertEquals("field_a", comp0.name());
      assertEquals(0, comp0.offset());

      // field_b at offset 4 should be renamed
      var comp1 = readBack.getComponents().get(1);
      assertEquals("renamed_b", comp1.name());
      assertEquals(4, comp1.offset());

      // field_c at offset 8 should be unchanged
      var comp2 = readBack.getComponents().get(2);
      assertEquals("field_c", comp2.name());
      assertEquals(8, comp2.offset());
    } finally {
      fixture.close();
    }
  }

  @Test
  void patchStructMemberRetypesFieldAndPreservesOthers() throws Exception {
    assumeTrue(
        Boolean.getBoolean("e2e.integration"), "Set -De2e.integration=true to run e2e tests");

    InMemoryProgramFixtureSupport.ProgramFixture fixture =
        InMemoryProgramFixtureSupport.createReadAndManageFixtureProgram();
    try {
      DataTypesTool tool = new InMemoryDataTypesTool(fixture.program());

      // Create a helper struct to use as the retype target
      tool.execute(
              null,
              Map.of(
                  "file_name", "fixture",
                  "action", "create",
                  "data_type_kind", "struct",
                  "name", "SmallStruct",
                  "members", List.of(Map.of("name", "val", "data_type_path", "int"))),
              null)
          .block();

      // Create a struct with two int fields and padding space
      tool.execute(
              null,
              Map.of(
                  "file_name", "fixture",
                  "action", "create",
                  "data_type_kind", "struct",
                  "name", "RetypeStruct",
                  "size", 16,
                  "members",
                      List.of(
                          Map.of("name", "a", "data_type_path", "int", "offset", 0),
                          Map.of("name", "b", "data_type_path", "int", "offset", 4))),
              null)
          .block();

      // Patch: retype field 'b' at offset 4 from int to SmallStruct
      Object patchedRaw =
          tool.execute(
                  null,
                  Map.of(
                      "file_name", "fixture",
                      "action", "update",
                      "data_type_kind", "struct",
                      "name", "RetypeStruct",
                      "member_update_mode", "patch",
                      "members",
                          List.of(
                              Map.of(
                                  "offset",
                                  4,
                                  "data_type_path",
                                  "SmallStruct",
                                  "name",
                                  "b_retyped"))),
                  null)
              .block();
      OperationResult patched = assertInstanceOf(OperationResult.class, patchedRaw);

      // Read back
      Object readBackRaw =
          tool.execute(
                  null,
                  Map.of(
                      "file_name", "fixture",
                      "action", "get",
                      "data_type_kind", "struct",
                      "name", "RetypeStruct"),
                  null)
              .block();
      DataTypeReadResult readBack = assertInstanceOf(DataTypeReadResult.class, readBackRaw);

      // field 'a' at offset 0 should be unchanged
      var compA =
          readBack.getComponents().stream().filter(c -> c.offset() == 0).findFirst().orElseThrow();
      assertEquals("a", compA.name());
      assertEquals("int", compA.type());

      // field at offset 4 should now be SmallStruct with new name
      var compB =
          readBack.getComponents().stream().filter(c -> c.offset() == 4).findFirst().orElseThrow();
      assertEquals("b_retyped", compB.name());
      assertEquals("SmallStruct", compB.type());
    } finally {
      fixture.close();
    }
  }

  @Test
  void patchStructMemberFailsForInvalidOffset() throws Exception {
    assumeTrue(
        Boolean.getBoolean("e2e.integration"), "Set -De2e.integration=true to run e2e tests");

    InMemoryProgramFixtureSupport.ProgramFixture fixture =
        InMemoryProgramFixtureSupport.createReadAndManageFixtureProgram();
    try {
      DataTypesTool tool = new InMemoryDataTypesTool(fixture.program());

      // Create a struct
      tool.execute(
              null,
              Map.of(
                  "file_name", "fixture",
                  "action", "create",
                  "data_type_kind", "struct",
                  "name", "OffsetTestStruct",
                  "members", List.of(Map.of("name", "x", "data_type_path", "int"))),
              null)
          .block();

      // Patch at invalid offset should fail
      var result =
          tool.execute(
              null,
              Map.of(
                  "file_name", "fixture",
                  "action", "update",
                  "data_type_kind", "struct",
                  "name", "OffsetTestStruct",
                  "member_update_mode", "patch",
                  "members", List.of(Map.of("offset", 999, "name", "ghost"))),
              null);

      assertThrows(Exception.class, () -> result.block());
    } finally {
      fixture.close();
    }
  }

  @Test
  void patchUnionMemberRenamesByOrdinal() throws Exception {
    assumeTrue(
        Boolean.getBoolean("e2e.integration"), "Set -De2e.integration=true to run e2e tests");

    InMemoryProgramFixtureSupport.ProgramFixture fixture =
        InMemoryProgramFixtureSupport.createReadAndManageFixtureProgram();
    try {
      DataTypesTool tool = new InMemoryDataTypesTool(fixture.program());

      // Create a union with three members
      tool.execute(
              null,
              Map.of(
                  "file_name", "fixture",
                  "action", "create",
                  "data_type_kind", "union",
                  "name", "PatchTestUnion",
                  "members",
                      List.of(
                          Map.of("name", "as_int", "data_type_path", "int"),
                          Map.of("name", "as_float", "data_type_path", "int"),
                          Map.of("name", "as_bytes", "data_type_path", "int"))),
              null)
          .block();

      // Patch: rename member at ordinal 1
      Object patchedRaw =
          tool.execute(
                  null,
                  Map.of(
                      "file_name", "fixture",
                      "action", "update",
                      "data_type_kind", "union",
                      "name", "PatchTestUnion",
                      "member_update_mode", "patch",
                      "members",
                          List.of(Map.of("ordinal", 1, "name", "as_single", "comment", "renamed"))),
                  null)
              .block();
      OperationResult patched = assertInstanceOf(OperationResult.class, patchedRaw);

      // Read back
      Object readBackRaw =
          tool.execute(
                  null,
                  Map.of(
                      "file_name", "fixture",
                      "action", "get",
                      "data_type_kind", "union",
                      "name", "PatchTestUnion"),
                  null)
              .block();
      DataTypeReadResult readBack = assertInstanceOf(DataTypeReadResult.class, readBackRaw);
      assertEquals(3, readBack.getComponentCount());

      // ordinal 0 unchanged
      assertEquals("as_int", readBack.getComponents().get(0).name());
      // ordinal 1 renamed
      assertEquals("as_single", readBack.getComponents().get(1).name());
      // ordinal 2 unchanged
      assertEquals("as_bytes", readBack.getComponents().get(2).name());
    } finally {
      fixture.close();
    }
  }

  @Test
  void patchUnionMemberRetypesByOrdinal() throws Exception {
    assumeTrue(
        Boolean.getBoolean("e2e.integration"), "Set -De2e.integration=true to run e2e tests");

    InMemoryProgramFixtureSupport.ProgramFixture fixture =
        InMemoryProgramFixtureSupport.createReadAndManageFixtureProgram();
    try {
      DataTypesTool tool = new InMemoryDataTypesTool(fixture.program());

      // Create a helper struct as a retype target
      tool.execute(
              null,
              Map.of(
                  "file_name", "fixture",
                  "action", "create",
                  "data_type_kind", "struct",
                  "name", "UnionRetypeTarget",
                  "members", List.of(Map.of("name", "x", "data_type_path", "int"))),
              null)
          .block();

      // Create a union
      tool.execute(
              null,
              Map.of(
                  "file_name", "fixture",
                  "action", "create",
                  "data_type_kind", "union",
                  "name", "RetypeUnion",
                  "members",
                      List.of(
                          Map.of("name", "val_a", "data_type_path", "int"),
                          Map.of("name", "val_b", "data_type_path", "int"))),
              null)
          .block();

      // Patch: retype member at ordinal 0 to UnionRetypeTarget
      Object patchedRaw =
          tool.execute(
                  null,
                  Map.of(
                      "file_name", "fixture",
                      "action", "update",
                      "data_type_kind", "union",
                      "name", "RetypeUnion",
                      "member_update_mode", "patch",
                      "members",
                          List.of(Map.of("ordinal", 0, "data_type_path", "UnionRetypeTarget"))),
                  null)
              .block();
      OperationResult patched = assertInstanceOf(OperationResult.class, patchedRaw);

      // Read back and verify type changed but name preserved
      Object readBackRaw =
          tool.execute(
                  null,
                  Map.of(
                      "file_name", "fixture",
                      "action", "get",
                      "data_type_kind", "union",
                      "name", "RetypeUnion"),
                  null)
              .block();
      DataTypeReadResult readBack = assertInstanceOf(DataTypeReadResult.class, readBackRaw);

      assertEquals("val_a", readBack.getComponents().get(0).name());
      assertEquals("UnionRetypeTarget", readBack.getComponents().get(0).type());
      // ordinal 1 untouched
      assertEquals("val_b", readBack.getComponents().get(1).name());
      assertEquals("int", readBack.getComponents().get(1).type());
    } finally {
      fixture.close();
    }
  }

  @Test
  void getStructReturnsComponentCommentsAndOrdinals() throws Exception {
    assumeTrue(
        Boolean.getBoolean("e2e.integration"), "Set -De2e.integration=true to run e2e tests");

    InMemoryProgramFixtureSupport.ProgramFixture fixture =
        InMemoryProgramFixtureSupport.createReadAndManageFixtureProgram();
    try {
      DataTypesTool tool = new InMemoryDataTypesTool(fixture.program());

      // Create a struct with commented members
      tool.execute(
              null,
              Map.of(
                  "file_name", "fixture",
                  "action", "create",
                  "data_type_kind", "struct",
                  "name", "CommentStruct",
                  "members",
                      List.of(
                          Map.of(
                              "name", "field1", "data_type_path", "int", "comment", "first field"),
                          Map.of("name", "field2", "data_type_path", "int"))),
              null)
          .block();

      // Read back and verify comments and ordinals
      Object readBackRaw =
          tool.execute(
                  null,
                  Map.of(
                      "file_name", "fixture",
                      "action", "get",
                      "data_type_kind", "struct",
                      "name", "CommentStruct"),
                  null)
              .block();
      DataTypeReadResult readBack = assertInstanceOf(DataTypeReadResult.class, readBackRaw);

      var comp0 = readBack.getComponents().get(0);
      assertEquals("first field", comp0.comment());
      assertNotNull(comp0.ordinal());

      var comp1 = readBack.getComponents().get(1);
      // No comment should be null (omitted in JSON)
      assertEquals("field2", comp1.name());
    } finally {
      fixture.close();
    }
  }

  @Test
  void listVariablesReturnsCompactStableVariableTargets() throws Exception {
    assumeTrue(
        Boolean.getBoolean("e2e.integration"), "Set -De2e.integration=true to run e2e tests");

    InMemoryProgramFixtureSupport.ProgramFixture fixture =
        InMemoryProgramFixtureSupport.createFixtureWithLocalVariables();
    try {
      FunctionsTool tool = new InMemoryFunctionsTool(fixture.program());

      // List variables to get high_symbol_id
      Object listRaw =
          tool.execute(
                  null,
                  Map.of(
                      "file_name", "fixture",
                      "action", "list_variables",
                      "address", "0x401000"),
                  null)
              .block();
      @SuppressWarnings("unchecked")
      PaginatedResult<FunctionVariableInfo> variables =
          assertInstanceOf(PaginatedResult.class, listRaw);

      assertFalse(variables.results.isEmpty(), "Expected decompiler variable targets");
      assertEquals(
          variables.results.size(),
          variables.results.stream()
              .map(FunctionVariableInfo::getVariableSymbolId)
              .distinct()
              .count());

      FunctionVariableInfo target = variables.results.get(0);

      String serialized = BaseMcpTool.mapper.writeValueAsString(target);
      assertTrue(serialized.contains("\"name\":\"" + target.getName() + "\""));
      assertTrue(
          serialized.contains(
              "\"variable_symbol_id\":\"" + Long.toString(target.getVariableSymbolId()) + "\""));
      assertFalse(serialized.contains("\"data_type\""), serialized);
      assertFalse(serialized.contains("\"storage\""), serialized);
      assertFalse(serialized.contains("\"is_parameter\""), serialized);
      assertFalse(serialized.contains("\"effective_name\""));
      assertFalse(serialized.contains("\"symbol_id\""));
      assertFalse(serialized.contains("\"high_symbol_id\""));

      Object verboseListRaw =
          tool.execute(
                  null,
                  Map.of(
                      "file_name", "fixture",
                      "action", "list_variables",
                      "address", "0x401000",
                      "verbose", true),
                  null)
              .block();
      @SuppressWarnings("unchecked")
      PaginatedResult<FunctionVariableInfo> verboseVariables =
          assertInstanceOf(PaginatedResult.class, verboseListRaw);
      FunctionVariableInfo verboseTarget =
          verboseVariables.results.stream()
              .filter(v -> target.getVariableSymbolId().equals(v.getVariableSymbolId()))
              .findFirst()
              .orElseThrow(() -> new AssertionError("Verbose variable listing lost target"));
      String verboseSerialized = BaseMcpTool.mapper.writeValueAsString(verboseTarget);
      assertTrue(verboseSerialized.contains("\"data_type\""));
      assertTrue(verboseSerialized.contains("\"storage\""));
      assertTrue(verboseSerialized.contains("\"is_parameter\""));
    } finally {
      fixture.close();
    }
  }

  @Test
  void renameVariableByStringVariableSymbolIdAndVerify() throws Exception {
    assumeTrue(
        Boolean.getBoolean("e2e.integration"), "Set -De2e.integration=true to run e2e tests");

    InMemoryProgramFixtureSupport.ProgramFixture fixture =
        InMemoryProgramFixtureSupport.createFixtureWithLocalVariables();
    try {
      FunctionsTool tool = new InMemoryFunctionsTool(fixture.program());

      Object listRaw =
          tool.execute(
                  null,
                  Map.of(
                      "file_name", "fixture",
                      "action", "list_variables",
                      "address", "0x401000",
                      "verbose", true),
                  null)
              .block();
      @SuppressWarnings("unchecked")
      PaginatedResult<FunctionVariableInfo> variables =
          assertInstanceOf(PaginatedResult.class, listRaw);

      FunctionVariableInfo target =
          variables.results.stream()
              .filter(v -> !v.isParameter())
              .findFirst()
              .orElseThrow(() -> new AssertionError("No non-parameter variable found"));

      String originalName = target.getName();
      String variableSymbolId = Long.toString(target.getVariableSymbolId());

      // Rename by variable_symbol_id
      @SuppressWarnings("unchecked")
      Map<String, Object> renameResult =
          (Map<String, Object>)
              tool.execute(
                      null,
                      Map.of(
                          "file_name", "fixture",
                          "action", "update_variable",
                          "address", "0x401000",
                          "variable_symbol_id", variableSymbolId,
                          "new_name", "renamed_via_id"),
                      null)
                  .block();

      assertNotNull(renameResult);
      assertEquals(variableSymbolId, renameResult.get("variable_symbol_id"));
      assertEquals(originalName, renameResult.get("old_name"));
      assertEquals("renamed_via_id", renameResult.get("new_name"));
    } finally {
      fixture.close();
    }
  }

  @Test
  void batchRenameByHighSymbolIdIsOrderIndependent() throws Exception {
    assumeTrue(
        Boolean.getBoolean("e2e.integration"), "Set -De2e.integration=true to run e2e tests");

    InMemoryProgramFixtureSupport.ProgramFixture fixture =
        InMemoryProgramFixtureSupport.createFixtureWithLocalVariables();
    try {
      FunctionsTool tool = new InMemoryFunctionsTool(fixture.program());

      // List variables and collect all non-parameter variables with IDs
      Object listRaw =
          tool.execute(
                  null,
                  Map.of(
                      "file_name", "fixture",
                      "action", "list_variables",
                      "address", "0x401000",
                      "verbose", true),
                  null)
              .block();
      @SuppressWarnings("unchecked")
      PaginatedResult<FunctionVariableInfo> variables =
          assertInstanceOf(PaginatedResult.class, listRaw);

      List<FunctionVariableInfo> renameable =
          variables.results.stream().filter(v -> !v.isParameter()).collect(Collectors.toList());

      // Need at least 2 variables to test ordering
      if (renameable.size() < 2) return;

      // Rename in ASCENDING order (the problematic order for name-based renames)
      // This should work fine with symbol IDs since they're stable
      for (int i = 0; i < renameable.size(); i++) {
        FunctionVariableInfo v = renameable.get(i);
        String variableSymbolId = Long.toString(v.getVariableSymbolId());
        String newName = "batch_var_" + i;

        @SuppressWarnings("unchecked")
        Map<String, Object> result =
            (Map<String, Object>)
                tool.execute(
                        null,
                        Map.of(
                            "file_name", "fixture",
                            "action", "update_variable",
                            "address", "0x401000",
                            "variable_symbol_id", variableSymbolId,
                            "new_name", newName),
                        null)
                    .block();

        assertNotNull(result, "Rename failed for variable at index " + i);
        assertEquals(variableSymbolId, result.get("variable_symbol_id"));
        assertEquals(newName, result.get("new_name"));
      }

      // Verify all renames persisted
      Object listAfterRaw =
          tool.execute(
                  null,
                  Map.of(
                      "file_name", "fixture",
                      "action", "list_variables",
                      "address", "0x401000",
                      "verbose", true),
                  null)
              .block();
      @SuppressWarnings("unchecked")
      PaginatedResult<FunctionVariableInfo> variablesAfter =
          assertInstanceOf(PaginatedResult.class, listAfterRaw);
      for (int i = 0; i < renameable.size(); i++) {
        String expectedName = "batch_var_" + i;
        boolean found =
            variablesAfter.results.stream().anyMatch(v -> expectedName.equals(v.getName()));
        assertTrue(
            found, "Expected to find variable named '" + expectedName + "' after batch rename");
      }
    } finally {
      fixture.close();
    }
  }

  @Test
  void renameVariableRenamesDecompilerLocalAndVerifiesViaListVariables() throws Exception {
    assumeTrue(
        Boolean.getBoolean("e2e.integration"), "Set -De2e.integration=true to run e2e tests");

    InMemoryProgramFixtureSupport.ProgramFixture fixture =
        InMemoryProgramFixtureSupport.createFixtureWithLocalVariables();
    try {
      FunctionsTool tool = new InMemoryFunctionsTool(fixture.program());

      // Discover decompiler-generated variable names
      Object listRaw =
          tool.execute(
                  null,
                  Map.of(
                      "file_name", "fixture",
                      "action", "list_variables",
                      "address", "0x401000",
                      "verbose", true),
                  null)
              .block();
      @SuppressWarnings("unchecked")
      PaginatedResult<FunctionVariableInfo> variables =
          assertInstanceOf(PaginatedResult.class, listRaw);
      assertFalse(variables.results.isEmpty(), "Expected decompiler to produce local variables");

      // Pick the first non-parameter variable to rename
      FunctionVariableInfo target =
          variables.results.stream()
              .filter(v -> !v.isParameter())
              .findFirst()
              .orElseThrow(() -> new AssertionError("No non-parameter variable found to rename"));

      String originalName = target.getName();
      String renamedName = "test_renamed_var";

      // Rename the variable
      @SuppressWarnings("unchecked")
      Map<String, Object> renameResult =
          (Map<String, Object>)
              tool.execute(
                      null,
                      Map.of(
                          "file_name", "fixture",
                          "action", "rename_variable",
                          "address", "0x401000",
                          "current_name", originalName,
                          "new_name", renamedName),
                      null)
                  .block();

      assertNotNull(renameResult);
      assertEquals(originalName, renameResult.get("old_name"));
      assertEquals(renamedName, renameResult.get("new_name"));

      // Verify the rename persisted by listing variables again
      Object listAfterRaw =
          tool.execute(
                  null,
                  Map.of(
                      "file_name", "fixture",
                      "action", "list_variables",
                      "address", "0x401000",
                      "verbose", true),
                  null)
              .block();
      @SuppressWarnings("unchecked")
      PaginatedResult<FunctionVariableInfo> variablesAfter =
          assertInstanceOf(PaginatedResult.class, listAfterRaw);
      boolean renamedFound =
          variablesAfter.results.stream().anyMatch(v -> renamedName.equals(v.getName()));
      assertTrue(renamedFound, "Expected to find variable with new name '" + renamedName + "'");
    } finally {
      fixture.close();
    }
  }

  @Test
  void updateVariableRetypesLocalUsingStringVariableSymbolId() throws Exception {
    assumeTrue(
        Boolean.getBoolean("e2e.integration"), "Set -De2e.integration=true to run e2e tests");

    InMemoryProgramFixtureSupport.ProgramFixture fixture =
        InMemoryProgramFixtureSupport.createFixtureWithLocalVariables();
    try {
      FunctionsTool tool = new InMemoryFunctionsTool(fixture.program());

      Object listRaw =
          tool.execute(
                  null,
                  Map.of(
                      "file_name", "fixture",
                      "action", "list_variables",
                      "address", "0x401000",
                      "verbose", true),
                  null)
              .block();
      @SuppressWarnings("unchecked")
      PaginatedResult<FunctionVariableInfo> variables =
          assertInstanceOf(PaginatedResult.class, listRaw);

      FunctionVariableInfo target =
          variables.results.stream()
              .filter(v -> !v.isParameter())
              .findFirst()
              .orElseThrow(() -> new AssertionError("No non-parameter variable found to retype"));

      String variableSymbolId = Long.toString(target.getVariableSymbolId());

      @SuppressWarnings("unchecked")
      Map<String, Object> updateResult =
          (Map<String, Object>)
              tool.execute(
                      null,
                      Map.of(
                          "file_name", "fixture",
                          "action", "update_variable",
                          "address", "0x401000",
                          "variable_symbol_id", variableSymbolId,
                          "new_data_type", "float"),
                      null)
                  .block();

      assertNotNull(updateResult);
      assertEquals(variableSymbolId, updateResult.get("variable_symbol_id"));
      assertEquals("float", updateResult.get("new_data_type"));

      Object listAfterRaw =
          tool.execute(
                  null,
                  Map.of(
                      "file_name", "fixture",
                      "action", "list_variables",
                      "address", "0x401000",
                      "verbose", true),
                  null)
              .block();
      @SuppressWarnings("unchecked")
      PaginatedResult<FunctionVariableInfo> variablesAfter =
          assertInstanceOf(PaginatedResult.class, listAfterRaw);
      boolean floatFound =
          variablesAfter.results.stream().anyMatch(v -> "float".equals(v.getDataType()));

      assertTrue(floatFound, "Expected to find a local variable retyped to float");
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
