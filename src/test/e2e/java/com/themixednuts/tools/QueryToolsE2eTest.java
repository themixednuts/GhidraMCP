package com.themixednuts.tools;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.models.FunctionInfo;
import com.themixednuts.models.FunctionListEntry;
import com.themixednuts.models.MemoryBlockInfo;
import com.themixednuts.models.MemoryReadResult;
import com.themixednuts.models.SymbolInfo;
import com.themixednuts.models.SymbolListEntry;
import com.themixednuts.utils.CursorDataResult;
import com.themixednuts.utils.PaginatedResult;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import java.util.Map;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;

class QueryToolsE2eTest {

  @Test
  void readFunctionsSupportsListingPaginationAndSingleLookup() throws Exception {
    assumeTrue(
        Boolean.getBoolean("e2e.integration"), "Set -De2e.integration=true to run e2e tests");

    InMemoryProgramFixtureSupport.ProgramFixture fixture =
        InMemoryProgramFixtureSupport.createReadAndManageFixtureProgram();
    try {
      FunctionsTool tool = new InMemoryFunctionsTool(fixture.program());

      Object firstPageRaw =
          tool.execute(null, Map.of("file_name", "fixture", "action", "list", "page_size", 1), null)
              .block();
      @SuppressWarnings("unchecked")
      PaginatedResult<FunctionListEntry> firstPage =
          assertInstanceOf(PaginatedResult.class, firstPageRaw);

      assertEquals(1, firstPage.results.size());
      assertNotNull(firstPage.nextCursor);

      Object secondPageRaw =
          tool.execute(
                  null,
                  Map.of(
                      "file_name",
                      "fixture",
                      "action",
                      "list",
                      "page_size",
                      1,
                      "cursor",
                      firstPage.nextCursor),
                  null)
              .block();
      @SuppressWarnings("unchecked")
      PaginatedResult<FunctionListEntry> secondPage =
          assertInstanceOf(PaginatedResult.class, secondPageRaw);
      assertFalse(secondPage.results.isEmpty());

      FunctionListEntry firstFunction = firstPage.results.get(0);
      assertNotNull(firstFunction.getSymbolId());
      assertEquals(null, firstFunction.getSignature());

      Object verbosePageRaw =
          tool.execute(
                  null,
                  Map.of("file_name", "fixture", "action", "list", "page_size", 1, "verbose", true),
                  null)
              .block();
      @SuppressWarnings("unchecked")
      PaginatedResult<FunctionListEntry> verbosePage =
          assertInstanceOf(PaginatedResult.class, verbosePageRaw);
      assertFalse(verbosePage.results.isEmpty());
      assertNotNull(verbosePage.results.get(0).getSignature());

      Object singleRaw =
          tool.execute(
                  null,
                  Map.of(
                      "file_name",
                      "fixture",
                      "action",
                      "get",
                      "address",
                      firstFunction.getEntryPoint()),
                  null)
              .block();
      FunctionInfo singleResult = assertInstanceOf(FunctionInfo.class, singleRaw);
      assertEquals(firstFunction.getEntryPoint(), singleResult.getEntryPoint());
    } finally {
      fixture.close();
    }
  }

  @Test
  void readSymbolsSupportsSingleLookupAndFilteredListing() throws Exception {
    assumeTrue(
        Boolean.getBoolean("e2e.integration"), "Set -De2e.integration=true to run e2e tests");

    InMemoryProgramFixtureSupport.ProgramFixture fixture =
        InMemoryProgramFixtureSupport.createReadAndManageFixtureProgram();
    try {
      SymbolsTool tool = new InMemorySymbolsTool(fixture.program());

      Object singleRaw =
          tool.execute(
                  null, Map.of("file_name", "fixture", "action", "get", "name", "entry_main"), null)
              .block();
      SymbolInfo singleResult = assertInstanceOf(SymbolInfo.class, singleRaw);
      assertEquals("entry_main", singleResult.getName());

      Object listRaw =
          tool.execute(
                  null,
                  Map.of(
                      "file_name",
                      "fixture",
                      "action",
                      "list",
                      "name_pattern",
                      "entry_.*",
                      "page_size",
                      1),
                  null)
              .block();
      @SuppressWarnings("unchecked")
      PaginatedResult<SymbolListEntry> listed = assertInstanceOf(PaginatedResult.class, listRaw);

      assertEquals(1, listed.results.size());
      assertNotNull(listed.nextCursor);
      assertTrue(listed.results.stream().anyMatch(symbol -> symbol.getName().startsWith("entry_")));
      assertTrue(listed.results.stream().allMatch(symbol -> symbol.getSymbolId() != 0));

      Object secondListRaw =
          tool.execute(
                  null,
                  Map.of(
                      "file_name",
                      "fixture",
                      "action",
                      "list",
                      "name_pattern",
                      "entry_.*",
                      "page_size",
                      1,
                      "cursor",
                      listed.nextCursor),
                  null)
              .block();
      @SuppressWarnings("unchecked")
      PaginatedResult<SymbolListEntry> secondListed =
          assertInstanceOf(PaginatedResult.class, secondListRaw);
      assertFalse(secondListed.results.isEmpty());
    } finally {
      fixture.close();
    }
  }

  @Test
  void readListingReturnsInstructionRowsForAddressRange() throws Exception {
    assumeTrue(
        Boolean.getBoolean("e2e.integration"), "Set -De2e.integration=true to run e2e tests");

    InMemoryProgramFixtureSupport.ProgramFixture fixture =
        InMemoryProgramFixtureSupport.createReadAndManageFixtureProgram();
    try {
      InspectTool tool = new InMemoryInspectTool(fixture.program());

      Object raw =
          tool.execute(
                  null,
                  Map.of(
                      "file_name",
                      "fixture",
                      "action",
                      "listing",
                      "address",
                      "0x401000",
                      "end_address",
                      "0x401030",
                      "max_lines",
                      25),
                  null)
              .block();
      @SuppressWarnings("unchecked")
      CursorDataResult<String> result = assertInstanceOf(CursorDataResult.class, raw);

      assertNotNull(result.data);
      assertFalse(result.data.isBlank());
      assertTrue(
          result.data.lines().anyMatch(line -> line.contains("55") && line.contains("PUSH")),
          "Expected listing text to include PUSH instruction bytes and mnemonic");
      assertTrue(
          result.data.lines().anyMatch(line -> line.contains("48 89 e5") && line.contains("MOV")),
          "Expected listing text to include MOV instruction bytes and mnemonic");
    } finally {
      fixture.close();
    }
  }

  @Test
  void readListingSupportsFunctionSelectorAsAddress() throws Exception {
    assumeTrue(
        Boolean.getBoolean("e2e.integration"), "Set -De2e.integration=true to run e2e tests");

    InMemoryProgramFixtureSupport.ProgramFixture fixture =
        InMemoryProgramFixtureSupport.createReadAndManageFixtureProgram();
    try {
      InspectTool tool = new InMemoryInspectTool(fixture.program());

      Object raw =
          tool.execute(
                  null,
                  Map.of(
                      "file_name", "fixture",
                      "action", "listing",
                      "name", "0x401000",
                      "max_lines", 10),
                  null)
              .block();

      @SuppressWarnings("unchecked")
      CursorDataResult<String> result = assertInstanceOf(CursorDataResult.class, raw);
      assertNotNull(result.data);
      assertFalse(result.data.isBlank());
      assertTrue(result.data.lines().findFirst().isPresent());
    } finally {
      fixture.close();
    }
  }

  @Test
  void memoryToolListBlocksSupportsPermissionAndNameFilters() throws Exception {
    assumeTrue(
        Boolean.getBoolean("e2e.integration"), "Set -De2e.integration=true to run e2e tests");

    InMemoryProgramFixtureSupport.ProgramFixture fixture =
        InMemoryProgramFixtureSupport.createReadAndManageFixtureProgram();
    try {
      MemoryTool tool = new InMemoryMemoryTool(fixture.program());

      Object raw =
          tool.execute(
                  null,
                  Map.of(
                      "file_name", "fixture",
                      "action", "list_blocks",
                      "name_filter", ".text",
                      "executable", true),
                  null)
              .block();
      @SuppressWarnings("unchecked")
      PaginatedResult<MemoryBlockInfo> result = assertInstanceOf(PaginatedResult.class, raw);

      assertFalse(result.results.isEmpty());
      MemoryBlockInfo first = result.results.get(0);
      assertTrue(first.getName().contains(".text"));
      assertTrue(first.isExecute());
      String blockJson = BaseMcpTool.mapper.writeValueAsString(first);
      assertTrue(blockJson.contains("\"permissions\""), blockJson);
      assertFalse(blockJson.contains("\"execute\""), blockJson);
    } finally {
      fixture.close();
    }
  }

  @Test
  void queryToolsAcceptImageBaseRelativeAddressOffsets() throws Exception {
    assumeTrue(
        Boolean.getBoolean("e2e.integration"), "Set -De2e.integration=true to run e2e tests");

    InMemoryProgramFixtureSupport.ProgramFixture fixture =
        InMemoryProgramFixtureSupport.createReadAndManageFixtureProgram();
    try {
      Program program = fixture.program();
      FunctionsTool functions = new InMemoryFunctionsTool(program);
      InspectTool inspect = new InMemoryInspectTool(program);
      MemoryTool memory = new InMemoryMemoryTool(program);

      String entryOffset = imageBaseOffset(program, "0x401000");
      Address entryAddress = program.getAddressFactory().getAddress("0x401000");

      Object functionRaw =
          functions
              .execute(
                  null,
                  Map.of("file_name", "fixture", "action", "get", "address", entryOffset),
                  null)
              .block();
      FunctionInfo functionResult = assertInstanceOf(FunctionInfo.class, functionRaw);
      assertEquals(entryAddress.toString(), functionResult.getEntryPoint());

      Object listingRaw =
          inspect
              .execute(
                  null,
                  Map.of(
                      "file_name",
                      "fixture",
                      "action",
                      "listing",
                      "address",
                      entryOffset,
                      "end_address",
                      imageBaseOffset(program, "0x401030"),
                      "max_lines",
                      10),
                  null)
              .block();
      @SuppressWarnings("unchecked")
      CursorDataResult<String> listingResult = assertInstanceOf(CursorDataResult.class, listingRaw);
      assertTrue(listingResult.data.lines().anyMatch(line -> line.contains("PUSH")));

      Address dataAddress = program.getAddressFactory().getAddress("0x402000");
      Object memoryRaw =
          memory
              .execute(
                  null,
                  Map.of(
                      "file_name",
                      "fixture",
                      "action",
                      "read",
                      "address",
                      imageBaseOffset(program, "0x402000"),
                      "length",
                      4),
                  null)
              .block();
      MemoryReadResult memoryResult = assertInstanceOf(MemoryReadResult.class, memoryRaw);
      assertEquals(dataAddress.toString(), memoryResult.getAddress());
      assertEquals(4, memoryResult.getBytesRead());
    } finally {
      fixture.close();
    }
  }

  private static String imageBaseOffset(Program program, String absoluteAddress) {
    Address address = program.getAddressFactory().getAddress(absoluteAddress);
    long offset = address.subtract(program.getImageBase());
    return "+0x" + Long.toHexString(offset);
  }

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

  @GhidraMcpTool(
      name = "Inspect Test",
      description = "In-memory inspect test wrapper",
      mcpName = "inspect",
      mcpDescription = "In-memory wrapper for inspect")
  private static final class InMemoryInspectTool extends InspectTool {
    private final Program program;

    InMemoryInspectTool(Program program) {
      this.program = program;
    }

    @Override
    protected Mono<Program> getProgram(
        Map<String, Object> args, ghidra.framework.plugintool.PluginTool tool) {
      return Mono.just(program);
    }
  }

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
}
