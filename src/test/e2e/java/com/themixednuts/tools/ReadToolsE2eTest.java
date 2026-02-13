package com.themixednuts.tools;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.themixednuts.models.FunctionInfo;
import com.themixednuts.models.ListingInfo;
import com.themixednuts.models.MemoryBlockInfo;
import com.themixednuts.models.SymbolInfo;
import com.themixednuts.utils.PaginatedResult;
import ghidra.program.model.listing.Program;
import java.util.Map;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;

class ReadToolsE2eTest {

  @Test
  void readFunctionsSupportsListingPaginationAndSingleLookup() throws Exception {
    assumeTrue(Boolean.getBoolean("e2e.integration"), "Set -De2e.integration=true to run e2e tests");

    InMemoryProgramFixtureSupport.ProgramFixture fixture =
        InMemoryProgramFixtureSupport.createReadAndManageFixtureProgram();
    try {
      ReadFunctionsTool tool = new InMemoryReadFunctionsTool(fixture.program());

      Object firstPageRaw =
          tool.execute(null, Map.of("file_name", "fixture", "page_size", 1), null).block();
      @SuppressWarnings("unchecked")
      PaginatedResult<FunctionInfo> firstPage =
          assertInstanceOf(PaginatedResult.class, firstPageRaw);

      assertEquals(1, firstPage.results.size());
      assertNotNull(firstPage.nextCursor);

      Object secondPageRaw =
          tool.execute(
                  null,
                  Map.of("file_name", "fixture", "page_size", 1, "cursor", firstPage.nextCursor),
                  null)
              .block();
      @SuppressWarnings("unchecked")
      PaginatedResult<FunctionInfo> secondPage =
          assertInstanceOf(PaginatedResult.class, secondPageRaw);
      assertFalse(secondPage.results.isEmpty());

      FunctionInfo firstFunction = firstPage.results.get(0);
      Object singleRaw =
          tool.execute(
                  null,
                  Map.of("file_name", "fixture", "address", firstFunction.getEntryPoint()),
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
    assumeTrue(Boolean.getBoolean("e2e.integration"), "Set -De2e.integration=true to run e2e tests");

    InMemoryProgramFixtureSupport.ProgramFixture fixture =
        InMemoryProgramFixtureSupport.createReadAndManageFixtureProgram();
    try {
      ReadSymbolsTool tool = new InMemoryReadSymbolsTool(fixture.program());

      Object singleRaw =
          tool.execute(null, Map.of("file_name", "fixture", "name", "entry_main"), null).block();
      SymbolInfo singleResult = assertInstanceOf(SymbolInfo.class, singleRaw);
      assertEquals("entry_main", singleResult.getName());

      Object listRaw =
          tool.execute(
                  null,
                  Map.of("file_name", "fixture", "name_filter", "entry_", "page_size", 10),
                  null)
              .block();
      @SuppressWarnings("unchecked")
      PaginatedResult<SymbolInfo> listed = assertInstanceOf(PaginatedResult.class, listRaw);

      assertFalse(listed.results.isEmpty());
      assertTrue(listed.results.stream().anyMatch(symbol -> symbol.getName().startsWith("entry_")));
    } finally {
      fixture.close();
    }
  }

  @Test
  void readListingReturnsInstructionRowsForAddressRange() throws Exception {
    assumeTrue(Boolean.getBoolean("e2e.integration"), "Set -De2e.integration=true to run e2e tests");

    InMemoryProgramFixtureSupport.ProgramFixture fixture =
        InMemoryProgramFixtureSupport.createReadAndManageFixtureProgram();
    try {
      ReadListingTool tool = new InMemoryReadListingTool(fixture.program());

      Object raw =
          tool.execute(
                  null,
                  Map.of(
                      "file_name",
                      "fixture",
                      "address",
                      "0x401000",
                      "end_address",
                      "0x401030",
                      "max_lines",
                      25),
                  null)
              .block();
      @SuppressWarnings("unchecked")
      PaginatedResult<ListingInfo> result = assertInstanceOf(PaginatedResult.class, raw);

      assertFalse(result.results.isEmpty());
      assertTrue(
          result.results.stream().anyMatch(item -> "instruction".equals(item.getType())),
          "Expected at least one instruction listing row");
    } finally {
      fixture.close();
    }
  }

  @Test
  void readMemoryBlocksSupportsPermissionAndNameFilters() throws Exception {
    assumeTrue(Boolean.getBoolean("e2e.integration"), "Set -De2e.integration=true to run e2e tests");

    InMemoryProgramFixtureSupport.ProgramFixture fixture =
        InMemoryProgramFixtureSupport.createReadAndManageFixtureProgram();
    try {
      ReadMemoryBlocksTool tool = new InMemoryReadMemoryBlocksTool(fixture.program());

      Object raw =
          tool.execute(
                  null,
                  Map.of("file_name", "fixture", "name_filter", ".text", "executable", true),
                  null)
              .block();
      @SuppressWarnings("unchecked")
      PaginatedResult<MemoryBlockInfo> result = assertInstanceOf(PaginatedResult.class, raw);

      assertFalse(result.results.isEmpty());
      MemoryBlockInfo first = result.results.get(0);
      assertTrue(first.getName().contains(".text"));
      assertTrue(first.isExecute());
    } finally {
      fixture.close();
    }
  }

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

  private static final class InMemoryReadListingTool extends ReadListingTool {
    private final Program program;

    InMemoryReadListingTool(Program program) {
      this.program = program;
    }

    @Override
    protected Mono<Program> getProgram(
        Map<String, Object> args, ghidra.framework.plugintool.PluginTool tool) {
      return Mono.just(program);
    }
  }

  private static final class InMemoryReadMemoryBlocksTool extends ReadMemoryBlocksTool {
    private final Program program;

    InMemoryReadMemoryBlocksTool(Program program) {
      this.program = program;
    }

    @Override
    protected Mono<Program> getProgram(
        Map<String, Object> args, ghidra.framework.plugintool.PluginTool tool) {
      return Mono.just(program);
    }
  }
}
