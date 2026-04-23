package com.themixednuts.tools;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.models.AnalysisOptionInfo;
import com.themixednuts.models.DecompilationResult;
import com.themixednuts.tools.MemoryTool.SearchResult;
import com.themixednuts.utils.CursorDataResult;
import com.themixednuts.utils.PaginatedResult;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;

class AnalysisToolsE2eTest {

  @Test
  void searchMemoryFindsKnownHexPatternAtExpectedAddresses() throws Exception {
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
                      "action", "search",
                      "search_type", "hex",
                      "search_value", "55 48 89 e5",
                      "page_size", 10),
                  null)
              .block();

      @SuppressWarnings("unchecked")
      PaginatedResult<SearchResult> result = assertInstanceOf(PaginatedResult.class, raw);

      assertFalse(result.results.isEmpty());
      assertTrue(result.results.stream().allMatch(match -> "hex".equals(match.getSearchType())));

      Set<String> addresses =
          result.results.stream()
              .map(SearchResult::getAddress)
              .map(String::toLowerCase)
              .collect(Collectors.toSet());
      assertTrue(addresses.stream().anyMatch(address -> address.contains("401000")));
      assertTrue(addresses.stream().anyMatch(address -> address.contains("401020")));
    } finally {
      fixture.close();
    }
  }

  @Test
  void findReferencesSupportsDirectionFilteringAndCursorPagination() throws Exception {
    assumeTrue(
        Boolean.getBoolean("e2e.integration"), "Set -De2e.integration=true to run e2e tests");

    InMemoryProgramFixtureSupport.ProgramFixture fixture =
        InMemoryProgramFixtureSupport.createReadAndManageFixtureProgram();
    try {
      Program program = fixture.program();
      addDataReference(program, "0x401060", "0x401000", 0);
      addDataReference(program, "0x401060", "0x401020", 1);
      addDataReference(program, "0x401062", "0x401000", 0);

      InspectTool tool = new InMemoryInspectTool(program);

      Object firstPageRaw =
          tool.execute(
                  null,
                  Map.of(
                      "file_name", "fixture",
                      "action", "references_from",
                      "address", "0x401060",
                      "reference_type", "DATA",
                      "page_size", 1),
                  null)
              .block();
      @SuppressWarnings("unchecked")
      CursorDataResult<String> firstPage = assertInstanceOf(CursorDataResult.class, firstPageRaw);
      assertNotNull(firstPage.nextCursor);
      assertTrue(firstPage.data.lines().count() == 1);
      assertTrue(firstPage.data.contains("DATA"));

      Object secondPageRaw =
          tool.execute(
                  null,
                  Map.of(
                      "file_name", "fixture",
                      "action", "references_from",
                      "address", "0x401060",
                      "reference_type", "DATA",
                      "page_size", 1,
                      "cursor", firstPage.nextCursor),
                  null)
              .block();
      @SuppressWarnings("unchecked")
      CursorDataResult<String> secondPage = assertInstanceOf(CursorDataResult.class, secondPageRaw);
      assertTrue(secondPage.data.lines().count() == 1);

      Set<String> pagedTargets =
          java.util.stream.Stream.concat(firstPage.data.lines(), secondPage.data.lines())
              .map(line -> line.split("\\s+", 3)[0].toLowerCase())
              .collect(Collectors.toSet());
      assertTrue(
          pagedTargets.stream().anyMatch(address -> address.toLowerCase().contains("401000")));
      assertTrue(
          pagedTargets.stream().anyMatch(address -> address.toLowerCase().contains("401020")));

      Object incomingRaw =
          tool.execute(
                  null,
                  Map.of(
                      "file_name", "fixture",
                      "action", "references_to",
                      "address", "0x401000",
                      "reference_type", "DATA",
                      "page_size", 10),
                  null)
              .block();
      @SuppressWarnings("unchecked")
      CursorDataResult<String> incoming = assertInstanceOf(CursorDataResult.class, incomingRaw);

      assertTrue(incoming.data.lines().allMatch(line -> line.contains("DATA")));
      assertTrue(incoming.data.lines().anyMatch(line -> line.toLowerCase().contains("401060")));
      assertTrue(incoming.data.lines().anyMatch(line -> line.toLowerCase().contains("401062")));
    } finally {
      fixture.close();
    }
  }

  @Test
  void decompileCodeReturnsCAndPcodeForFunctionContainingAddress() throws Exception {
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
                      "decompile",
                      "address",
                      "0x401000",
                      "include_pcode",
                      true,
                      "include_ast",
                      true,
                      "timeout",
                      30),
                  null)
              .block();
      DecompilationResult result = assertInstanceOf(DecompilationResult.class, raw);

      assertTrue(result.isDecompilationSuccessful());
      assertTrue(result.getEntryAddress().toLowerCase().contains("401000"));
      assertNotNull(result.getDecompiledCode());
      assertFalse(result.getDecompiledCode().isBlank());
      assertNotNull(result.getPcodeOperations());
      assertFalse(result.getPcodeOperations().isEmpty());
      assertNotNull(result.getAstInfo());
      assertTrue(result.getAstInfo().containsKey("basic_blocks"));
    } finally {
      fixture.close();
    }
  }

  @Test
  void decompileCodeSupportsFunctionNameIdentifierWithoutTargetValue() throws Exception {
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
                      "action", "decompile",
                      "name", "entry_main",
                      "timeout", 30),
                  null)
              .block();
      DecompilationResult result = assertInstanceOf(DecompilationResult.class, raw);

      assertTrue(result.isDecompilationSuccessful());
      assertEquals("entry_main", result.getTargetName());
      assertNotNull(result.getDecompiledCode());
    } finally {
      fixture.close();
    }
  }

  @Test
  void listAnalysisOptionsSupportsFilteringAndPagination() throws Exception {
    assumeTrue(
        Boolean.getBoolean("e2e.integration"), "Set -De2e.integration=true to run e2e tests");

    InMemoryProgramFixtureSupport.ProgramFixture fixture =
        InMemoryProgramFixtureSupport.createReadAndManageFixtureProgram();
    try {
      ProjectTool tool = new InMemoryProjectTool(fixture.program());

      Object firstPageRaw =
          tool.execute(
                  null,
                  Map.of("file_name", "fixture", "action", "list_analysis_options", "page_size", 5),
                  null)
              .block();
      @SuppressWarnings("unchecked")
      PaginatedResult<AnalysisOptionInfo> firstPage =
          assertInstanceOf(PaginatedResult.class, firstPageRaw);

      assertFalse(firstPage.results.isEmpty());
      for (int i = 1; i < firstPage.results.size(); i++) {
        String previous = firstPage.results.get(i - 1).getName();
        String current = firstPage.results.get(i).getName();
        assertTrue(
            previous.compareToIgnoreCase(current) <= 0, "Expected case-insensitive sort order");
      }

      String firstName = firstPage.results.get(0).getName();
      final String filterToken = firstName.substring(0, Math.min(5, firstName.length()));
      Object filteredRaw =
          tool.execute(
                  null,
                  Map.of(
                      "file_name",
                      "fixture",
                      "action",
                      "list_analysis_options",
                      "filter",
                      filterToken,
                      "page_size",
                      10),
                  null)
              .block();
      @SuppressWarnings("unchecked")
      PaginatedResult<AnalysisOptionInfo> filtered =
          assertInstanceOf(PaginatedResult.class, filteredRaw);
      assertTrue(
          filtered.results.stream()
              .allMatch(
                  option -> option.getName().toLowerCase().contains(filterToken.toLowerCase())));

      Object defaultsOnlyRaw =
          tool.execute(
                  null,
                  Map.of(
                      "file_name",
                      "fixture",
                      "action",
                      "list_analysis_options",
                      "defaults_only",
                      true,
                      "page_size",
                      20),
                  null)
              .block();
      @SuppressWarnings("unchecked")
      PaginatedResult<AnalysisOptionInfo> defaultsOnly =
          assertInstanceOf(PaginatedResult.class, defaultsOnlyRaw);
      assertTrue(defaultsOnly.results.stream().allMatch(AnalysisOptionInfo::isUsingDefaultValue));

      if (firstPage.nextCursor != null) {
        Object secondPageRaw =
            tool.execute(
                    null,
                    Map.of(
                        "file_name",
                        "fixture",
                        "action",
                        "list_analysis_options",
                        "page_size",
                        5,
                        "cursor",
                        firstPage.nextCursor),
                    null)
                .block();
        @SuppressWarnings("unchecked")
        PaginatedResult<AnalysisOptionInfo> secondPage =
            assertInstanceOf(PaginatedResult.class, secondPageRaw);
        assertFalse(secondPage.results.isEmpty());
      }
    } finally {
      fixture.close();
    }
  }

  private static void addDataReference(
      Program program, String fromAddressText, String toAddressText, int operandIndex) {
    int txId = program.startTransaction("Add e2e data reference");
    boolean commit = false;
    try {
      Address from = program.getAddressFactory().getAddress(fromAddressText);
      Address to = program.getAddressFactory().getAddress(toAddressText);
      program
          .getReferenceManager()
          .addMemoryReference(from, to, RefType.DATA, SourceType.USER_DEFINED, operandIndex);
      commit = true;
    } finally {
      program.endTransaction(txId, commit);
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
