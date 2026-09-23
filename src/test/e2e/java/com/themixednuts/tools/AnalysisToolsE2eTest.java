package com.themixednuts.tools;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.models.AnalysisOptionInfo;
import com.themixednuts.models.CodeSearchResult;
import com.themixednuts.models.DecompilationResult;
import com.themixednuts.tools.MemoryTool.SearchResult;
import com.themixednuts.ui.ToolOutcome;
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
  void searchMemoryReturnsEmptyPageWhenPatternIsAbsent() throws Exception {
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
                      "search_value", "13 37 13 37 13 37 13 37",
                      "page_size", 10),
                  null)
              .block();

      @SuppressWarnings("unchecked")
      PaginatedResult<SearchResult> result = assertInstanceOf(PaginatedResult.class, raw);
      assertTrue(result.results.isEmpty());
      assertNull(result.nextCursor);
    } finally {
      fixture.close();
    }
  }

  @Test
  void searchMemoryFindsKnownStringAndRegexPatterns() throws Exception {
    assumeTrue(
        Boolean.getBoolean("e2e.integration"), "Set -De2e.integration=true to run e2e tests");

    InMemoryProgramFixtureSupport.ProgramFixture fixture =
        InMemoryProgramFixtureSupport.createReadAndManageFixtureProgram();
    try {
      MemoryTool tool = new InMemoryMemoryTool(fixture.program());

      Object stringRaw =
          tool.execute(
                  null,
                  Map.of(
                      "file_name", "fixture",
                      "action", "search",
                      "search_type", "string",
                      "search_value", "CanvasAsset",
                      "case_sensitive", true,
                      "page_size", 10),
                  null)
              .block();
      @SuppressWarnings("unchecked")
      PaginatedResult<SearchResult> stringResult =
          assertInstanceOf(PaginatedResult.class, stringRaw);

      assertTrue(
          stringResult.results.stream()
              .anyMatch(match -> match.getAddress().toLowerCase().contains("402010")));

      Object regexRaw =
          tool.execute(
                  null,
                  Map.of(
                      "file_name", "fixture",
                      "action", "search",
                      "search_type", "regex",
                      "search_value", "CanvasAsset",
                      "case_sensitive", true,
                      "page_size", 10),
                  null)
              .block();
      @SuppressWarnings("unchecked")
      PaginatedResult<SearchResult> regexResult = assertInstanceOf(PaginatedResult.class, regexRaw);

      assertTrue(
          regexResult.results.stream()
              .anyMatch(match -> match.getAddress().toLowerCase().contains("402010")));
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
      DecompilationResult result = assertInstanceOf(DecompilationResult.class, unwrapOutcome(raw));

      assertTrue(result.getEntryAddress().toLowerCase().contains("401000"));
      assertNotNull(result.getDecompiledCode());
      assertFalse(result.getDecompiledCode().isBlank());
      assertNotNull(result.getPcodeOperations());
      assertFalse(result.getPcodeOperations().isEmpty());
      assertNotNull(result.getBasicBlockCount());
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
      DecompilationResult result = assertInstanceOf(DecompilationResult.class, unwrapOutcome(raw));

      assertEquals("entry_main", result.getTargetName());
      assertNotNull(result.getDecompiledCode());
    } finally {
      fixture.close();
    }
  }

  @Test
  void decompileCodePagesSourceLinesAndAllowsFullOutput() throws Exception {
    assumeTrue(
        Boolean.getBoolean("e2e.integration"), "Set -De2e.integration=true to run e2e tests");

    InMemoryProgramFixtureSupport.ProgramFixture fixture =
        InMemoryProgramFixtureSupport.createReadAndManageFixtureProgram();
    try {
      InspectTool tool = new InMemoryInspectTool(fixture.program());
      Map<String, Object> target =
          Map.of("file_name", "fixture", "action", "decompile", "name", "entry_main");
      Map<String, Object> firstArgs = new java.util.HashMap<>(target);
      firstArgs.put("max_lines", 1);
      DecompilationResult first =
          assertInstanceOf(
              DecompilationResult.class,
              unwrapOutcome(tool.execute(null, firstArgs, null).block()));

      Map<String, Object> fullArgs = new java.util.HashMap<>(target);
      fullArgs.put("max_lines", 0);
      DecompilationResult full =
          assertInstanceOf(
              DecompilationResult.class, unwrapOutcome(tool.execute(null, fullArgs, null).block()));

      assertEquals(1, first.getCodeStartLine());
      assertNotNull(first.getDecompilationId());
      assertEquals(2, first.getNextLine());
      assertEquals(full.getCodeTotalLines(), first.getCodeTotalLines());
      assertTrue(full.getDecompiledCode().startsWith(first.getDecompiledCode()));
      assertNull(full.getNextLine());

      int transaction = fixture.program().startTransaction("Rename after decompilation");
      try {
        fixture
            .program()
            .getFunctionManager()
            .getFunctionAt(fixture.program().getAddressFactory().getAddress("0x401000"))
            .getSymbol()
            .setName("renamed_main", SourceType.USER_DEFINED);
      } finally {
        fixture.program().endTransaction(transaction, true);
      }

      DecompilationResult reused =
          assertInstanceOf(
              DecompilationResult.class,
              unwrapOutcome(
                  tool.execute(
                          null,
                          Map.of(
                              "file_name",
                              "fixture",
                              "action",
                              "decompile",
                              "decompilation_id",
                              first.getDecompilationId(),
                              "max_lines",
                              0),
                          null)
                      .block()));
      assertEquals(first.getDecompilationId(), reused.getDecompilationId());
      assertEquals("entry_main", reused.getTargetName());
      assertEquals(first.getCodeTotalLines(), reused.getCodeTotalLines());
      assertTrue(reused.getDecompiledCode().startsWith(first.getDecompiledCode()));

      DecompilationResult fresh =
          assertInstanceOf(
              DecompilationResult.class,
              unwrapOutcome(
                  tool.execute(
                          null,
                          Map.of(
                              "file_name", "fixture",
                              "action", "decompile",
                              "name", "renamed_main",
                              "max_lines", 1),
                          null)
                      .block()));
      assertEquals("renamed_main", fresh.getTargetName());
    } finally {
      fixture.close();
    }
  }

  @Test
  void searchCodePagesAcrossFunctionsAndExposesReusableSnapshots() throws Exception {
    assumeTrue(
        Boolean.getBoolean("e2e.integration"), "Set -De2e.integration=true to run e2e tests");
    InMemoryProgramFixtureSupport.ProgramFixture fixture =
        InMemoryProgramFixtureSupport.createReadAndManageFixtureProgram();
    try {
      InspectTool tool = new InMemoryInspectTool(fixture.program());
      CodeSearchResult first =
          assertInstanceOf(
              CodeSearchResult.class,
              unwrapOutcome(
                  tool.execute(
                          null,
                          Map.of(
                              "file_name", "fixture",
                              "action", "search_code",
                              "search_text", "entry_",
                              "max_functions", 1),
                          null)
                      .block()));
      assertEquals(1, first.functionsScanned());
      assertEquals("entry_main", first.matches().get(0).functionName());
      assertNotNull(first.matches().get(0).decompilationId());
      assertNotNull(first.nextCursor());

      CodeSearchResult second =
          assertInstanceOf(
              CodeSearchResult.class,
              unwrapOutcome(
                  tool.execute(
                          null,
                          Map.of(
                              "file_name", "fixture",
                              "action", "search_code",
                              "search_text", "entry_",
                              "max_functions", 1,
                              "cursor", first.nextCursor()),
                          null)
                      .block()));
      assertEquals("entry_worker", second.matches().get(0).functionName());
      assertTrue(second.complete());
      assertNull(second.nextCursor());
    } finally {
      fixture.close();
    }
  }

  @Test
  void searchCodeResumesWithinOneFunctionWithoutRepeatingTheFirstMatch() throws Exception {
    assumeTrue(
        Boolean.getBoolean("e2e.integration"), "Set -De2e.integration=true to run e2e tests");
    InMemoryProgramFixtureSupport.ProgramFixture fixture =
        InMemoryProgramFixtureSupport.createReadAndManageFixtureProgram();
    try {
      InspectTool tool = new InMemoryInspectTool(fixture.program());
      CodeSearchResult first =
          assertInstanceOf(
              CodeSearchResult.class,
              unwrapOutcome(
                  tool.execute(
                          null,
                          Map.of(
                              "file_name",
                              "fixture",
                              "action",
                              "search_code",
                              "search_text",
                              "n",
                              "max_matches",
                              1,
                              "context_lines",
                              0,
                              "max_functions",
                              1),
                          null)
                      .block()));
      assertTrue(first.matches().get(0).totalMatchesInFunction() >= 2);
      assertNotNull(first.nextCursor());

      CodeSearchResult second =
          assertInstanceOf(
              CodeSearchResult.class,
              unwrapOutcome(
                  tool.execute(
                          null,
                          Map.of(
                              "file_name",
                              "fixture",
                              "action",
                              "search_code",
                              "search_text",
                              "n",
                              "max_matches",
                              1,
                              "context_lines",
                              0,
                              "max_functions",
                              1,
                              "cursor",
                              first.nextCursor()),
                          null)
                      .block()));
      assertEquals(first.matches().get(0).entryAddress(), second.matches().get(0).entryAddress());
      assertFalse(
          first.matches().get(0).matchingLines().equals(second.matches().get(0).matchingLines()));
    } finally {
      fixture.close();
    }
  }

  @Test
  void decompileSearchReturnsNumberedMatchesAndEmptyResult() throws Exception {
    assumeTrue(
        Boolean.getBoolean("e2e.integration"), "Set -De2e.integration=true to run e2e tests");
    InMemoryProgramFixtureSupport.ProgramFixture fixture =
        InMemoryProgramFixtureSupport.createReadAndManageFixtureProgram();
    try {
      InspectTool tool = new InMemoryInspectTool(fixture.program());
      Map<String, Object> target =
          Map.of("file_name", "fixture", "action", "decompile", "name", "entry_main");
      Map<String, Object> searchArgs = new java.util.HashMap<>(target);
      searchArgs.put("search_text", "entry_main");
      searchArgs.put("context_lines", 0);
      DecompilationResult found =
          assertInstanceOf(
              DecompilationResult.class,
              unwrapOutcome(tool.execute(null, searchArgs, null).block()));

      assertEquals("entry_main", found.getSearchText());
      assertTrue(found.getTotalMatches() > 0);
      assertTrue(found.getDecompiledCode().contains("entry_main"));
      assertTrue(found.getDecompiledCode().contains(" | "));
      assertFalse(found.getMatchingLines().isEmpty());

      searchArgs.put("search_text", "__MCP_NO_SUCH_TOKEN_2026__");
      DecompilationResult absent =
          assertInstanceOf(
              DecompilationResult.class,
              unwrapOutcome(tool.execute(null, searchArgs, null).block()));
      assertEquals(0, absent.getTotalMatches());
      assertTrue(absent.getDecompiledCode().isEmpty());
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
      String defaultOptionJson = BaseMcpTool.mapper.writeValueAsString(firstPage.results.get(0));
      assertFalse(defaultOptionJson.contains("\"description\""), defaultOptionJson);
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

      Object verboseRaw =
          tool.execute(
                  null,
                  Map.of(
                      "file_name",
                      "fixture",
                      "action",
                      "list_analysis_options",
                      "page_size",
                      20,
                      "verbose",
                      true),
                  null)
              .block();
      @SuppressWarnings("unchecked")
      PaginatedResult<AnalysisOptionInfo> verbose =
          assertInstanceOf(PaginatedResult.class, verboseRaw);
      assertFalse(verbose.results.isEmpty());
      AnalysisOptionInfo described =
          new AnalysisOptionInfo("Option", "Long description", "BOOLEAN", "true", true, true);
      String describedJson = BaseMcpTool.mapper.writeValueAsString(described);
      assertTrue(describedJson.contains("\"description\""), describedJson);

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

  private static Object unwrapOutcome(Object raw) {
    if (raw instanceof ToolOutcome<?> outcome) {
      return outcome.data();
    }
    return raw;
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
