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
import com.themixednuts.models.ReferenceInfo;
import com.themixednuts.tools.SearchMemoryTool.SearchResult;
import com.themixednuts.utils.PaginatedResult;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;

class AnalysisToolsE2eTest {

  @Test
  void searchMemoryFindsKnownHexPatternAtExpectedAddresses() throws Exception {
    assumeTrue(Boolean.getBoolean("e2e.integration"), "Set -De2e.integration=true to run e2e tests");

    InMemoryProgramFixtureSupport.ProgramFixture fixture =
        InMemoryProgramFixtureSupport.createReadAndManageFixtureProgram();
    try {
      SearchMemoryTool tool = new InMemorySearchMemoryTool(fixture.program());

      Object raw =
          tool.execute(
                  null,
                  Map.of(
                      "file_name", "fixture",
                      "search_type", "hex",
                      "search_value", "55 48 89 e5",
                      "max_results", 10),
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
    assumeTrue(Boolean.getBoolean("e2e.integration"), "Set -De2e.integration=true to run e2e tests");

    InMemoryProgramFixtureSupport.ProgramFixture fixture =
        InMemoryProgramFixtureSupport.createReadAndManageFixtureProgram();
    try {
      Program program = fixture.program();
      addDataReference(program, "0x401060", "0x401000", 0);
      addDataReference(program, "0x401060", "0x401020", 1);
      addDataReference(program, "0x401062", "0x401000", 0);

      FindReferencesTool tool = new InMemoryFindReferencesTool(program);

      Object firstPageRaw =
          tool.execute(
                  null,
                  Map.of(
                      "file_name", "fixture",
                      "address", "0x401060",
                      "direction", "from",
                      "reference_type", "DATA",
                      "page_size", 1),
                  null)
              .block();
      @SuppressWarnings("unchecked")
      PaginatedResult<ReferenceInfo> firstPage = assertInstanceOf(PaginatedResult.class, firstPageRaw);
      assertEquals(1, firstPage.results.size());
      assertNotNull(firstPage.nextCursor);
      assertTrue(firstPage.results.stream().allMatch(ref -> "DATA".equalsIgnoreCase(ref.getReferenceType())));

      Object secondPageRaw =
          tool.execute(
                  null,
                  Map.of(
                      "file_name", "fixture",
                      "address", "0x401060",
                      "direction", "from",
                      "reference_type", "DATA",
                      "page_size", 1,
                      "cursor", firstPage.nextCursor),
                  null)
              .block();
      @SuppressWarnings("unchecked")
      PaginatedResult<ReferenceInfo> secondPage =
          assertInstanceOf(PaginatedResult.class, secondPageRaw);
      assertEquals(1, secondPage.results.size());

      Set<String> pagedTargets =
          java.util.stream.Stream.concat(firstPage.results.stream(), secondPage.results.stream())
              .map(ReferenceInfo::getToAddress)
              .collect(Collectors.toSet());
      assertTrue(pagedTargets.stream().anyMatch(address -> address.toLowerCase().contains("401000")));
      assertTrue(pagedTargets.stream().anyMatch(address -> address.toLowerCase().contains("401020")));

      Object incomingRaw =
          tool.execute(
                  null,
                  Map.of(
                      "file_name", "fixture",
                      "address", "0x401000",
                      "direction", "to",
                      "reference_type", "DATA",
                      "page_size", 10),
                  null)
              .block();
      @SuppressWarnings("unchecked")
      PaginatedResult<ReferenceInfo> incoming = assertInstanceOf(PaginatedResult.class, incomingRaw);

      assertTrue(incoming.results.stream().allMatch(ref -> "DATA".equalsIgnoreCase(ref.getReferenceType())));
      assertTrue(
          incoming.results.stream()
              .anyMatch(ref -> ref.getFromAddress().toLowerCase().contains("401060")));
      assertTrue(
          incoming.results.stream()
              .anyMatch(ref -> ref.getFromAddress().toLowerCase().contains("401062")));
    } finally {
      fixture.close();
    }
  }

  @Test
  void decompileCodeReturnsCAndPcodeForFunctionContainingAddress() throws Exception {
    assumeTrue(Boolean.getBoolean("e2e.integration"), "Set -De2e.integration=true to run e2e tests");

    InMemoryProgramFixtureSupport.ProgramFixture fixture =
        InMemoryProgramFixtureSupport.createReadAndManageFixtureProgram();
    try {
      DecompileCodeTool tool = new InMemoryDecompileCodeTool(fixture.program());

      Object raw =
          tool.execute(
                  null,
                  Map.of(
                      "file_name", "fixture",
                      "target_type", "address",
                      "target_value", "0x401000",
                      "include_pcode", true,
                      "include_ast", true,
                      "timeout", 30),
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
  void listAnalysisOptionsSupportsFilteringAndPagination() throws Exception {
    assumeTrue(Boolean.getBoolean("e2e.integration"), "Set -De2e.integration=true to run e2e tests");

    InMemoryProgramFixtureSupport.ProgramFixture fixture =
        InMemoryProgramFixtureSupport.createReadAndManageFixtureProgram();
    try {
      ListAnalysisOptionsTool tool = new InMemoryListAnalysisOptionsTool(fixture.program());

      Object firstPageRaw =
          tool.execute(null, Map.of("file_name", "fixture", "page_size", 5), null).block();
      @SuppressWarnings("unchecked")
      PaginatedResult<AnalysisOptionInfo> firstPage =
          assertInstanceOf(PaginatedResult.class, firstPageRaw);

      assertFalse(firstPage.results.isEmpty());
      for (int i = 1; i < firstPage.results.size(); i++) {
        String previous = firstPage.results.get(i - 1).getName();
        String current = firstPage.results.get(i).getName();
        assertTrue(previous.compareToIgnoreCase(current) <= 0, "Expected case-insensitive sort order");
      }

      String firstName = firstPage.results.get(0).getName();
      final String filterToken = firstName.substring(0, Math.min(5, firstName.length()));
      Object filteredRaw =
          tool.execute(
                  null,
                  Map.of("file_name", "fixture", "filter", filterToken, "page_size", 10),
                  null)
              .block();
      @SuppressWarnings("unchecked")
      PaginatedResult<AnalysisOptionInfo> filtered = assertInstanceOf(PaginatedResult.class, filteredRaw);
      assertTrue(
          filtered.results.stream()
              .allMatch(
                  option -> option.getName().toLowerCase().contains(filterToken.toLowerCase())));

      Object defaultsOnlyRaw =
          tool.execute(null, Map.of("file_name", "fixture", "defaults_only", true, "page_size", 20), null)
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
                        "file_name", "fixture",
                        "page_size", 5,
                        "cursor", firstPage.nextCursor),
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
      name = "Search Memory Test",
      description = "In-memory search memory test wrapper",
      mcpName = "search_memory",
      mcpDescription = "In-memory wrapper for search_memory")
  private static final class InMemorySearchMemoryTool extends SearchMemoryTool {
    private final Program program;

    InMemorySearchMemoryTool(Program program) {
      this.program = program;
    }

    @Override
    protected Mono<Program> getProgram(
        Map<String, Object> args, ghidra.framework.plugintool.PluginTool tool) {
      return Mono.just(program);
    }
  }

  @GhidraMcpTool(
      name = "Find References Test",
      description = "In-memory find references test wrapper",
      mcpName = "find_references",
      mcpDescription = "In-memory wrapper for find_references")
  private static final class InMemoryFindReferencesTool extends FindReferencesTool {
    private final Program program;

    InMemoryFindReferencesTool(Program program) {
      this.program = program;
    }

    @Override
    protected Mono<Program> getProgram(
        Map<String, Object> args, ghidra.framework.plugintool.PluginTool tool) {
      return Mono.just(program);
    }
  }

  @GhidraMcpTool(
      name = "Decompile Code Test",
      description = "In-memory decompile code test wrapper",
      mcpName = "decompile_code",
      mcpDescription = "In-memory wrapper for decompile_code")
  private static final class InMemoryDecompileCodeTool extends DecompileCodeTool {
    private final Program program;

    InMemoryDecompileCodeTool(Program program) {
      this.program = program;
    }

    @Override
    protected Mono<Program> getProgram(
        Map<String, Object> args, ghidra.framework.plugintool.PluginTool tool) {
      return Mono.just(program);
    }
  }

  @GhidraMcpTool(
      name = "List Analysis Options Test",
      description = "In-memory list analysis options test wrapper",
      mcpName = "list_analysis_options",
      mcpDescription = "In-memory wrapper for list_analysis_options")
  private static final class InMemoryListAnalysisOptionsTool extends ListAnalysisOptionsTool {
    private final Program program;

    InMemoryListAnalysisOptionsTool(Program program) {
      this.program = program;
    }

    @Override
    protected Mono<Program> getProgram(
        Map<String, Object> args, ghidra.framework.plugintool.PluginTool tool) {
      return Mono.just(program);
    }
  }
}
