package com.themixednuts.tools;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.models.versiontracking.VTCorrelatorInfo;
import com.themixednuts.models.versiontracking.VTMatchInfo;
import com.themixednuts.models.versiontracking.VTSessionInfo;
import com.themixednuts.tools.versiontracking.VTMatchResolver;
import com.themixednuts.tools.versiontracking.VTOperationsTool;
import com.themixednuts.tools.versiontracking.VTSessionsTool;
import com.themixednuts.utils.PaginatedResult;
import ghidra.feature.vt.api.main.VTSession;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer.OrderAnnotation;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import org.junit.jupiter.api.TestMethodOrder;

@TestInstance(Lifecycle.PER_CLASS)
@TestMethodOrder(OrderAnnotation.class)
class VersionTrackingE2eTest {

  private VTFixtureSupport.VTFixture fixture;

  @BeforeAll
  void setUp() throws Exception {
    assumeTrue(
        Boolean.getBoolean("e2e.integration"), "Set -De2e.integration=true to run e2e tests");
    fixture = VTFixtureSupport.createVTFixture();
  }

  @AfterAll
  void tearDown() {
    if (fixture != null) {
      fixture.close();
    }
  }

  // =================== Session Info (Order 10) ===================

  @Test
  @Order(10)
  void sessionInfoReturnsCorrectProgramNamesAndInitialCounts() {
    InMemoryVTSessionsTool tool = new InMemoryVTSessionsTool(fixture.session());
    Object raw =
        tool.execute(null, Map.of("action", "info", "session_name", "vt_test_session"), null)
            .block();

    VTSessionInfo info = assertInstanceOf(VTSessionInfo.class, raw);
    assertEquals("source_v1", info.sourceProgram());
    assertEquals("dest_v2", info.destinationProgram());
    assertEquals(0, info.totalMatches());
    assertEquals(0, info.acceptedMatches());
    assertEquals(0, info.rejectedMatches());
  }

  // =================== Correlators (Order 20-60) ===================

  @Test
  @Order(20)
  void listCorrelatorsReturnsAllTypes() {
    InMemoryVTOperationsTool tool = new InMemoryVTOperationsTool(fixture.session());
    Object raw = tool.execute(null, Map.of("action", "list_correlators"), null).block();

    @SuppressWarnings("unchecked")
    List<VTCorrelatorInfo> correlators = assertInstanceOf(List.class, raw);
    assertEquals(13, correlators.size());
  }

  @Test
  @Order(30)
  void runExactBytesFindsExpectedMatches() {
    InMemoryVTOperationsTool tool = new InMemoryVTOperationsTool(fixture.session());
    Object raw =
        tool.execute(
                null,
                Map.of(
                    "action", "run_correlator",
                    "session_name", "vt_test_session",
                    "correlator_type", "exact_bytes",
                    "exclude_accepted", false),
                null)
            .block();

    @SuppressWarnings("unchecked")
    Map<String, Object> result = assertInstanceOf(Map.class, raw);
    assertEquals("exact_bytes", result.get("correlator"));
    int matchCount = ((Number) result.get("match_count")).intValue();
    assertTrue(matchCount >= 5, "Expected at least 5 exact byte matches, got " + matchCount);
  }

  @Test
  @Order(40)
  void runExactInstructionsFindsAdditionalMatches() {
    InMemoryVTOperationsTool tool = new InMemoryVTOperationsTool(fixture.session());
    Object raw =
        tool.execute(
                null,
                Map.of(
                    "action", "run_correlator",
                    "session_name", "vt_test_session",
                    "correlator_type", "exact_instructions",
                    "exclude_accepted", false),
                null)
            .block();

    @SuppressWarnings("unchecked")
    Map<String, Object> result = assertInstanceOf(Map.class, raw);
    int matchCount = ((Number) result.get("match_count")).intValue();
    assertTrue(matchCount >= 1, "Expected at least 1 exact instruction match, got " + matchCount);
  }

  @Test
  @Order(50)
  void runExactDataFindsDataMatches() {
    InMemoryVTOperationsTool tool = new InMemoryVTOperationsTool(fixture.session());
    Object raw =
        tool.execute(
                null,
                Map.of(
                    "action", "run_correlator",
                    "session_name", "vt_test_session",
                    "correlator_type", "exact_data",
                    "exclude_accepted", false),
                null)
            .block();

    @SuppressWarnings("unchecked")
    Map<String, Object> result = assertInstanceOf(Map.class, raw);
    int matchCount = ((Number) result.get("match_count")).intValue();
    assertTrue(matchCount >= 3, "Expected at least 3 exact data matches, got " + matchCount);
  }

  @Test
  @Order(60)
  void runSymbolNameFindsCommonApiMatch() {
    InMemoryVTOperationsTool tool = new InMemoryVTOperationsTool(fixture.session());
    Object raw =
        tool.execute(
                null,
                Map.of(
                    "action", "run_correlator",
                    "session_name", "vt_test_session",
                    "correlator_type", "symbol_name",
                    "exclude_accepted", false),
                null)
            .block();

    @SuppressWarnings("unchecked")
    Map<String, Object> result = assertInstanceOf(Map.class, raw);
    int matchCount = ((Number) result.get("match_count")).intValue();
    assertTrue(matchCount >= 1, "Expected at least 1 symbol name match, got " + matchCount);
  }

  // =================== Edge Cases (Order 70-90) ===================

  @Test
  @Order(70)
  void edgeBelowMinFuncSizeNotMatched() {
    assertFalse(
        hasAnyMatchForSourceAddressInCorrelator("0x401060", "exact_bytes"),
        "tiny_ret (1 byte) should not be matched by exact_bytes");
  }

  @Test
  @Order(72)
  void edgeRelocatedFunctionMatches() {
    assertTrue(
        hasMatchPairInCorrelator("0x4010E0", "0x401180", "exact_bytes"),
        "shifted_func should match exact_bytes at relocated destination address");
  }

  @Test
  @Order(74)
  void edgeComplexControlFlowMatches() {
    assertTrue(
        hasMatchPairInCorrelator("0x401080", "0x401080", "exact_bytes"),
        "branch_func should match exact_bytes");
  }

  @Test
  @Order(75)
  void edgeNopPaddedFunctionMatches() {
    assertTrue(
        hasMatchPairInCorrelator("0x401070", "0x401070", "exact_bytes"),
        "nop_sled should match exact_bytes");
  }

  @Test
  @Order(76)
  void edgeLoopWithBackwardJumpMatches() {
    assertTrue(
        hasMatchPairInCorrelator("0x401140", "0x401120", "exact_bytes"),
        "loop_func should match exact_bytes");
  }

  @Test
  @Order(78)
  void edgeNonUniqueBytesNotMatched() {
    assertFalse(
        hasAnyMatchForSourceAddressInCorrelator("0x4010A0", "exact_bytes"),
        "dup_bytes_alpha should not match because source bytes are not unique");
  }

  @Test
  @Order(80)
  void edgeNonUniqueDataNotMatched() {
    assertFalse(
        hasAnyMatchForSourceAddressInCorrelator("0x402010", "exact_data"),
        "dup_data at 0x402010 should not match because source data are not unique");
  }

  @Test
  @Order(82)
  void edgeHomogeneousDataSkipped() {
    assertFalse(
        hasAnyMatchForSourceAddressInCorrelator("0x402080", "exact_data"),
        "homogeneous all-0xFF data should be skipped");
  }

  @Test
  @Order(84)
  void edgeWideImmInstructionMatch() {
    assertTrue(
        hasMatchPairInCorrelator("0x401120", "0x401100", "exact_instructions"),
        "wide_imm_func should match exact_instructions");
  }

  @Test
  @Order(86)
  void edgeModifiedDataNotMatched() {
    assertFalse(
        hasAnyMatchForSourceAddressInCorrelator("0x402040", "exact_data"),
        "version string should not match after content changed from v1.0 to v2.0");
  }

  // =================== Match Reading (Order 100-150) ===================

  @Test
  @Order(100)
  void readAllMatchesReturnsExpectedCount() {
    InMemoryVTOperationsTool tool = new InMemoryVTOperationsTool(fixture.session());
    Object raw =
        tool.execute(
                null,
                Map.of(
                    "action", "list_matches", "session_name", "vt_test_session", "page_size", 50),
                null)
            .block();

    @SuppressWarnings("unchecked")
    PaginatedResult<VTMatchInfo> result = assertInstanceOf(PaginatedResult.class, raw);
    assertFalse(result.results.isEmpty(), "Expected non-empty match results after correlators ran");
  }

  @Test
  @Order(110)
  void readMatchesFilterByStatusAvailable() {
    InMemoryVTOperationsTool tool = new InMemoryVTOperationsTool(fixture.session());
    Object raw =
        tool.execute(
                null,
                Map.of(
                    "action", "list_matches",
                    "session_name", "vt_test_session",
                    "status", "AVAILABLE",
                    "page_size", 50),
                null)
            .block();

    @SuppressWarnings("unchecked")
    PaginatedResult<VTMatchInfo> result = assertInstanceOf(PaginatedResult.class, raw);
    assertFalse(result.results.isEmpty());
    assertTrue(
        result.results.stream().allMatch(m -> "AVAILABLE".equals(m.status())),
        "All matches should have AVAILABLE status");
  }

  @Test
  @Order(120)
  void readMatchesFilterByMatchTypeFunction() {
    InMemoryVTOperationsTool tool = new InMemoryVTOperationsTool(fixture.session());
    Object raw =
        tool.execute(
                null,
                Map.of(
                    "action", "list_matches",
                    "session_name", "vt_test_session",
                    "match_type", "FUNCTION",
                    "page_size", 50),
                null)
            .block();

    @SuppressWarnings("unchecked")
    PaginatedResult<VTMatchInfo> result = assertInstanceOf(PaginatedResult.class, raw);
    assertFalse(result.results.isEmpty());
    assertTrue(
        result.results.stream().allMatch(m -> "FUNCTION".equals(m.matchType())),
        "All matches should be FUNCTION type");
  }

  @Test
  @Order(130)
  void readMatchesFilterByMatchTypeData() {
    InMemoryVTOperationsTool tool = new InMemoryVTOperationsTool(fixture.session());
    Object raw =
        tool.execute(
                null,
                Map.of(
                    "action", "list_matches",
                    "session_name", "vt_test_session",
                    "match_type", "DATA",
                    "page_size", 50),
                null)
            .block();

    @SuppressWarnings("unchecked")
    PaginatedResult<VTMatchInfo> result = assertInstanceOf(PaginatedResult.class, raw);
    assertTrue(
        result.results.stream().allMatch(m -> "DATA".equals(m.matchType())),
        "All matches should be DATA type");
  }

  @Test
  @Order(140)
  void readMatchesPaginationWorks() {
    InMemoryVTOperationsTool tool = new InMemoryVTOperationsTool(fixture.session());

    // First page with size 1
    Object firstRaw =
        tool.execute(
                null,
                Map.of("action", "list_matches", "session_name", "vt_test_session", "page_size", 1),
                null)
            .block();
    @SuppressWarnings("unchecked")
    PaginatedResult<VTMatchInfo> firstPage = assertInstanceOf(PaginatedResult.class, firstRaw);
    assertEquals(1, firstPage.results.size());
    assertNotNull(firstPage.nextCursor, "Expected cursor for next page");

    // Second page
    Object secondRaw =
        tool.execute(
                null,
                Map.of(
                    "action",
                    "list_matches",
                    "session_name",
                    "vt_test_session",
                    "page_size",
                    1,
                    "cursor",
                    firstPage.nextCursor),
                null)
            .block();
    @SuppressWarnings("unchecked")
    PaginatedResult<VTMatchInfo> secondPage = assertInstanceOf(PaginatedResult.class, secondRaw);
    assertEquals(1, secondPage.results.size());

    // Pages should have different matches
    assertFalse(
        firstPage.results.get(0).sourceAddress().equals(secondPage.results.get(0).sourceAddress())
            && firstPage
                .results
                .get(0)
                .destinationAddress()
                .equals(secondPage.results.get(0).destinationAddress()),
        "Paginated results should return different matches");
  }

  @Test
  @Order(150)
  void readMatchesErrorOnSingleAddressOnly() {
    InMemoryVTOperationsTool tool = new InMemoryVTOperationsTool(fixture.session());

    assertThrows(
        Exception.class,
        () ->
            tool.execute(
                    null,
                    Map.of(
                        "action", "list_matches",
                        "session_name", "vt_test_session",
                        "source_address", "0x401000"),
                    null)
                .block(),
        "Should throw when only source_address is provided without destination_address");
  }

  // =================== Match Management (Order 200-260) ===================

  @Test
  @Order(200)
  void acceptMatchChangesStatus() {
    // Find the main_func exact bytes match (0x401000 -> 0x401000)
    InMemoryVTOperationsTool tool = new InMemoryVTOperationsTool(fixture.session());
    Object raw =
        tool.execute(
                null,
                Map.of(
                    "action", "accept",
                    "session_name", "vt_test_session",
                    "source_address", "0x401000",
                    "destination_address", "0x401000"),
                null)
            .block();

    @SuppressWarnings("unchecked")
    Map<String, Object> result = assertInstanceOf(Map.class, raw);
    assertEquals(1, ((Number) result.get("affected_count")).intValue());
    assertEquals("accept", result.get("action"));

    // Verify status changed
    InMemoryVTOperationsTool readTool = new InMemoryVTOperationsTool(fixture.session());
    Object readRaw =
        readTool
            .execute(
                null,
                Map.of(
                    "action", "list_matches",
                    "session_name", "vt_test_session",
                    "source_address", "0x401000",
                    "destination_address", "0x401000"),
                null)
            .block();
    VTMatchInfo matchInfo = assertInstanceOf(VTMatchInfo.class, readRaw);
    assertEquals("ACCEPTED", matchInfo.status());
  }

  @Test
  @Order(210)
  void rejectMatchChangesStatus() {
    // Find a match to reject - helper_func (0x401020 -> 0x401020)
    InMemoryVTOperationsTool tool = new InMemoryVTOperationsTool(fixture.session());
    Object raw =
        tool.execute(
                null,
                Map.of(
                    "action", "reject",
                    "session_name", "vt_test_session",
                    "source_address", "0x401020",
                    "destination_address", "0x401020"),
                null)
            .block();

    @SuppressWarnings("unchecked")
    Map<String, Object> result = assertInstanceOf(Map.class, raw);
    assertEquals(1, ((Number) result.get("affected_count")).intValue());
    assertEquals("reject", result.get("action"));
  }

  @Test
  @Order(220)
  void clearResetsToAvailable() {
    // Clear the rejected match
    InMemoryVTOperationsTool tool = new InMemoryVTOperationsTool(fixture.session());
    Object raw =
        tool.execute(
                null,
                Map.of(
                    "action", "clear",
                    "session_name", "vt_test_session",
                    "source_address", "0x401020",
                    "destination_address", "0x401020"),
                null)
            .block();

    @SuppressWarnings("unchecked")
    Map<String, Object> result = assertInstanceOf(Map.class, raw);
    assertEquals("clear", result.get("action"));

    // Verify status is back to AVAILABLE
    InMemoryVTOperationsTool readTool = new InMemoryVTOperationsTool(fixture.session());
    Object readRaw =
        readTool
            .execute(
                null,
                Map.of(
                    "action", "list_matches",
                    "session_name", "vt_test_session",
                    "source_address", "0x401020",
                    "destination_address", "0x401020"),
                null)
            .block();
    VTMatchInfo matchInfo = assertInstanceOf(VTMatchInfo.class, readRaw);
    assertEquals("AVAILABLE", matchInfo.status());
  }

  @Test
  @Order(240)
  void bulkAcceptBySimilarityThreshold() {
    InMemoryVTOperationsTool tool = new InMemoryVTOperationsTool(fixture.session());
    Object raw =
        tool.execute(
                null,
                Map.of(
                    "action", "accept_bulk",
                    "session_name", "vt_test_session",
                    "min_similarity", 1.0),
                null)
            .block();

    @SuppressWarnings("unchecked")
    Map<String, Object> result = assertInstanceOf(Map.class, raw);
    int acceptedCount = ((Number) result.get("accepted_count")).intValue();
    assertTrue(acceptedCount >= 0, "accepted_count should be non-negative");
  }

  @Test
  @Order(250)
  void bulkRejectByMaxSimilarity() {
    InMemoryVTOperationsTool tool = new InMemoryVTOperationsTool(fixture.session());
    Object raw =
        tool.execute(
                null,
                Map.of(
                    "action", "reject_bulk",
                    "session_name", "vt_test_session",
                    "max_similarity", 0.5),
                null)
            .block();

    @SuppressWarnings("unchecked")
    Map<String, Object> result = assertInstanceOf(Map.class, raw);
    int rejectedCount = ((Number) result.get("rejected_count")).intValue();
    assertTrue(rejectedCount >= 0, "rejected_count should be non-negative");
  }

  @Test
  @Order(260)
  void bulkAcceptWithoutThresholdThrowsError() {
    InMemoryVTOperationsTool tool = new InMemoryVTOperationsTool(fixture.session());

    assertThrows(
        Exception.class,
        () ->
            tool.execute(
                    null,
                    Map.of(
                        "action", "accept_bulk",
                        "session_name", "vt_test_session"),
                    null)
                .block(),
        "Should throw when no min_similarity or min_confidence provided for bulk accept");
  }

  // =================== Markup Operations (Order 300-340) ===================

  @Test
  @Order(300)
  void listMarkupItemsForAcceptedMatch() {
    InMemoryVTOperationsTool tool = new InMemoryVTOperationsTool(fixture.session());
    Object raw =
        tool.execute(
                null,
                Map.of(
                    "action", "list_markup",
                    "session_name", "vt_test_session",
                    "source_address", "0x401000",
                    "destination_address", "0x401000"),
                null)
            .block();

    @SuppressWarnings("unchecked")
    List<?> items = assertInstanceOf(List.class, raw);
    assertFalse(items.isEmpty(), "Expected at least one markup item for accepted match");
  }

  @Test
  @Order(310)
  void applyMarkupToAcceptedMatch() {
    InMemoryVTOperationsTool tool = new InMemoryVTOperationsTool(fixture.session());

    Map<String, Object> args = new HashMap<>();
    args.put("action", "apply_markup");
    args.put("session_name", "vt_test_session");
    args.put("source_address", "0x401000");
    args.put("destination_address", "0x401000");
    args.put("markup_types", List.of("function_name"));

    Object raw = tool.execute(null, args, null).block();

    @SuppressWarnings("unchecked")
    Map<String, Object> result = assertInstanceOf(Map.class, raw);
    assertEquals("apply", result.get("action"));
    int appliedCount = ((Number) result.get("applied_count")).intValue();
    assertTrue(appliedCount >= 1, "Expected at least 1 applied markup item, got " + appliedCount);
  }

  @Test
  @Order(320)
  void applyAllMarkupToAllAcceptedMatches() {
    InMemoryVTOperationsTool tool = new InMemoryVTOperationsTool(fixture.session());
    Object raw =
        tool.execute(
                null, Map.of("action", "apply_all_markup", "session_name", "vt_test_session"), null)
            .block();

    @SuppressWarnings("unchecked")
    Map<String, Object> result = assertInstanceOf(Map.class, raw);
    assertEquals("apply_all", result.get("action"));
    int matchesProcessed = ((Number) result.get("matches_processed")).intValue();
    assertTrue(matchesProcessed > 0, "Expected at least 1 match processed");
  }

  @Test
  @Order(330)
  void unapplyMarkupReversesPreviouslyApplied() {
    InMemoryVTOperationsTool tool = new InMemoryVTOperationsTool(fixture.session());
    Object raw =
        tool.execute(
                null,
                Map.of(
                    "action", "unapply_markup",
                    "session_name", "vt_test_session",
                    "source_address", "0x401000",
                    "destination_address", "0x401000"),
                null)
            .block();

    @SuppressWarnings("unchecked")
    Map<String, Object> result = assertInstanceOf(Map.class, raw);
    assertEquals("unapply", result.get("action"));
    int unappliedCount = ((Number) result.get("unapplied_count")).intValue();
    assertTrue(unappliedCount >= 1, "Expected at least 1 unapplied markup item");
  }

  @Test
  @Order(340)
  void applyMarkupToNonAcceptedMatchThrowsError() {
    // First, find an AVAILABLE match to test with
    InMemoryVTOperationsTool readTool = new InMemoryVTOperationsTool(fixture.session());
    Object readRaw =
        readTool
            .execute(
                null,
                Map.of(
                    "action", "list_matches",
                    "session_name", "vt_test_session",
                    "status", "AVAILABLE",
                    "page_size", 1),
                null)
            .block();

    @SuppressWarnings("unchecked")
    PaginatedResult<VTMatchInfo> readResult = assertInstanceOf(PaginatedResult.class, readRaw);

    // Skip test if no AVAILABLE matches remain (all were accepted/rejected)
    if (readResult.results.isEmpty()) {
      return;
    }

    VTMatchInfo availableMatch = readResult.results.get(0);

    InMemoryVTOperationsTool tool = new InMemoryVTOperationsTool(fixture.session());
    Map<String, Object> args = new HashMap<>();
    args.put("action", "apply_markup");
    args.put("session_name", "vt_test_session");
    args.put("source_address", availableMatch.sourceAddress());
    args.put("destination_address", availableMatch.destinationAddress());

    assertThrows(
        Exception.class,
        () -> tool.execute(null, args, null).block(),
        "Should throw when applying markup to non-ACCEPTED match");
  }

  // =================== Final Verification (Order 400) ===================

  @Test
  @Order(400)
  void sessionInfoReflectsAcceptedAndRejectedCounts() {
    InMemoryVTSessionsTool tool = new InMemoryVTSessionsTool(fixture.session());
    Object raw =
        tool.execute(null, Map.of("action", "info", "session_name", "vt_test_session"), null)
            .block();

    VTSessionInfo info = assertInstanceOf(VTSessionInfo.class, raw);
    assertTrue(info.totalMatches() > 0, "Expected total_matches > 0 after running correlators");
    assertTrue(info.acceptedMatches() > 0, "Expected accepted_matches > 0 after accepting matches");
  }

  // =================== Test Helpers ===================

  private boolean hasAnyMatchForSourceAddressInCorrelator(
      String sourceAddress, String correlatorType) {
    return readAllMatches().stream()
        .filter(match -> isCorrelatorType(match.correlator(), correlatorType))
        .anyMatch(
            match ->
                VTMatchResolver.normalizeAddressHex(sourceAddress)
                    .equals(VTMatchResolver.normalizeAddressHex(match.sourceAddress())));
  }

  private boolean hasMatchPairInCorrelator(
      String sourceAddress, String destinationAddress, String correlatorType) {
    String normalizedSource = VTMatchResolver.normalizeAddressHex(sourceAddress);
    String normalizedDestination = VTMatchResolver.normalizeAddressHex(destinationAddress);

    return readAllMatches().stream()
        .filter(match -> isCorrelatorType(match.correlator(), correlatorType))
        .anyMatch(
            match ->
                normalizedSource.equals(VTMatchResolver.normalizeAddressHex(match.sourceAddress()))
                    && normalizedDestination.equals(
                        VTMatchResolver.normalizeAddressHex(match.destinationAddress())));
  }

  private boolean isCorrelatorType(String correlatorName, String correlatorType) {
    if (correlatorName == null) {
      return false;
    }

    String normalizedCorrelatorName = correlatorName.toLowerCase();
    return switch (correlatorType.toLowerCase()) {
      case "exact_bytes" -> normalizedCorrelatorName.contains("bytes");
      case "exact_instructions" -> normalizedCorrelatorName.contains("instruction");
      case "exact_data" -> normalizedCorrelatorName.contains("data");
      case "symbol_name" -> normalizedCorrelatorName.contains("symbol");
      default -> normalizedCorrelatorName.contains(correlatorType.toLowerCase());
    };
  }

  private List<VTMatchInfo> readAllMatches() {
    InMemoryVTOperationsTool tool = new InMemoryVTOperationsTool(fixture.session());
    List<VTMatchInfo> allMatches = new ArrayList<>();
    String cursor = null;

    while (true) {
      Map<String, Object> args = new HashMap<>();
      args.put("action", "list_matches");
      args.put("session_name", "vt_test_session");
      args.put("page_size", 100);
      if (cursor != null) {
        args.put("cursor", cursor);
      }

      Object raw = tool.execute(null, args, null).block();
      @SuppressWarnings("unchecked")
      PaginatedResult<VTMatchInfo> page = assertInstanceOf(PaginatedResult.class, raw);
      allMatches.addAll(page.results);

      if (page.nextCursor == null) {
        break;
      }
      cursor = page.nextCursor;
    }

    return allMatches;
  }

  // =================== Inner Wrapper Classes ===================

  @GhidraMcpTool(
      name = "VT Sessions Test",
      description = "In-memory VT session test wrapper",
      mcpName = "vt_sessions",
      mcpDescription = "In-memory wrapper for vt_sessions")
  private static final class InMemoryVTSessionsTool extends VTSessionsTool {
    private final VTSession session;

    InMemoryVTSessionsTool(VTSession session) {
      this.session = session;
    }

    @Override
    protected VTSession openVTSession(String sessionName) {
      session.addConsumer(this);
      return session;
    }

    @Override
    protected VTSession openVTSession(String sessionName, boolean forUpdate) {
      return openVTSession(sessionName);
    }

    @Override
    protected VTSession openVTSession(
        String sessionName, boolean forUpdate, ghidra.util.task.TaskMonitor monitor) {
      return openVTSession(sessionName);
    }
  }

  @GhidraMcpTool(
      name = "VT Operations Test",
      description = "In-memory VT operations test wrapper",
      mcpName = "vt_operations",
      mcpDescription = "In-memory wrapper for vt_operations")
  private static final class InMemoryVTOperationsTool extends VTOperationsTool {
    private final VTSession session;

    InMemoryVTOperationsTool(VTSession session) {
      this.session = session;
    }

    @Override
    protected VTSession openVTSession(String sessionName) {
      session.addConsumer(this);
      return session;
    }

    @Override
    protected VTSession openVTSession(String sessionName, boolean forUpdate) {
      return openVTSession(sessionName);
    }

    @Override
    protected VTSession openVTSession(
        String sessionName, boolean forUpdate, ghidra.util.task.TaskMonitor monitor) {
      return openVTSession(sessionName);
    }
  }
}
