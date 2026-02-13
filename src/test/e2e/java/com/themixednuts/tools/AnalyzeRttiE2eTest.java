package com.themixednuts.tools;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.themixednuts.models.RTTIAnalysisResult;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.common.McpTransportContext;
import java.util.Locale;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import reactor.core.publisher.Mono;

class AnalyzeRttiE2eTest {

  @Test
  void analyzeRttiRejectsItaniumBackendForMicrosoftAddress() throws Exception {
    assumeTrue(Boolean.getBoolean("rtti.integration"), "Set -Drtti.integration=true to run");
    assumeTrue(RttiFixtureSupport.isWindows(), "MSVC fixture build requires Windows");

    Path repoRoot = Paths.get("").toAbsolutePath();
    RttiFixtureSupport.FixtureArtifacts artifacts = RttiFixtureSupport.buildMsvcX64Fixture(repoRoot);
    String rtti4Address =
        RttiFixtureSupport.findAddressForSymbol(
            artifacts.mapPath(), "??_R4Diamond@@6B@", "msvc_rtti_fixture.obj");

    GhidraE2eRuntimeSupport.ensureGhidraRuntimeInitialized(repoRoot);

    Object consumer = new Object();
    ProgramBuilder builder;
    Program program;
    try {
      builder = new ProgramBuilder("msvc_rtti_fixture", ProgramBuilder._X64, "windows", consumer);
      program = builder.getProgram();
    } catch (Throwable t) {
      assumeTrue(false, "Skipping: Ghidra x64 language runtime unavailable: " + t.getMessage());
      return;
    }

    try {
      PeProgramMappingSupport.configurePeMetadataForVisualStudio(program);
      PeProgramMappingSupport.mapPortableExecutableIntoProgram(builder, program, artifacts.exePath());

      AnalyzeRttiTool tool = new InMemoryAnalyzeRttiTool(program);
      McpTransportContext context = Mockito.mock(McpTransportContext.class);
      ghidra.framework.plugintool.PluginTool pluginTool =
          Mockito.mock(ghidra.framework.plugintool.PluginTool.class);

      RTTIAnalysisResult invalid =
          executeAnalyze(tool, context, pluginTool, "msvc_rtti_fixture", rtti4Address, "itanium");
      assertInvalidResult(invalid, rtti4Address, "itanium");
    } finally {
      builder.dispose();
    }
  }

  @Test
  void analyzeRttiMatchesExpectedTypesForFixtureMapAddresses() throws Exception {
    assumeTrue(Boolean.getBoolean("rtti.integration"), "Set -Drtti.integration=true to run");
    assumeTrue(RttiFixtureSupport.isWindows(), "MSVC fixture build requires Windows");

    Path repoRoot = Paths.get("").toAbsolutePath();
    RttiFixtureSupport.FixtureArtifacts artifacts = RttiFixtureSupport.buildMsvcX64Fixture(repoRoot);

    String rtti4Address =
        RttiFixtureSupport.findAddressForSymbol(
            artifacts.mapPath(), "??_R4Diamond@@6B@", "msvc_rtti_fixture.obj");
    String rtti3Address =
        RttiFixtureSupport.findAddressForSymbol(
            artifacts.mapPath(), "??_R3Diamond@@8", "msvc_rtti_fixture.obj");
    String rtti1Address =
        RttiFixtureSupport.findAddressForSymbol(
            artifacts.mapPath(), "??_R1A@?0A@EA@Diamond@@8", "msvc_rtti_fixture.obj");
    String rtti0Address =
        RttiFixtureSupport.findAddressForSymbol(
            artifacts.mapPath(), "??_R0?AUDiamond@@@8", "msvc_rtti_fixture.obj");
    String vftableAddress =
        RttiFixtureSupport.findAddressForSymbol(
            artifacts.mapPath(), "??_7Diamond@@6B@", "msvc_rtti_fixture.obj");

    GhidraE2eRuntimeSupport.ensureGhidraRuntimeInitialized(repoRoot);

    Object consumer = new Object();
    ProgramBuilder builder;
    Program program;
    try {
      builder = new ProgramBuilder("msvc_rtti_fixture", ProgramBuilder._X64, "windows", consumer);
      program = builder.getProgram();
    } catch (Throwable t) {
      assumeTrue(false, "Skipping: Ghidra x64 language runtime unavailable: " + t.getMessage());
      return;
    }

    try {
      PeProgramMappingSupport.configurePeMetadataForVisualStudio(program);
      PeProgramMappingSupport.mapPortableExecutableIntoProgram(builder, program, artifacts.exePath());

      AnalyzeRttiTool tool = new InMemoryAnalyzeRttiTool(program);
      McpTransportContext context = Mockito.mock(McpTransportContext.class);
      ghidra.framework.plugintool.PluginTool pluginTool =
          Mockito.mock(ghidra.framework.plugintool.PluginTool.class);

      RTTIAnalysisResult rtti4Result =
          executeAnalyze(tool, context, pluginTool, "msvc_rtti_fixture", rtti4Address);
      assertValidType(rtti4Result, rtti4Address, RTTIAnalysisResult.RttiType.RTTI4);
      RTTIAnalysisResult.Rtti4Result typedRtti4 =
          assertInstanceOf(RTTIAnalysisResult.Rtti4Result.class, rtti4Result);
      assertTrue(typedRtti4.data().rtti0Address().isPresent());
      assertTrue(typedRtti4.data().rtti3Address().isPresent());
      assertTrue(!typedRtti4.data().baseClassTypes().isEmpty());
      assertAddressEquals(
          program,
          rtti3Address,
          typedRtti4.data().rtti3Address().orElseThrow(),
          "RTTI4.rtti3Address should match RTTI3 fixture symbol");
      assertAddressEquals(
          program,
          rtti0Address,
          typedRtti4.data().rtti0Address().orElseThrow(),
          "RTTI4.rtti0Address should match RTTI0 fixture symbol");

      RTTIAnalysisResult rtti3Result =
          executeAnalyze(tool, context, pluginTool, "msvc_rtti_fixture", rtti3Address);
      assertValidType(rtti3Result, rtti3Address, RTTIAnalysisResult.RttiType.RTTI3);
      RTTIAnalysisResult.Rtti3Result typedRtti3 =
          assertInstanceOf(RTTIAnalysisResult.Rtti3Result.class, rtti3Result);
      assertTrue(typedRtti3.data().rtti1Count().orElse(0) > 0);
      assertTrue(typedRtti3.data().rtti2Address().isPresent());
      assertTrue(!typedRtti3.data().baseClassTypes().isEmpty());
      assertAddressEquals(
          program,
          rtti0Address,
          typedRtti3.data().rtti0Address().orElseThrow(),
          "RTTI3.rtti0Address should match RTTI0 fixture symbol");

      RTTIAnalysisResult rtti1Result =
          executeAnalyze(tool, context, pluginTool, "msvc_rtti_fixture", rtti1Address);
      assertValidType(rtti1Result, rtti1Address, RTTIAnalysisResult.RttiType.RTTI1);
      RTTIAnalysisResult.Rtti1Result typedRtti1 =
          assertInstanceOf(RTTIAnalysisResult.Rtti1Result.class, rtti1Result);
      assertTrue(typedRtti1.data().rtti0Address().isPresent());
      assertTrue(typedRtti1.data().rtti3Address().isPresent());
      assertAddressEquals(
          program,
          rtti0Address,
          typedRtti1.data().rtti0Address().orElseThrow(),
          "RTTI1.rtti0Address should match RTTI0 fixture symbol");
      assertAddressEquals(
          program,
          rtti3Address,
          typedRtti1.data().rtti3Address().orElseThrow(),
          "RTTI1.rtti3Address should match RTTI3 fixture symbol");

      RTTIAnalysisResult rtti0Result =
          executeAnalyze(tool, context, pluginTool, "msvc_rtti_fixture", rtti0Address);
      assertValidType(rtti0Result, rtti0Address, RTTIAnalysisResult.RttiType.RTTI0);
      RTTIAnalysisResult.Rtti0Result typedRtti0 =
          assertInstanceOf(RTTIAnalysisResult.Rtti0Result.class, rtti0Result);
      assertTrue(typedRtti0.data().vfTableAddress().isPresent());
      assertTrue(typedRtti0.data().mangledName().isPresent());
      assertTrue(typedRtti0.data().mangledName().orElse("").contains("Diamond"));

      RTTIAnalysisResult vftableResult =
          executeAnalyze(tool, context, pluginTool, "msvc_rtti_fixture", vftableAddress);
      assertValidType(vftableResult, vftableAddress, RTTIAnalysisResult.RttiType.VFTABLE);
      RTTIAnalysisResult.VfTableResult typedVftable =
          assertInstanceOf(RTTIAnalysisResult.VfTableResult.class, vftableResult);
      assertTrue(typedVftable.data().elementCount() > 0);
      assertTrue(!typedVftable.data().virtualFunctionPointers().isEmpty());
      assertAddressEquals(
          program,
          rtti0Address,
          typedVftable.data().rtti0Address().orElseThrow(),
          "VfTable.rtti0Address should match RTTI0 fixture symbol");
    } finally {
      builder.dispose();
    }
  }

  private static RTTIAnalysisResult executeAnalyze(
      AnalyzeRttiTool tool,
      McpTransportContext context,
      ghidra.framework.plugintool.PluginTool pluginTool,
      String fileName,
      String address) {
    return executeAnalyze(tool, context, pluginTool, fileName, address, null);
  }

  private static RTTIAnalysisResult executeAnalyze(
      AnalyzeRttiTool tool,
      McpTransportContext context,
      ghidra.framework.plugintool.PluginTool pluginTool,
      String fileName,
      String address,
      String backend) {
    Map<String, Object> args = new HashMap<>();
    args.put("file_name", fileName);
    args.put("address", address);
    args.put("validate_referred_to_data", false);
    args.put("ignore_instructions", true);
    args.put("ignore_defined_data", true);
    if (backend != null) {
      args.put("backend", backend);
    }

    Object rawResult =
        tool.execute(context, args, pluginTool).block();

    return assertInstanceOf(RTTIAnalysisResult.class, rawResult);
  }

  private static void assertValidType(
      RTTIAnalysisResult result, String address, RTTIAnalysisResult.RttiType expectedType) {
    String detail = "";
    if (result instanceof RTTIAnalysisResult.InvalidResult inv) {
      detail = " error=" + inv.error() + " attemptedType=" + inv.attemptedType();
    }
    assertTrue(result.isValid(), "Expected valid RTTI result at " + address + detail);
    assertEquals(expectedType, result.rttiType(), "Unexpected RTTI type at " + address);
  }

  private static void assertInvalidResult(
      RTTIAnalysisResult result, String address, String backend) {
    RTTIAnalysisResult.InvalidResult invalid =
        assertInstanceOf(RTTIAnalysisResult.InvalidResult.class, result);
    assertFalse(invalid.isValid(), "Expected invalid RTTI result at " + address);
    assertEquals(RTTIAnalysisResult.RttiType.UNKNOWN, invalid.rttiType());
    assertTrue(invalid.error().contains("No valid RTTI structure"));
    assertTrue(invalid.error().contains(backend + "="));
  }

  private static void assertAddressEquals(
      Program program, String expectedAddress, String actualAddress, String message) {
    assertEquals(
        canonicalAddress(program, expectedAddress),
        canonicalAddress(program, actualAddress),
        message);
  }

  private static String canonicalAddress(Program program, String addressText) {
    if (addressText == null || addressText.isBlank()) {
      return "";
    }

    Address parsed = program.getAddressFactory().getAddress(addressText);
    if (parsed != null) {
      return parsed.toString();
    }

    if (!addressText.startsWith("0x") && !addressText.contains(":")) {
      parsed = program.getAddressFactory().getAddress("0x" + addressText);
      if (parsed != null) {
        return parsed.toString();
      }
    }

    return addressText.toLowerCase(Locale.ROOT);
  }

  private static final class InMemoryAnalyzeRttiTool extends AnalyzeRttiTool {
    private final Program program;

    InMemoryAnalyzeRttiTool(Program program) {
      this.program = program;
    }

    @Override
    protected Mono<Program> getProgram(
        java.util.Map<String, Object> args, ghidra.framework.plugintool.PluginTool tool) {
      return Mono.just(program);
    }
  }
}
