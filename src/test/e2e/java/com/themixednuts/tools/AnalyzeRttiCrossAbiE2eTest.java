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
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Locale;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import reactor.core.publisher.Mono;

class AnalyzeRttiCrossAbiE2eTest {

  @Test
  void analyzeRttiRejectsGoBackendForItaniumAddress() throws Exception {
    assumeTrue(Boolean.getBoolean("rtti.integration"), "Set -Drtti.integration=true to run");
    assumeTrue(RttiFixtureSupport.isWindows(), "Cross-ABI PE fixture tests require Windows");

    Path repoRoot = Paths.get("").toAbsolutePath();
    assumeTrue(
        CrossAbiRttiFixtureSupport.hasToolchainForItanium(repoRoot),
        "Skipping: g++/clang++ toolchain unavailable for Itanium fixture build");

    CrossAbiRttiFixtureSupport.ItaniumFixtureArtifacts artifacts =
        CrossAbiRttiFixtureSupport.buildItaniumPeFixture(repoRoot);
    String typeInfoAddress =
        CrossAbiRttiFixtureSupport.findAddressForSymbol(artifacts.nmRawPath(), "_ZTI7Diamond");

    GhidraE2eRuntimeSupport.ensureGhidraRuntimeInitialized(repoRoot);

    Object consumer = new Object();
    ProgramBuilder builder;
    Program program;
    try {
      builder = new ProgramBuilder("itanium_rtti_fixture", ProgramBuilder._X64, "windows", consumer);
      program = builder.getProgram();
    } catch (Throwable t) {
      assumeTrue(false, "Skipping: Ghidra x64 language runtime unavailable: " + t.getMessage());
      return;
    }

    try {
      PeProgramMappingSupport.mapPortableExecutableIntoProgram(builder, program, artifacts.exePath());

      AnalyzeRttiTool tool = new InMemoryAnalyzeRttiTool(program);
      McpTransportContext context = Mockito.mock(McpTransportContext.class);
      ghidra.framework.plugintool.PluginTool pluginTool =
          Mockito.mock(ghidra.framework.plugintool.PluginTool.class);

      RTTIAnalysisResult invalid =
          executeAnalyze(
              tool,
              context,
              pluginTool,
              "itanium_rtti_fixture",
              typeInfoAddress,
              "go");
      assertInvalidResult(invalid, typeInfoAddress, "go");
    } finally {
      builder.dispose();
    }
  }

  @Test
  void analyzeRttiRejectsItaniumAndMicrosoftBackendsForGoAddress() throws Exception {
    assumeTrue(Boolean.getBoolean("rtti.integration"), "Set -Drtti.integration=true to run");
    assumeTrue(RttiFixtureSupport.isWindows(), "Cross-ABI PE fixture tests require Windows");

    Path repoRoot = Paths.get("").toAbsolutePath();
    assumeTrue(
        CrossAbiRttiFixtureSupport.hasToolchainForGo(repoRoot),
        "Skipping: Go toolchain unavailable for Go fixture build");

    CrossAbiRttiFixtureSupport.GoFixtureArtifacts artifacts =
        CrossAbiRttiFixtureSupport.buildGoPeFixture(repoRoot);
    String goTypeAddress =
        CrossAbiRttiFixtureSupport.findAddressForAnySymbol(
            artifacts.nmPath(),
            "type:*main.WorkerImpl",
            "type:main.WorkerImpl",
            "type:main.Worker");

    GhidraE2eRuntimeSupport.ensureGhidraRuntimeInitialized(repoRoot);

    Object consumer = new Object();
    ProgramBuilder builder;
    Program program;
    try {
      builder = new ProgramBuilder("go_rtti_fixture", ProgramBuilder._X64, "windows", consumer);
      program = builder.getProgram();
    } catch (Throwable t) {
      assumeTrue(false, "Skipping: Ghidra x64 language runtime unavailable: " + t.getMessage());
      return;
    }

    try {
      PeProgramMappingSupport.mapPortableExecutableIntoProgram(builder, program, artifacts.exePath());

      AnalyzeRttiTool tool = new InMemoryAnalyzeRttiTool(program);
      McpTransportContext context = Mockito.mock(McpTransportContext.class);
      ghidra.framework.plugintool.PluginTool pluginTool =
          Mockito.mock(ghidra.framework.plugintool.PluginTool.class);

      RTTIAnalysisResult itaniumInvalid =
          executeAnalyze(tool, context, pluginTool, "go_rtti_fixture", goTypeAddress, "itanium");
      assertInvalidResult(itaniumInvalid, goTypeAddress, "itanium");

      RTTIAnalysisResult microsoftInvalid =
          executeAnalyze(tool, context, pluginTool, "go_rtti_fixture", goTypeAddress, "microsoft");
      assertInvalidResult(microsoftInvalid, goTypeAddress, "microsoft");
    } finally {
      builder.dispose();
    }
  }

  @Test
  void analyzeRttiDetectsItaniumTypeinfoAndVtable() throws Exception {
    assumeTrue(Boolean.getBoolean("rtti.integration"), "Set -Drtti.integration=true to run");
    assumeTrue(RttiFixtureSupport.isWindows(), "Cross-ABI PE fixture tests require Windows");

    Path repoRoot = Paths.get("").toAbsolutePath();
    assumeTrue(
        CrossAbiRttiFixtureSupport.hasToolchainForItanium(repoRoot),
        "Skipping: g++/clang++ toolchain unavailable for Itanium fixture build");

    CrossAbiRttiFixtureSupport.ItaniumFixtureArtifacts artifacts =
        CrossAbiRttiFixtureSupport.buildItaniumPeFixture(repoRoot);

    String typeInfoAddress =
        CrossAbiRttiFixtureSupport.findAddressForSymbol(artifacts.nmRawPath(), "_ZTI7Diamond");
    String vtableAddress =
        CrossAbiRttiFixtureSupport.findAddressForSymbol(artifacts.nmRawPath(), "_ZTV7Diamond");

    GhidraE2eRuntimeSupport.ensureGhidraRuntimeInitialized(repoRoot);

    Object consumer = new Object();
    ProgramBuilder builder;
    Program program;
    try {
      builder = new ProgramBuilder("itanium_rtti_fixture", ProgramBuilder._X64, "windows", consumer);
      program = builder.getProgram();
    } catch (Throwable t) {
      assumeTrue(false, "Skipping: Ghidra x64 language runtime unavailable: " + t.getMessage());
      return;
    }

    try {
      PeProgramMappingSupport.mapPortableExecutableIntoProgram(builder, program, artifacts.exePath());

      AnalyzeRttiTool tool = new InMemoryAnalyzeRttiTool(program);
      McpTransportContext context = Mockito.mock(McpTransportContext.class);
      ghidra.framework.plugintool.PluginTool pluginTool =
          Mockito.mock(ghidra.framework.plugintool.PluginTool.class);

      RTTIAnalysisResult typeInfoResult =
          executeAnalyze(
              tool,
              context,
              pluginTool,
              "itanium_rtti_fixture",
              typeInfoAddress,
              "itanium");
      assertValidType(
          typeInfoResult, typeInfoAddress, RTTIAnalysisResult.RttiType.ITANIUM_VMI_CLASS_TYPEINFO);
      RTTIAnalysisResult.ItaniumVmiClassTypeInfoResult typedTypeInfo =
          assertInstanceOf(RTTIAnalysisResult.ItaniumVmiClassTypeInfoResult.class, typeInfoResult);
      assertTrue(typedTypeInfo.data().symbolName().startsWith("_ZTI"));
      assertTrue(typedTypeInfo.data().classTypeInfoVtableAddress().isPresent());
      assertTrue(typedTypeInfo.data().numBaseClasses() > 0);
      assertTrue(!typedTypeInfo.data().baseClasses().isEmpty());
      assertTrue(
          typedTypeInfo.data().representedType().map(s -> s.contains("Diamond")).orElse(false)
              || typedTypeInfo.data().demangledSymbol().map(s -> s.contains("Diamond")).orElse(false)
              || typedTypeInfo.data().symbolName().contains("Diamond"));

      RTTIAnalysisResult vtableResult =
          executeAnalyze(
          tool,
          context,
          pluginTool,
          "itanium_rtti_fixture",
          vtableAddress,
          "itanium");
      assertValidType(vtableResult, vtableAddress, RTTIAnalysisResult.RttiType.ITANIUM_VTABLE);
      RTTIAnalysisResult.ItaniumVtableResult typedVtable =
          assertInstanceOf(RTTIAnalysisResult.ItaniumVtableResult.class, vtableResult);
      assertTrue(typedVtable.data().symbolName().startsWith("_ZTV"));
      assertTrue(typedVtable.data().typeInfoAddress().isPresent());
      assertTrue(!typedVtable.data().virtualFunctionPointers().isEmpty());
      assertAddressEquals(
          program,
          typeInfoAddress,
          typedVtable.data().typeInfoAddress().orElseThrow(),
          "Itanium vtable typeinfo pointer should match queried typeinfo symbol");
    } finally {
      builder.dispose();
    }
  }

  @Test
  void analyzeRttiDetectsGoTypeAndGoItab() throws Exception {
    assumeTrue(Boolean.getBoolean("rtti.integration"), "Set -Drtti.integration=true to run");
    assumeTrue(RttiFixtureSupport.isWindows(), "Cross-ABI PE fixture tests require Windows");

    Path repoRoot = Paths.get("").toAbsolutePath();
    assumeTrue(
        CrossAbiRttiFixtureSupport.hasToolchainForGo(repoRoot),
        "Skipping: Go toolchain unavailable for Go fixture build");

    CrossAbiRttiFixtureSupport.GoFixtureArtifacts artifacts =
        CrossAbiRttiFixtureSupport.buildGoPeFixture(repoRoot);

    String goTypeAddress =
        CrossAbiRttiFixtureSupport.findAddressForAnySymbol(
            artifacts.nmPath(),
            "type:*main.WorkerImpl",
            "type:main.WorkerImpl",
            "type:main.Worker");
    String goItabAddress =
        CrossAbiRttiFixtureSupport.findAddressForAnySymbol(
            artifacts.nmPath(),
            "go:itab.*main.WorkerImpl,main.Worker",
            "go:itab.main.WorkerImpl,main.Worker",
            "go:itab.*main.Worker");

    GhidraE2eRuntimeSupport.ensureGhidraRuntimeInitialized(repoRoot);

    Object consumer = new Object();
    ProgramBuilder builder;
    Program program;
    try {
      builder = new ProgramBuilder("go_rtti_fixture", ProgramBuilder._X64, "windows", consumer);
      program = builder.getProgram();
    } catch (Throwable t) {
      assumeTrue(false, "Skipping: Ghidra x64 language runtime unavailable: " + t.getMessage());
      return;
    }

    try {
      PeProgramMappingSupport.mapPortableExecutableIntoProgram(builder, program, artifacts.exePath());

      AnalyzeRttiTool tool = new InMemoryAnalyzeRttiTool(program);
      McpTransportContext context = Mockito.mock(McpTransportContext.class);
      ghidra.framework.plugintool.PluginTool pluginTool =
          Mockito.mock(ghidra.framework.plugintool.PluginTool.class);

      RTTIAnalysisResult goTypeResult =
          executeAnalyze(
              tool,
              context,
              pluginTool,
              "go_rtti_fixture",
              goTypeAddress,
              "go");
      assertValidType(goTypeResult, goTypeAddress, RTTIAnalysisResult.RttiType.GO_TYPE);
      RTTIAnalysisResult.GoTypeResult typedGoType =
          assertInstanceOf(RTTIAnalysisResult.GoTypeResult.class, goTypeResult);
      assertTrue(!typedGoType.data().name().isBlank());
      assertTrue(!typedGoType.data().fullyQualifiedName().isBlank());
      assertTrue(typedGoType.data().fullyQualifiedName().contains("main."));
      assertTrue(typedGoType.data().runtimeTypeClass().contains("golang.rtti.types"));
      assertTrue(typedGoType.data().typeOffset() >= 0);
      assertTrue(typedGoType.data().typeAddress().startsWith("0x"));
      assertAddressEquals(
          program,
          goTypeAddress,
          typedGoType.data().typeAddress(),
          "Go type record address should match queried go type symbol");

      RTTIAnalysisResult goItabResult =
          executeAnalyze(
          tool,
          context,
          pluginTool,
          "go_rtti_fixture",
          goItabAddress,
          "go");
      assertValidType(goItabResult, goItabAddress, RTTIAnalysisResult.RttiType.GO_ITAB);
      RTTIAnalysisResult.GoItabResult typedGoItab =
          assertInstanceOf(RTTIAnalysisResult.GoItabResult.class, goItabResult);
      assertTrue(typedGoItab.data().concreteType().isPresent());
      assertTrue(typedGoItab.data().interfaceType().isPresent());
      assertTrue(typedGoItab.data().concreteType().orElse("").contains("WorkerImpl"));
      assertTrue(typedGoItab.data().interfaceType().orElse("").contains("Worker"));
      assertTrue(typedGoItab.data().functionCount().orElse(0L) > 0);
      assertEquals(
          normalizeGoTypeName(typedGoType.data().fullyQualifiedName()),
          normalizeGoTypeName(typedGoItab.data().concreteType().orElse("")),
          "Go itab concrete type should link to queried go type result");
    } finally {
      builder.dispose();
    }
  }

  private static RTTIAnalysisResult executeAnalyze(
      AnalyzeRttiTool tool,
      McpTransportContext context,
      ghidra.framework.plugintool.PluginTool pluginTool,
      String fileName,
      String address,
      String backend) {
    Object rawResult =
        tool.execute(
                context,
                Map.of(
                    "file_name", fileName,
                    "address", address,
                    "backend", backend,
                    "validate_referred_to_data", false,
                    "ignore_instructions", true,
                    "ignore_defined_data", true),
                pluginTool)
            .block();

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

  private static String normalizeGoTypeName(String value) {
    if (value == null) {
      return "";
    }
    return value.replaceFirst("^\\*", "");
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
