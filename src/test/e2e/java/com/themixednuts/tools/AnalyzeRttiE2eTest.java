package com.themixednuts.tools;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.themixednuts.models.RTTIAnalysisResult;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import io.modelcontextprotocol.common.McpTransportContext;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import reactor.core.publisher.Mono;

class AnalyzeRttiE2eTest {

  private static final long IMAGE_SCN_MEM_EXECUTE = 0x20000000L;
  private static final long IMAGE_SCN_MEM_READ = 0x40000000L;
  private static final long IMAGE_SCN_MEM_WRITE = 0x80000000L;

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
    String rtti2Address =
        RttiFixtureSupport.findAddressForSymbol(
            artifacts.mapPath(), "??_R2Diamond@@8", "msvc_rtti_fixture.obj");
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
      configurePeMetadata(program);
      mapPortableExecutableIntoProgram(builder, program, artifacts.exePath());

      AnalyzeRttiTool tool = new InMemoryAnalyzeRttiTool(program);
      McpTransportContext context = Mockito.mock(McpTransportContext.class);
      ghidra.framework.plugintool.PluginTool pluginTool =
          Mockito.mock(ghidra.framework.plugintool.PluginTool.class);

      assertDetectedType(
          tool, context, pluginTool, "msvc_rtti_fixture",
          rtti4Address, RTTIAnalysisResult.RttiType.RTTI4);
      assertDetectedType(
          tool, context, pluginTool, "msvc_rtti_fixture",
          rtti3Address, RTTIAnalysisResult.RttiType.RTTI3);

      // RTTI2 (BaseClassArray) cannot be detected standalone: the tool creates
      // Rtti2Model with count=0, so it cannot determine the array length.
      // Assert that the tool correctly returns UNKNOWN for standalone RTTI2 probing.
      assertDetectedAsUnknown(tool, context, pluginTool, "msvc_rtti_fixture", rtti2Address);

      assertDetectedType(
          tool, context, pluginTool, "msvc_rtti_fixture",
          rtti1Address, RTTIAnalysisResult.RttiType.RTTI1);
      assertDetectedType(
          tool, context, pluginTool, "msvc_rtti_fixture",
          rtti0Address, RTTIAnalysisResult.RttiType.RTTI0);
      assertDetectedType(
          tool, context, pluginTool, "msvc_rtti_fixture",
          vftableAddress, RTTIAnalysisResult.RttiType.VFTABLE);
    } finally {
      builder.dispose();
    }
  }

  /**
   * Configures the in-memory program with PE metadata required by Ghidra's RTTI validation.
   * The {@code isWindows()} check in {@code AbstractCreateDataTypeModel} requires:
   * <ul>
   *   <li>Compiler spec ID = "windows"</li>
   *   <li>Executable format = "Portable Executable (PE)"</li>
   *   <li>Compiler string matching {@code CompilerEnum.VisualStudio.toString()}</li>
   * </ul>
   */
  private static void configurePeMetadata(Program program) throws Exception {
    ghidra.program.database.ProgramDB db = (ghidra.program.database.ProgramDB) program;
    int txId = program.startTransaction("Set PE metadata");
    boolean commit = false;
    try {
      db.setExecutableFormat("Portable Executable (PE)");
      db.setCompiler(
          ghidra.app.util.opinion.PeLoader.CompilerOpinion.CompilerEnum.VisualStudio.toString());
      commit = true;
    } finally {
      program.endTransaction(txId, commit);
    }
  }

  private static void mapPortableExecutableIntoProgram(
      ProgramBuilder builder, Program program, Path exePath) throws Exception {
    byte[] bytes = Files.readAllBytes(exePath);
    int peOffset = (int) readUInt32LE(bytes, 0x3c);
    int numberOfSections = readUInt16LE(bytes, peOffset + 6);
    int optionalHeaderSize = readUInt16LE(bytes, peOffset + 20);
    int optionalHeaderOffset = peOffset + 24;
    long imageBase = readUInt64LE(bytes, optionalHeaderOffset + 24);
    int sectionTableOffset = optionalHeaderOffset + optionalHeaderSize;

    AddressSpace defaultSpace = program.getAddressFactory().getDefaultAddressSpace();
    Address imageBaseAddress = defaultSpace.getAddress(imageBase);

    int txId = program.startTransaction("Map PE fixture");
    boolean commit = false;
    try {
      setImageBase(program, imageBaseAddress);

      for (int i = 0; i < numberOfSections; i++) {
        int sectionOffset = sectionTableOffset + (i * 40);

        String sectionName = readSectionName(bytes, sectionOffset);
        long virtualSize = readUInt32LE(bytes, sectionOffset + 8);
        long virtualAddress = readUInt32LE(bytes, sectionOffset + 12);
        long rawSize = readUInt32LE(bytes, sectionOffset + 16);
        long rawPointer = readUInt32LE(bytes, sectionOffset + 20);
        long characteristics = readUInt32LE(bytes, sectionOffset + 36);

        long mappedSize = Math.max(virtualSize, rawSize);
        if (mappedSize <= 0) {
          continue;
        }

        long maxReadable = Math.max(0L, bytes.length - rawPointer);
        int initializedLength = (int) Math.min(rawSize, maxReadable);

        Address sectionStart = defaultSpace.getAddress(imageBase + virtualAddress);
        String sectionStartString = toAddressString(sectionStart.getOffset());

        if (mappedSize > Integer.MAX_VALUE) {
          throw new IllegalStateException("Section too large for test fixture mapping: " + sectionName);
        }

        MemoryBlock block = builder.createMemory(sectionName, sectionStartString, (int) mappedSize);
        setPermissions(block, characteristics);

        if (initializedLength > 0) {
          byte[] sectionBytes =
              java.util.Arrays.copyOfRange(
                  bytes, (int) rawPointer, (int) rawPointer + initializedLength);
          builder.setBytes(sectionStartString, sectionBytes);
        }
      }

      commit = true;
    } finally {
      program.endTransaction(txId, commit);
    }
  }

  private static void setPermissions(MemoryBlock block, long characteristics) {
    boolean read = (characteristics & IMAGE_SCN_MEM_READ) != 0;
    boolean write = (characteristics & IMAGE_SCN_MEM_WRITE) != 0;
    boolean execute = (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
    block.setPermissions(read, write, execute);
  }

  private static void setImageBase(Program program, Address imageBaseAddress) throws Exception {
    try {
      java.lang.reflect.Method setImageBaseMethod =
          program.getClass().getMethod("setImageBase", Address.class, boolean.class);
      setImageBaseMethod.invoke(program, imageBaseAddress, true);
    } catch (java.lang.reflect.InvocationTargetException e) {
      Throwable cause = e.getCause();
      if (cause instanceof Exception ex) {
        throw ex;
      }
      throw e;
    }
  }

  private static String toAddressString(long addressOffset) {
    return String.format("0x%x", addressOffset);
  }

  private static int readUInt16LE(byte[] data, int offset) {
    return (data[offset] & 0xff) | ((data[offset + 1] & 0xff) << 8);
  }

  private static long readUInt32LE(byte[] data, int offset) {
    return (data[offset] & 0xffL)
        | ((data[offset + 1] & 0xffL) << 8)
        | ((data[offset + 2] & 0xffL) << 16)
        | ((data[offset + 3] & 0xffL) << 24);
  }

  private static long readUInt64LE(byte[] data, int offset) {
    return (data[offset] & 0xffL)
        | ((data[offset + 1] & 0xffL) << 8)
        | ((data[offset + 2] & 0xffL) << 16)
        | ((data[offset + 3] & 0xffL) << 24)
        | ((data[offset + 4] & 0xffL) << 32)
        | ((data[offset + 5] & 0xffL) << 40)
        | ((data[offset + 6] & 0xffL) << 48)
        | ((data[offset + 7] & 0xffL) << 56);
  }

  private static String readSectionName(byte[] data, int sectionOffset) {
    int end = sectionOffset;
    while (end < sectionOffset + 8 && data[end] != 0) {
      end++;
    }
    String name = new String(data, sectionOffset, end - sectionOffset, java.nio.charset.StandardCharsets.US_ASCII);
    return name.isBlank() ? "section" + sectionOffset : name;
  }

  private static void assertDetectedType(
      AnalyzeRttiTool tool,
      McpTransportContext context,
      ghidra.framework.plugintool.PluginTool pluginTool,
      String fileName,
      String address,
      RTTIAnalysisResult.RttiType expectedType) {
    Object rawResult =
        tool.execute(
                context,
                Map.of(
                    "file_name", fileName,
                    "address", address,
                    "validate_referred_to_data", false,
                    "ignore_instructions", true,
                    "ignore_defined_data", true),
                pluginTool)
            .block();

    RTTIAnalysisResult result = assertInstanceOf(RTTIAnalysisResult.class, rawResult);
    String detail = "";
    if (result instanceof RTTIAnalysisResult.InvalidResult inv) {
      detail = " error=" + inv.error() + " attemptedType=" + inv.attemptedType();
    }
    assertTrue(result.isValid(), "Expected valid RTTI result at " + address + detail);
    assertEquals(expectedType, result.rttiType(), "Unexpected RTTI type at " + address);
  }

  private static void assertDetectedAsUnknown(
      AnalyzeRttiTool tool,
      McpTransportContext context,
      ghidra.framework.plugintool.PluginTool pluginTool,
      String fileName,
      String address) {
    Object rawResult =
        tool.execute(
                context,
                Map.of(
                    "file_name", fileName,
                    "address", address,
                    "validate_referred_to_data", false,
                    "ignore_instructions", true,
                    "ignore_defined_data", true),
                pluginTool)
            .block();

    RTTIAnalysisResult result = assertInstanceOf(RTTIAnalysisResult.class, rawResult);
    assertFalse(result.isValid(), "Expected invalid RTTI result at " + address);
    assertEquals(
        RTTIAnalysisResult.RttiType.UNKNOWN,
        result.rttiType(),
        "Expected UNKNOWN type for standalone RTTI2 probe at " + address);
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
