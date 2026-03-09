package com.themixednuts.tools;

import ghidra.feature.vt.api.db.VTSessionDB;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import java.lang.reflect.Field;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Creates a pair of in-memory x64 programs connected by a VTSessionDB for VT E2E tests. Sets
 * Ghidra's testing mode to bypass VTSessionDB's read-only check on in-memory programs.
 */
final class VTFixtureSupport {

  private VTFixtureSupport() {}

  /**
   * Creates a VT fixture with source ("source_v1") and destination ("dest_v2") programs, plus a
   * VTSessionDB linking them. The programs are designed so that running standard correlators
   * produces predictable, testable matches and edge-case non-matches.
   */
  static VTFixture createVTFixture() throws Exception {
    Path repoRoot = Paths.get("").toAbsolutePath();
    GhidraE2eRuntimeSupport.ensureGhidraRuntimeInitialized(repoRoot);

    forceEnableSystemUtilitiesTestingMode();

    Object consumer = new Object();

    // ===== Source program: well-annotated "known" version =====
    ProgramBuilder sourceBuilder = new ProgramBuilder("source_v1", ProgramBuilder._X64, consumer);
    Program sourceProgram = sourceBuilder.getProgram();

    sourceBuilder.createMemory(".text", "0x401000", 0x200);
    sourceBuilder.createMemory(".data", "0x402000", 0x200);

    // Functions
    sourceBuilder.setBytes("0x401000", "55 48 89 e5 b8 2a 00 00 00 5d c3"); // main_func
    sourceBuilder.setBytes("0x401020", "55 48 89 e5 b8 01 00 00 00 5d c3"); // helper_func
    sourceBuilder.setBytes("0x401040", "55 48 89 e5 53 b8 0a 00 00 00 5b 5d c3"); // compute_val
    sourceBuilder.setBytes("0x401060", "c3"); // tiny_ret
    sourceBuilder.setBytes("0x401070", "55 48 89 e5 90 90 90 90 b8 07 00 00 00 5d c3"); // nop_sled
    sourceBuilder.setBytes(
        "0x401080", "55 48 89 e5 48 85 ff 74 07 b8 01 00 00 00 5d c3 31 c0 5d c3"); // branch_func
    sourceBuilder.setBytes("0x4010A0", "55 48 89 e5 48 31 c0 48 ff c0 5d c3"); // dup_bytes_alpha
    sourceBuilder.setBytes("0x4010C0", "55 48 89 e5 48 31 c0 48 ff c0 5d c3"); // dup_bytes_beta
    sourceBuilder.setBytes("0x4010E0", "55 48 89 e5 b8 de ad 00 00 5d c3"); // shifted_func
    sourceBuilder.setBytes("0x401100", "55 48 89 e5 48 83 c0 01 5d c3"); // common_api
    sourceBuilder.setBytes(
        "0x401120", "55 48 89 e5 48 b8 88 77 66 55 44 33 22 11 5d c3"); // wide_imm_func
    sourceBuilder.setBytes(
        "0x401140", "55 48 89 e5 31 c0 ff c0 3d 0a 00 00 00 75 f7 5d c3"); // loop_func
    sourceBuilder.setBytes("0x401160", "55 48 89 e5 b8 ff 00 00 00 5d c3"); // old_only

    // Data
    sourceBuilder.setBytes("0x402000", "de ad be ef ca fe ba be");
    sourceBuilder.setBytes("0x402010", "01 02 03 04 05 06 07 08");
    sourceBuilder.setBytes("0x402020", "01 02 03 04 05 06 07 08");
    sourceBuilder.setBytes("0x402030", "48 65 6c 6c 6f 00");
    sourceBuilder.setBytes("0x402040", "76 31 2e 30 00");
    sourceBuilder.setBytes("0x402050", "ff 00 01 00 02 00 03 00 04 00 05 00 06 00 07 00");
    sourceBuilder.setBytes("0x402070", "42");
    sourceBuilder.setBytes("0x402080", "ff ff ff ff ff ff ff ff");

    sourceBuilder.applyDataType("0x402000", new ArrayDataType(ByteDataType.dataType, 8, 1));
    sourceBuilder.applyDataType("0x402010", new ArrayDataType(ByteDataType.dataType, 8, 1));
    sourceBuilder.applyDataType("0x402020", new ArrayDataType(ByteDataType.dataType, 8, 1));
    sourceBuilder.applyDataType("0x402030", new ArrayDataType(ByteDataType.dataType, 6, 1));
    sourceBuilder.applyDataType("0x402040", new ArrayDataType(ByteDataType.dataType, 5, 1));
    sourceBuilder.applyDataType("0x402050", new ArrayDataType(ByteDataType.dataType, 16, 1));
    sourceBuilder.applyDataType("0x402070", new ArrayDataType(ByteDataType.dataType, 1, 1));
    sourceBuilder.applyDataType("0x402080", new ArrayDataType(ByteDataType.dataType, 8, 1));

    sourceBuilder.disassemble("0x401000", 11);
    sourceBuilder.disassemble("0x401020", 11);
    sourceBuilder.disassemble("0x401040", 13);
    sourceBuilder.disassemble("0x401060", 1);
    sourceBuilder.disassemble("0x401070", 15);
    sourceBuilder.disassemble("0x401080", 20);
    sourceBuilder.disassemble("0x4010A0", 12);
    sourceBuilder.disassemble("0x4010C0", 12);
    sourceBuilder.disassemble("0x4010E0", 11);
    sourceBuilder.disassemble("0x401100", 10);
    sourceBuilder.disassemble("0x401120", 16);
    sourceBuilder.disassemble("0x401140", 17);
    sourceBuilder.disassemble("0x401160", 11);

    sourceBuilder.createFunction("0x401000");
    sourceBuilder.createFunction("0x401020");
    sourceBuilder.createFunction("0x401040");
    sourceBuilder.createFunction("0x401060");
    sourceBuilder.createFunction("0x401070");
    sourceBuilder.createFunction("0x401080");
    sourceBuilder.createFunction("0x4010A0");
    sourceBuilder.createFunction("0x4010C0");
    sourceBuilder.createFunction("0x4010E0");
    sourceBuilder.createFunction("0x401100");
    sourceBuilder.createFunction("0x401120");
    sourceBuilder.createFunction("0x401140");
    sourceBuilder.createFunction("0x401160");

    sourceBuilder.createLabel("0x401000", "main_func");
    sourceBuilder.createLabel("0x401020", "helper_func");
    sourceBuilder.createLabel("0x401040", "compute_val");
    sourceBuilder.createLabel("0x401060", "tiny_ret");
    sourceBuilder.createLabel("0x401070", "nop_sled");
    sourceBuilder.createLabel("0x401080", "branch_func");
    sourceBuilder.createLabel("0x4010A0", "dup_bytes_alpha");
    sourceBuilder.createLabel("0x4010C0", "dup_bytes_beta");
    sourceBuilder.createLabel("0x4010E0", "shifted_func");
    sourceBuilder.createLabel("0x401100", "common_api");
    sourceBuilder.createLabel("0x401120", "wide_imm_func");
    sourceBuilder.createLabel("0x401140", "loop_func");
    sourceBuilder.createLabel("0x401160", "old_only");

    int srcTxId = sourceProgram.startTransaction("Add source annotations");
    boolean srcCommit = false;
    try {
      MemoryBlock srcText = sourceProgram.getMemory().getBlock(".text");
      srcText.setPermissions(true, false, true);
      MemoryBlock srcData = sourceProgram.getMemory().getBlock(".data");
      srcData.setPermissions(true, true, false);

      sourceProgram
          .getListing()
          .setComment(
              sourceProgram.getAddressFactory().getAddress("0x401000"),
              CodeUnit.EOL_COMMENT,
              "Entry point - returns 42");
      sourceProgram
          .getListing()
          .setComment(
              sourceProgram.getAddressFactory().getAddress("0x401020"),
              CodeUnit.PLATE_COMMENT,
              "Helper function");
      sourceProgram
          .getListing()
          .setComment(
              sourceProgram.getAddressFactory().getAddress("0x401080"),
              CodeUnit.PRE_COMMENT,
              "Branch-heavy control flow");
      sourceProgram
          .getListing()
          .setComment(
              sourceProgram.getAddressFactory().getAddress("0x401140"),
              CodeUnit.EOL_COMMENT,
              "Loop with backward jump");
      sourceProgram
          .getListing()
          .setComment(
              sourceProgram.getAddressFactory().getAddress("0x401100"),
              CodeUnit.REPEATABLE_COMMENT,
              "Shared API name for symbol correlator");

      StructureDataType point2d = new StructureDataType("Point2D", 0);
      point2d.add(IntegerDataType.dataType, "x", "X coordinate");
      point2d.add(IntegerDataType.dataType, "y", "Y coordinate");
      sourceProgram.getDataTypeManager().addDataType(point2d, null);

      EnumDataType status = new EnumDataType("Status", 4);
      status.add("OK", 0);
      status.add("ERROR", 1);
      sourceProgram.getDataTypeManager().addDataType(status, null);

      srcCommit = true;
    } finally {
      sourceProgram.endTransaction(srcTxId, srcCommit);
    }

    // ===== Destination program: sparsely annotated "new" version =====
    ProgramBuilder destBuilder = new ProgramBuilder("dest_v2", ProgramBuilder._X64, consumer);
    Program destProgram = destBuilder.getProgram();

    destBuilder.createMemory(".text", "0x401000", 0x200);
    destBuilder.createMemory(".data", "0x402000", 0x200);

    // Functions
    destBuilder.setBytes("0x401000", "55 48 89 e5 b8 2a 00 00 00 5d c3");
    destBuilder.setBytes("0x401020", "55 48 89 e5 b8 01 00 00 00 5d c3");
    destBuilder.setBytes("0x401040", "55 48 89 e5 53 b8 14 00 00 00 5b 5d c3");
    destBuilder.setBytes("0x401060", "c3");
    destBuilder.setBytes("0x401070", "55 48 89 e5 90 90 90 90 b8 07 00 00 00 5d c3");
    destBuilder.setBytes("0x401080", "55 48 89 e5 48 85 ff 74 07 b8 01 00 00 00 5d c3 31 c0 5d c3");
    destBuilder.setBytes("0x4010A0", "55 48 89 e5 48 31 c0 48 ff c0 5d c3");
    destBuilder.setBytes("0x4010C0", "55 48 89 e5 b8 64 00 00 00 5d c3");
    destBuilder.setBytes("0x4010E0", "55 48 89 e5 48 83 e8 01 5d c3");
    destBuilder.setBytes("0x401100", "55 48 89 e5 48 b8 ff ee dd cc bb aa 99 88 5d c3");
    destBuilder.setBytes("0x401120", "55 48 89 e5 31 c0 ff c0 3d 0a 00 00 00 75 f7 5d c3");
    destBuilder.setBytes("0x401140", "55 48 89 e5 48 89 f8 48 01 f0 5d c3");
    destBuilder.setBytes("0x401180", "55 48 89 e5 b8 de ad 00 00 5d c3");

    // Data
    destBuilder.setBytes("0x402000", "de ad be ef ca fe ba be");
    destBuilder.setBytes("0x402010", "01 02 03 04 05 06 07 08");
    destBuilder.setBytes("0x402020", "aa bb cc dd ee ff 00 11");
    destBuilder.setBytes("0x402030", "48 65 6c 6c 6f 00");
    destBuilder.setBytes("0x402040", "76 32 2e 30 00");
    destBuilder.setBytes("0x402050", "ff 00 01 00 02 00 03 00 04 00 05 00 06 00 07 00");
    destBuilder.setBytes("0x402070", "42");
    destBuilder.setBytes("0x402080", "ff ff ff ff ff ff ff ff");

    destBuilder.applyDataType("0x402000", new ArrayDataType(ByteDataType.dataType, 8, 1));
    destBuilder.applyDataType("0x402010", new ArrayDataType(ByteDataType.dataType, 8, 1));
    destBuilder.applyDataType("0x402020", new ArrayDataType(ByteDataType.dataType, 8, 1));
    destBuilder.applyDataType("0x402030", new ArrayDataType(ByteDataType.dataType, 6, 1));
    destBuilder.applyDataType("0x402040", new ArrayDataType(ByteDataType.dataType, 5, 1));
    destBuilder.applyDataType("0x402050", new ArrayDataType(ByteDataType.dataType, 16, 1));
    destBuilder.applyDataType("0x402070", new ArrayDataType(ByteDataType.dataType, 1, 1));
    destBuilder.applyDataType("0x402080", new ArrayDataType(ByteDataType.dataType, 8, 1));

    destBuilder.disassemble("0x401000", 11);
    destBuilder.disassemble("0x401020", 11);
    destBuilder.disassemble("0x401040", 13);
    destBuilder.disassemble("0x401060", 1);
    destBuilder.disassemble("0x401070", 15);
    destBuilder.disassemble("0x401080", 20);
    destBuilder.disassemble("0x4010A0", 12);
    destBuilder.disassemble("0x4010C0", 11);
    destBuilder.disassemble("0x4010E0", 10);
    destBuilder.disassemble("0x401100", 16);
    destBuilder.disassemble("0x401120", 17);
    destBuilder.disassemble("0x401140", 12);
    destBuilder.disassemble("0x401180", 11);

    destBuilder.createFunction("0x401000");
    destBuilder.createFunction("0x401020");
    destBuilder.createFunction("0x401040");
    destBuilder.createFunction("0x401060");
    destBuilder.createFunction("0x401070");
    destBuilder.createFunction("0x401080");
    destBuilder.createFunction("0x4010A0");
    destBuilder.createFunction("0x4010C0");
    destBuilder.createFunction("0x4010E0");
    destBuilder.createFunction("0x401100");
    destBuilder.createFunction("0x401120");
    destBuilder.createFunction("0x401140");
    destBuilder.createFunction("0x401180");

    destBuilder.createLabel("0x4010A0", "dup_single");
    destBuilder.createLabel("0x4010C0", "new_only");
    destBuilder.createLabel("0x4010E0", "common_api");
    destBuilder.createLabel("0x401140", "another_new");

    int destTxId = destProgram.startTransaction("Set dest permissions");
    boolean destCommit = false;
    try {
      MemoryBlock destText = destProgram.getMemory().getBlock(".text");
      destText.setPermissions(true, false, true);
      MemoryBlock destData = destProgram.getMemory().getBlock(".data");
      destData.setPermissions(true, true, false);
      destCommit = true;
    } finally {
      destProgram.endTransaction(destTxId, destCommit);
    }

    // ===== Create VT session linking the two programs =====
    VTSessionDB session = new VTSessionDB("vt_test_session", sourceProgram, destProgram, consumer);

    return new VTFixture(sourceBuilder, destBuilder, sourceProgram, destProgram, session, consumer);
  }

  private static void forceEnableSystemUtilitiesTestingMode() {
    // VTSessionDB.initializePrograms skips the read-only check when in testing mode.
    // SystemUtilities caches this value, so force cache refresh for deterministic e2e behavior.
    System.setProperty("SystemUtilities.isTesting", "true");

    try {
      Class<?> systemUtilitiesClass = Class.forName("ghidra.util.SystemUtilities");
      Field testingModeCacheField = systemUtilitiesClass.getDeclaredField("isInTestingMode");
      testingModeCacheField.setAccessible(true);
      testingModeCacheField.set(null, null);
    } catch (Exception ignored) {
      // Best effort only: property is still set even if cache reset is inaccessible.
    }
  }

  record VTFixture(
      ProgramBuilder sourceBuilder,
      ProgramBuilder destBuilder,
      Program sourceProgram,
      Program destProgram,
      VTSessionDB session,
      Object consumer)
      implements AutoCloseable {

    @Override
    public void close() {
      try {
        session.release(consumer);
      } catch (Exception ignored) {
      }
      sourceBuilder.dispose();
      destBuilder.dispose();
    }
  }
}
