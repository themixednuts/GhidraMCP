package com.themixednuts.tools;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import java.nio.file.Path;
import java.nio.file.Paths;

final class InMemoryProgramFixtureSupport {

  private InMemoryProgramFixtureSupport() {}

  static ProgramFixture createReadAndManageFixtureProgram() throws Exception {
    Path repoRoot = Paths.get("").toAbsolutePath();
    GhidraE2eRuntimeSupport.ensureGhidraRuntimeInitialized(repoRoot);

    Object consumer = new Object();
    ProgramBuilder builder = new ProgramBuilder("read_manage_fixture", ProgramBuilder._X64, consumer);
    Program program = builder.getProgram();

    builder.createMemory(".text", "0x401000", 0x400);
    builder.createMemory(".data", "0x402000", 0x100);
    builder.setBytes("0x401000", "55 48 89 e5 b8 2a 00 00 00 c3");
    builder.setBytes("0x401020", "55 48 89 e5 b8 01 00 00 00 c3");
    builder.setBytes("0x401040", "c3");
    builder.setBytes("0x402000", "11 22 33 44");
    builder.disassemble("0x401000", 10);
    builder.disassemble("0x401020", 10);
    builder.disassemble("0x401040", 1);

    builder.createLabel("0x401000", "entry_main");
    builder.createLabel("0x401020", "entry_worker");
    builder.createFunction("0x401000");
    builder.createFunction("0x401020");

    int txId = program.startTransaction("Set fixture permissions");
    boolean commit = false;
    try {
      MemoryBlock textBlock = program.getMemory().getBlock(".text");
      textBlock.setPermissions(true, true, true);
      MemoryBlock dataBlock = program.getMemory().getBlock(".data");
      dataBlock.setPermissions(true, true, false);
      commit = true;
    } finally {
      program.endTransaction(txId, commit);
    }

    return new ProgramFixture(builder, program);
  }

  record ProgramFixture(ProgramBuilder builder, Program program) implements AutoCloseable {
    @Override
    public void close() {
      builder.dispose();
    }
  }
}
