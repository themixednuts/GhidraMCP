package com.themixednuts.tools;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import java.nio.file.Path;
import java.nio.file.Paths;

final class InMemoryProgramFixtureSupport {

  private InMemoryProgramFixtureSupport() {}

  static ProgramFixture createReadAndManageFixtureProgram() throws Exception {
    Path repoRoot = Paths.get("").toAbsolutePath();
    GhidraE2eRuntimeSupport.ensureGhidraRuntimeInitialized(repoRoot);

    Object consumer = new Object();
    ProgramBuilder builder =
        new ProgramBuilder("read_manage_fixture", ProgramBuilder._X64, consumer);
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

  /**
   * Creates a fixture with a function that has stack-allocated local variables, suitable for
   * testing decompiler-level variable operations (e.g., rename_variable).
   *
   * <p>The function at 0x401000 ("locals_func") compiles roughly to:
   *
   * <pre>
   *   int locals_func(void) {
   *       int local1 = 42;
   *       int local2 = 16;
   *       return local1 + local2;
   *   }
   * </pre>
   */
  static ProgramFixture createFixtureWithLocalVariables() throws Exception {
    Path repoRoot = Paths.get("").toAbsolutePath();
    GhidraE2eRuntimeSupport.ensureGhidraRuntimeInitialized(repoRoot);

    Object consumer = new Object();
    ProgramBuilder builder = new ProgramBuilder("locals_fixture", ProgramBuilder._X64, consumer);
    Program program = builder.getProgram();

    builder.createMemory(".text", "0x401000", 0x400);
    // push rbp; mov rbp,rsp; sub rsp,0x10;
    // mov [rbp-4],0x2a; mov [rbp-8],0x10;
    // mov eax,[rbp-4]; add eax,[rbp-8]; leave; ret
    builder.setBytes(
        "0x401000",
        "55 48 89 e5 48 83 ec 10 c7 45 fc 2a 00 00 00 c7 45 f8 10 00 00 00 8b 45 fc 03 45 f8 c9"
            + " c3");
    builder.disassemble("0x401000", 30);
    builder.createFunction("0x401000");
    builder.createLabel("0x401000", "locals_func");

    int txId = program.startTransaction("Add locals and permissions");
    boolean commit = false;
    try {
      MemoryBlock textBlock = program.getMemory().getBlock(".text");
      textBlock.setPermissions(true, true, true);

      // Add explicit stack variables so the decompiler maps them to HighSymbols
      Function func =
          program
              .getFunctionManager()
              .getFunctionAt(program.getAddressFactory().getAddress("0x401000"));
      func.addLocalVariable(
          new LocalVariableImpl("local_val1", new IntegerDataType(), -4, program),
          SourceType.USER_DEFINED);
      func.addLocalVariable(
          new LocalVariableImpl("local_val2", new IntegerDataType(), -8, program),
          SourceType.USER_DEFINED);
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
