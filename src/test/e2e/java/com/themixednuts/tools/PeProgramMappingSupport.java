package com.themixednuts.tools;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

final class PeProgramMappingSupport {

  private static final long IMAGE_SCN_MEM_EXECUTE = 0x20000000L;
  private static final long IMAGE_SCN_MEM_READ = 0x40000000L;
  private static final long IMAGE_SCN_MEM_WRITE = 0x80000000L;

  private PeProgramMappingSupport() {}

  static void configurePeMetadataForVisualStudio(Program program) throws Exception {
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

  static void mapPortableExecutableIntoProgram(ProgramBuilder builder, Program program, Path exePath)
      throws Exception {
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
              java.util.Arrays.copyOfRange(bytes, (int) rawPointer, (int) rawPointer + initializedLength);
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
    String name = new String(data, sectionOffset, end - sectionOffset, StandardCharsets.US_ASCII);
    return name.isBlank() ? "section" + sectionOffset : name;
  }
}
