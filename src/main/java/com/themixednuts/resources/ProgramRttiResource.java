package com.themixednuts.resources;

import com.themixednuts.annotation.GhidraMcpResource;
import ghidra.app.cmd.data.TypeDescriptorModel;
import ghidra.app.cmd.data.rtti.RttiUtil;
import ghidra.app.util.datatype.microsoft.DataValidationOptions;
import ghidra.features.base.memsearch.bytesource.ProgramByteSource;
import ghidra.features.base.memsearch.format.SearchFormat;
import ghidra.features.base.memsearch.matcher.ByteMatcher;
import ghidra.features.base.memsearch.searcher.MemoryMatch;
import ghidra.features.base.memsearch.searcher.MemorySearcher;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.common.McpTransportContext;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import reactor.core.publisher.Mono;

/**
 * Fast RTTI index resource. Returns raw mangled names and addresses only — no demangling, no lambda
 * parsing, no RTTI4 chain traversal. Use analyze tool (action: list_rtti) for compact summaries or
 * analyze (action: rtti) for full RTTI chain details.
 */
@GhidraMcpResource(
    uri = "ghidra://program/{name}/rtti",
    name = "Program RTTI",
    description =
        "Fast index of MSVC RTTI type descriptors — raw mangled names and addresses. Use"
            + " analyze (action: list_rtti) for compact RTTI summaries or analyze"
            + " (action: rtti) for detailed class hierarchy inspection.",
    mimeType = "application/json",
    template = true)
public class ProgramRttiResource extends BaseMcpResource {

  private static final int MAX_ENTRIES = 5000;
  private static final int MAX_SCAN = 50000;
  private static final int MAX_STRING_LENGTH = 512;

  @Override
  public Mono<String> read(McpTransportContext context, String uri, PluginTool tool) {
    return Mono.fromCallable(
        () -> {
          Map<String, String> params = extractUriParams(uri);
          String programName = params.get("name");

          if (programName == null || programName.isEmpty()) {
            throw new IllegalArgumentException("Program name is required");
          }

          Program program = getProgramByName(programName);
          try {
            Memory memory = program.getMemory();

            // Scan .data section where RTTI0 type descriptors live
            MemoryBlock dataBlock = memory.getBlock(".data");
            AddressSetView searchSet;
            if (dataBlock != null) {
              searchSet =
                  program
                      .getMemory()
                      .getLoadedAndInitializedAddressSet()
                      .intersectRange(dataBlock.getStart(), dataBlock.getEnd());
            } else {
              searchSet = program.getMemory().getLoadedAndInitializedAddressSet();
            }

            // Try to find type_info vftable for structured RTTI0 discovery
            Address typeInfoVftable = null;
            try {
              typeInfoVftable = RttiUtil.findTypeInfoVftableAddress(program, TaskMonitor.DUMMY);
            } catch (Exception ignored) {
              // Fall back to byte pattern scan
            }

            ghidra.util.datastruct.ListAccumulator<MemoryMatch> accumulator =
                new ghidra.util.datastruct.ListAccumulator<>();

            if (typeInfoVftable != null) {
              // Structured approach: search for vftable pointer in .data
              int pointerSize = program.getDefaultPointerSize();
              byte[] vftableBytes = addressToLittleEndianBytes(typeInfoVftable, pointerSize);
              String hexPattern = bytesToHexString(vftableBytes);

              ghidra.features.base.memsearch.gui.SearchSettings settings =
                  new ghidra.features.base.memsearch.gui.SearchSettings();
              settings.withSearchFormat(SearchFormat.HEX);
              settings.withBigEndian(memory.isBigEndian());
              ByteMatcher matcher = SearchFormat.HEX.parse(hexPattern, settings);

              ProgramByteSource byteSource = new ProgramByteSource(program);
              MemorySearcher searcher =
                  new MemorySearcher(byteSource, matcher, searchSet, MAX_SCAN);
              searcher.findAll(accumulator, TaskMonitor.DUMMY);
            }

            // Collect unique entries using Ghidra RTTI models
            List<Map<String, Object>> entries = new ArrayList<>();
            Set<String> seen = new LinkedHashSet<>();
            DataValidationOptions validationOptions = new DataValidationOptions();

            if (typeInfoVftable != null && !accumulator.isEmpty()) {
              // Each match IS an RTTI0 base address (vftable ptr is at offset 0)
              for (MemoryMatch match : accumulator) {
                if (entries.size() >= MAX_ENTRIES) {
                  break;
                }
                Address rtti0Addr = match.getAddress();
                try {
                  TypeDescriptorModel rtti0 =
                      new TypeDescriptorModel(program, rtti0Addr, validationOptions);
                  rtti0.validate();
                  String mangledName = rtti0.getTypeName();
                  if (mangledName == null
                      || mangledName.length() < 4
                      || seen.contains(mangledName)) {
                    continue;
                  }
                  String typeKind = classifyTypeKind(mangledName);
                  if (typeKind == null) {
                    continue;
                  }

                  seen.add(mangledName);
                  Map<String, Object> entry = new LinkedHashMap<>();
                  entry.put("mangled", mangledName);
                  entry.put("type_kind", typeKind);
                  entry.put("rtti0_address", rtti0Addr.toString());
                  if (mangledName.contains("<lambda") && mangledName.contains("@??")) {
                    entry.put("is_lambda", true);
                  }
                  entries.add(entry);
                } catch (Exception ignored) {
                  // Invalid RTTI0 structure — skip
                }
              }
            } else {
              // Fallback: bulk search for ".?A" byte pattern
              ghidra.features.base.memsearch.gui.SearchSettings settings =
                  new ghidra.features.base.memsearch.gui.SearchSettings();
              settings.withSearchFormat(SearchFormat.HEX);
              settings.withBigEndian(memory.isBigEndian());
              ByteMatcher matcher = SearchFormat.HEX.parse("2e 3f 41", settings);

              ProgramByteSource byteSource = new ProgramByteSource(program);
              MemorySearcher searcher =
                  new MemorySearcher(byteSource, matcher, searchSet, MAX_SCAN);

              ghidra.util.datastruct.ListAccumulator<MemoryMatch> fallbackAccumulator =
                  new ghidra.util.datastruct.ListAccumulator<>();
              searcher.findAll(fallbackAccumulator, TaskMonitor.DUMMY);

              for (MemoryMatch match : fallbackAccumulator) {
                if (entries.size() >= MAX_ENTRIES) {
                  break;
                }
                Address found = match.getAddress();
                String mangledName = readCString(memory, found, MAX_STRING_LENGTH);
                if (mangledName == null || mangledName.length() < 4 || seen.contains(mangledName)) {
                  continue;
                }
                String typeKind = classifyTypeKind(mangledName);
                if (typeKind == null) {
                  continue;
                }

                seen.add(mangledName);
                try {
                  Address rtti0Addr = found.subtract(16);
                  Map<String, Object> entry = new LinkedHashMap<>();
                  entry.put("mangled", mangledName);
                  entry.put("type_kind", typeKind);
                  entry.put("rtti0_address", rtti0Addr.toString());
                  if (mangledName.contains("<lambda") && mangledName.contains("@??")) {
                    entry.put("is_lambda", true);
                  }
                  entries.add(entry);
                } catch (Exception ignored) {
                }
              }
            }

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("programName", programName);
            result.put("entries", entries);
            result.put("count", entries.size());
            result.put("hasMore", accumulator.size() >= MAX_SCAN || entries.size() >= MAX_ENTRIES);

            return toJson(result);
          } finally {
            program.release(this);
          }
        });
  }

  private String classifyTypeKind(String mangledName) {
    if (mangledName.startsWith(".?AV")) return "class";
    if (mangledName.startsWith(".?AU")) return "struct";
    if (mangledName.startsWith(".?AT")) return "union";
    if (mangledName.startsWith(".?AW4")) return "enum";
    return null;
  }

  private byte[] addressToLittleEndianBytes(Address addr, int pointerSize) {
    long value = addr.getOffset();
    ByteBuffer buffer = ByteBuffer.allocate(pointerSize);
    buffer.order(ByteOrder.LITTLE_ENDIAN);
    if (pointerSize == 8) {
      buffer.putLong(value);
    } else {
      buffer.putInt((int) value);
    }
    return buffer.array();
  }

  private String bytesToHexString(byte[] bytes) {
    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < bytes.length; i++) {
      if (i > 0) {
        sb.append(' ');
      }
      sb.append(String.format("%02x", bytes[i] & 0xff));
    }
    return sb.toString();
  }

  private String readCString(Memory memory, Address addr, int maxLen) {
    try {
      StringBuilder sb = new StringBuilder();
      for (int i = 0; i < maxLen; i++) {
        byte b = memory.getByte(addr.add(i));
        if (b == 0) break;
        sb.append((char) (b & 0xff));
      }
      return sb.toString();
    } catch (Exception e) {
      return null;
    }
  }
}
