package com.themixednuts.resources;

import com.themixednuts.annotation.GhidraMcpResource;
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
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import reactor.core.publisher.Mono;

/**
 * Fast RTTI index resource. Returns raw mangled names and addresses only — no demangling, no lambda
 * parsing, no RTTI4 chain traversal. Use analyze tool (action: list_rtti) for full processing.
 */
@GhidraMcpResource(
    uri = "ghidra://program/{name}/rtti",
    name = "Program RTTI",
    description =
        "Fast index of MSVC RTTI type descriptors — raw mangled names and addresses. Use"
            + " analyze (action: list_rtti) for demangled names, methods, and class hierarchies.",
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

            // Bulk search for ".?A" pattern
            ghidra.features.base.memsearch.gui.SearchSettings settings =
                new ghidra.features.base.memsearch.gui.SearchSettings();
            settings.withSearchFormat(SearchFormat.HEX);
            settings.withBigEndian(memory.isBigEndian());
            ByteMatcher matcher = SearchFormat.HEX.parse("2e 3f 41", settings);

            ProgramByteSource byteSource = new ProgramByteSource(program);
            MemorySearcher searcher = new MemorySearcher(byteSource, matcher, searchSet, MAX_SCAN);

            ghidra.util.datastruct.ListAccumulator<MemoryMatch> accumulator =
                new ghidra.util.datastruct.ListAccumulator<>();
            searcher.findAll(accumulator, TaskMonitor.DUMMY);

            // Collect unique entries — raw mangled names only, no demangling
            List<Map<String, Object>> entries = new ArrayList<>();
            Set<String> seen = new LinkedHashSet<>();

            for (MemoryMatch match : accumulator) {
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
