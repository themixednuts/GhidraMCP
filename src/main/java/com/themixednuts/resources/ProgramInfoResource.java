package com.themixednuts.resources;

import com.themixednuts.annotation.GhidraMcpResource;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import io.modelcontextprotocol.common.McpTransportContext;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import reactor.core.publisher.Mono;

/** MCP resource template that provides program metadata. */
@GhidraMcpResource(
    uri = "ghidra://program/{name}/info",
    name = "Program Info",
    description =
        "Program metadata including architecture, format, language, compiler, address ranges, and"
            + " creation date.",
    mimeType = "application/json",
    template = true)
public class ProgramInfoResource extends BaseMcpResource {

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
            Map<String, Object> info = new LinkedHashMap<>();
            info.put("programName", programName);
            info.put("language", program.getLanguageID().toString());
            info.put("compilerSpec", program.getCompilerSpec().getCompilerSpecID().toString());
            info.put("processor", program.getLanguage().getProcessor().toString());
            info.put("endian", program.getLanguage().isBigEndian() ? "big" : "little");
            info.put("addressSize", program.getAddressFactory().getDefaultAddressSpace().getSize());
            info.put(
                "executableFormat",
                program.getExecutableFormat() != null ? program.getExecutableFormat() : "unknown");
            info.put(
                "executablePath",
                program.getExecutablePath() != null ? program.getExecutablePath() : "unknown");
            info.put(
                "imageBase",
                program.getImageBase() != null ? program.getImageBase().toString() : null);

            Date creationDate = program.getCreationDate();
            if (creationDate != null) {
              info.put("creationDate", creationDate.toString());
            }

            info.put(
                "minAddress",
                program.getMinAddress() != null ? program.getMinAddress().toString() : null);
            info.put(
                "maxAddress",
                program.getMaxAddress() != null ? program.getMaxAddress().toString() : null);
            info.put("functionCount", program.getFunctionManager().getFunctionCount());
            info.put("symbolCount", program.getSymbolTable().getNumSymbols());

            List<Map<String, Object>> memoryBlocks = new ArrayList<>();
            for (MemoryBlock block : program.getMemory().getBlocks()) {
              Map<String, Object> blockInfo = new LinkedHashMap<>();
              blockInfo.put("name", block.getName());
              blockInfo.put("start", block.getStart().toString());
              blockInfo.put("end", block.getEnd().toString());
              blockInfo.put("size", block.getSize());
              blockInfo.put("permissions", formatPermissions(block));
              memoryBlocks.add(blockInfo);
            }
            info.put("memoryBlocks", memoryBlocks);

            return toJson(info);
          } finally {
            program.release(this);
          }
        });
  }

  private String formatPermissions(MemoryBlock block) {
    StringBuilder sb = new StringBuilder();
    sb.append(block.isRead() ? "r" : "-");
    sb.append(block.isWrite() ? "w" : "-");
    sb.append(block.isExecute() ? "x" : "-");
    return sb.toString();
  }
}
