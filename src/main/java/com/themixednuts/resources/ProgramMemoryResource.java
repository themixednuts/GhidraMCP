package com.themixednuts.resources;

import com.themixednuts.annotation.GhidraMcpResource;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import io.modelcontextprotocol.common.McpTransportContext;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import reactor.core.publisher.Mono;

/** MCP resource template that provides memory block layout for a program. */
@GhidraMcpResource(
    uri = "ghidra://program/{name}/memory",
    name = "Program Memory",
    description =
        "Memory block layout including block names, address ranges, sizes, permissions, and types.",
    mimeType = "application/json",
    template = true)
public class ProgramMemoryResource extends BaseMcpResource {

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
            List<Map<String, Object>> blocks = new ArrayList<>();

            for (MemoryBlock block : program.getMemory().getBlocks()) {
              Map<String, Object> blockInfo = new LinkedHashMap<>();
              blockInfo.put("name", block.getName());
              blockInfo.put("start", block.getStart().toString());
              blockInfo.put("end", block.getEnd().toString());
              blockInfo.put("size", block.getSize());
              blockInfo.put("read", block.isRead());
              blockInfo.put("write", block.isWrite());
              blockInfo.put("execute", block.isExecute());
              blockInfo.put("volatile", block.isVolatile());
              blockInfo.put("initialized", block.isInitialized());
              blockInfo.put("type", block.getType().toString());

              if (block.getSourceName() != null && !block.getSourceName().isEmpty()) {
                blockInfo.put("source", block.getSourceName());
              }
              if (block.getComment() != null && !block.getComment().isEmpty()) {
                blockInfo.put("comment", block.getComment());
              }

              blocks.add(blockInfo);
            }

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("programName", programName);
            result.put("blocks", blocks);
            result.put("count", blocks.size());
            result.put("totalSize", program.getMemory().getSize());

            return toJson(result);
          } finally {
            program.release(this);
          }
        });
  }
}
