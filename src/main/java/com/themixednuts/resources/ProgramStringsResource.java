package com.themixednuts.resources;

import com.themixednuts.annotation.GhidraMcpResource;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.common.McpTransportContext;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import reactor.core.publisher.Mono;

/** MCP resource template that lists defined strings in a program. */
@GhidraMcpResource(
    uri = "ghidra://program/{name}/strings",
    name = "Program Strings",
    description =
        "Defined strings in a program. Critical for initial triage — reveals URLs, file paths,"
            + " error messages, and crypto constants.",
    mimeType = "application/json",
    template = true)
public class ProgramStringsResource extends BaseMcpResource {

  private static final int MAX_STRINGS = 2000;

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
            List<Map<String, Object>> strings = new ArrayList<>();
            DataIterator dataIter = program.getListing().getDefinedData(true);

            while (dataIter.hasNext() && strings.size() < MAX_STRINGS) {
              Data data = dataIter.next();
              StringDataInstance sdi = StringDataInstance.getStringDataInstance(data);

              if (sdi == StringDataInstance.NULL_INSTANCE) {
                continue;
              }

              String stringValue = sdi.getStringValue();
              if (stringValue == null || stringValue.isEmpty()) {
                continue;
              }

              Map<String, Object> entry = new LinkedHashMap<>();
              entry.put("address", data.getAddress().toString());
              entry.put("value", stringValue);
              entry.put("length", stringValue.length());
              entry.put("dataType", data.getDataType().getName());

              // Check if string is in a specific memory block
              var block = program.getMemory().getBlock(data.getAddress());
              if (block != null) {
                entry.put("section", block.getName());
              }

              strings.add(entry);
            }

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("programName", programName);
            result.put("strings", strings);
            result.put("count", strings.size());
            result.put("hasMore", dataIter.hasNext());

            return toJson(result);
          } finally {
            program.release(this);
          }
        });
  }
}
