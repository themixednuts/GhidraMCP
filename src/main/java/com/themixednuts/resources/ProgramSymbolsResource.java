package com.themixednuts.resources;

import com.themixednuts.annotation.GhidraMcpResource;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import io.modelcontextprotocol.common.McpTransportContext;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import reactor.core.publisher.Mono;

/** MCP resource template that lists symbols in a specific program. */
@GhidraMcpResource(
    uri = "ghidra://program/{name}/symbols",
    name = "Program Symbols",
    description = "Lists all symbols (labels, functions, variables) in a specific program.",
    mimeType = "application/json",
    template = true)
public class ProgramSymbolsResource extends BaseMcpResource {

  private static final int MAX_SYMBOLS = 1000;

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
            SymbolTable symbolTable = program.getSymbolTable();
            List<Map<String, Object>> symbols = new ArrayList<>();

            SymbolIterator symIter = symbolTable.getAllSymbols(true);
            int count = 0;

            while (symIter.hasNext() && count < MAX_SYMBOLS) {
              Symbol sym = symIter.next();

              // Skip default symbols to reduce noise
              if (sym.getSource() == SourceType.DEFAULT) {
                continue;
              }

              Map<String, Object> symInfo = new HashMap<>();
              symInfo.put("id", sym.getID());
              symInfo.put("name", sym.getName());
              symInfo.put("address", sym.getAddress().toString());
              symInfo.put("type", sym.getSymbolType().toString());
              symInfo.put("source", sym.getSource().toString());
              symInfo.put("isPrimary", sym.isPrimary());
              symInfo.put("isExternal", sym.isExternal());
              symInfo.put("isGlobal", sym.isGlobal());

              if (sym.getParentNamespace() != null) {
                symInfo.put("namespace", sym.getParentNamespace().getName(true));
              }

              symbols.add(symInfo);
              count++;
            }

            Map<String, Object> result =
                Map.of(
                    "programName", programName,
                    "symbols", symbols,
                    "count", symbols.size(),
                    "hasMore", symIter.hasNext(),
                    "totalSymbolCount", symbolTable.getNumSymbols());

            return toJson(result);
          } finally {
            program.release(this);
          }
        });
  }
}
