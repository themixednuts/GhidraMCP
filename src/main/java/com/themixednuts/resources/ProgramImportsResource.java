package com.themixednuts.resources;

import com.themixednuts.annotation.GhidraMcpResource;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import io.modelcontextprotocol.common.McpTransportContext;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import reactor.core.publisher.Mono;

/** MCP resource template that lists imported symbols in a program. */
@GhidraMcpResource(
    uri = "ghidra://program/{name}/imports",
    name = "Program Imports",
    description =
        "Imported symbols (external functions and data) in a program. Critical for triage"
            + " workflows to identify API usage and capabilities.",
    mimeType = "application/json",
    template = true)
public class ProgramImportsResource extends BaseMcpResource {

  private static final int MAX_IMPORTS = 2000;

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
            List<Map<String, Object>> imports = new ArrayList<>();

            SymbolIterator symIter = symbolTable.getExternalSymbols();
            int count = 0;

            while (symIter.hasNext() && count < MAX_IMPORTS) {
              Symbol sym = symIter.next();
              Map<String, Object> symInfo = new LinkedHashMap<>();
              symInfo.put("name", sym.getName());
              symInfo.put("address", sym.getAddress().toString());
              symInfo.put("type", sym.getSymbolType().toString());

              if (sym.getParentNamespace() != null && !sym.getParentNamespace().isGlobal()) {
                symInfo.put("library", sym.getParentNamespace().getName(true));
              }

              imports.add(symInfo);
              count++;
            }

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("programName", programName);
            result.put("imports", imports);
            result.put("count", imports.size());
            result.put("hasMore", symIter.hasNext());

            return toJson(result);
          } finally {
            program.release(this);
          }
        });
  }
}
