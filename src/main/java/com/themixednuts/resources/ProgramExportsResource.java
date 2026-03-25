package com.themixednuts.resources;

import com.themixednuts.annotation.GhidraMcpResource;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import io.modelcontextprotocol.common.McpTransportContext;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import reactor.core.publisher.Mono;

/** MCP resource template that lists exported symbols in a program. */
@GhidraMcpResource(
    uri = "ghidra://program/{name}/exports",
    name = "Program Exports",
    description = "Exported symbols (public functions and data) in a program.",
    mimeType = "application/json",
    template = true)
public class ProgramExportsResource extends BaseMcpResource {

  private static final int MAX_EXPORTS = 2000;

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
            List<Map<String, Object>> exports = new ArrayList<>();

            // Exported symbols are those in the global namespace that are entry points
            // or explicitly marked as global/exported
            for (Symbol sym : symbolTable.getDefinedSymbols()) {
              if (exports.size() >= MAX_EXPORTS) break;

              // Check if symbol is at an entry point or is a global function
              boolean isExport = false;
              Function func = program.getFunctionManager().getFunctionAt(sym.getAddress());
              if (func != null && !func.isExternal()) {
                // Functions at entry points are exports
                if (program.getSymbolTable().isExternalEntryPoint(sym.getAddress())) {
                  isExport = true;
                }
              }

              if (!isExport) continue;

              Map<String, Object> symInfo = new LinkedHashMap<>();
              symInfo.put("name", sym.getName());
              symInfo.put("address", sym.getAddress().toString());
              symInfo.put("type", sym.getSymbolType().toString());

              if (func != null) {
                symInfo.put("signature", func.getPrototypeString(false, false));
              }

              if (sym.getParentNamespace() != null && !sym.getParentNamespace().isGlobal()) {
                symInfo.put("namespace", sym.getParentNamespace().getName(true));
              }

              exports.add(symInfo);
            }

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("programName", programName);
            result.put("exports", exports);
            result.put("count", exports.size());

            return toJson(result);
          } finally {
            program.release(this);
          }
        });
  }
}
