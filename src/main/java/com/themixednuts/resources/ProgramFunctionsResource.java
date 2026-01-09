package com.themixednuts.resources;

import com.themixednuts.annotation.GhidraMcpResource;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.common.McpTransportContext;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * MCP resource template that lists functions in a specific program.
 */
@GhidraMcpResource(
    uri = "ghidra://program/{name}/functions",
    name = "Program Functions",
    description = "Lists all functions in a specific program. Use the program name from the programs list.",
    mimeType = "application/json",
    template = true
)
public class ProgramFunctionsResource extends BaseMcpResource {

    private static final int MAX_FUNCTIONS = 1000;

    @Override
    public Mono<String> read(McpTransportContext context, String uri, PluginTool tool) {
        return Mono.fromCallable(() -> {
            Map<String, String> params = extractUriParams(uri);
            String programName = params.get("name");
            
            if (programName == null || programName.isEmpty()) {
                throw new IllegalArgumentException("Program name is required");
            }
            
            Program program = getProgramByName(programName);
            try {
                List<Map<String, Object>> functions = new ArrayList<>();
                FunctionIterator funcIter = program.getFunctionManager().getFunctions(true);
                
                int count = 0;
                while (funcIter.hasNext() && count < MAX_FUNCTIONS) {
                    Function func = funcIter.next();
                    Map<String, Object> funcInfo = new HashMap<>();
                    funcInfo.put("name", func.getName());
                    funcInfo.put("address", func.getEntryPoint().toString());
                    funcInfo.put("signature", func.getPrototypeString(false, false));
                    funcInfo.put("isThunk", func.isThunk());
                    funcInfo.put("isExternal", func.isExternal());
                    funcInfo.put("callingConvention", func.getCallingConventionName());
                    funcInfo.put("parameterCount", func.getParameterCount());
                    
                    if (func.getSymbol() != null) {
                        funcInfo.put("symbolId", func.getSymbol().getID());
                    }
                    
                    functions.add(funcInfo);
                    count++;
                }
                
                Map<String, Object> result = Map.of(
                    "programName", programName,
                    "functions", functions,
                    "count", functions.size(),
                    "hasMore", funcIter.hasNext()
                );
                
                return toJson(result);
            } finally {
                program.release(this);
            }
        });
    }
}
