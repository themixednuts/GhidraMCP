package com.themixednuts.resources;

import com.themixednuts.annotation.GhidraMcpResource;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.common.McpTransportContext;
import java.util.HashMap;
import java.util.Map;
import reactor.core.publisher.Mono;

/** MCP resource template that provides decompiled code for a specific function. */
@GhidraMcpResource(
    uri = "ghidra://program/{name}/function/{address}/decompile",
    name = "Function Decompilation",
    description =
        "Provides decompiled C code for a specific function. Specify program name and function"
            + " entry address.",
    mimeType = "application/json",
    template = true)
public class FunctionDecompilationResource extends BaseMcpResource {

  private static final int DECOMPILE_TIMEOUT_SECONDS = 30;

  @Override
  public Mono<String> read(McpTransportContext context, String uri, PluginTool tool) {
    return Mono.fromCallable(
        () -> {
          Map<String, String> params = extractUriParams(uri);
          String programName = params.get("name");
          String addressStr = params.get("address");

          if (programName == null || programName.isEmpty()) {
            throw new IllegalArgumentException("Program name is required");
          }
          if (addressStr == null || addressStr.isEmpty()) {
            throw new IllegalArgumentException("Function address is required");
          }

          Program program = getProgramByName(programName);
          DecompInterface decompiler = null;
          try {
            // Parse address
            Address address = program.getAddressFactory().getAddress(addressStr);
            if (address == null) {
              throw new IllegalArgumentException("Invalid address: " + addressStr);
            }

            // Find function at address
            Function function = program.getFunctionManager().getFunctionAt(address);
            if (function == null) {
              function = program.getFunctionManager().getFunctionContaining(address);
            }
            if (function == null) {
              throw new IllegalArgumentException("No function found at address: " + addressStr);
            }

            // Initialize decompiler
            decompiler = new DecompInterface();
            decompiler.openProgram(program);

            // Decompile the function
            DecompileResults results =
                decompiler.decompileFunction(
                    function, DECOMPILE_TIMEOUT_SECONDS, TaskMonitor.DUMMY);

            Map<String, Object> result = new HashMap<>();
            result.put("programName", programName);
            result.put("functionName", function.getName());
            result.put("entryPoint", function.getEntryPoint().toString());
            result.put("signature", function.getPrototypeString(false, false));

            if (results.decompileCompleted() && results.getDecompiledFunction() != null) {
              result.put("decompilation", results.getDecompiledFunction().getC());
              result.put("success", true);
            } else {
              result.put("success", false);
              result.put(
                  "error",
                  results.getErrorMessage() != null
                      ? results.getErrorMessage()
                      : "Decompilation failed or produced no output");
            }

            // Add function metadata
            result.put(
                "metadata",
                Map.of(
                    "isThunk", function.isThunk(),
                    "isExternal", function.isExternal(),
                    "callingConvention", function.getCallingConventionName(),
                    "parameterCount", function.getParameterCount(),
                    "hasVarArgs", function.hasVarArgs(),
                    "stackFrameSize",
                        function.getStackFrame() != null
                            ? function.getStackFrame().getFrameSize()
                            : 0));

            return toJson(result);
          } finally {
            if (decompiler != null) {
              decompiler.dispose();
            }
            program.release(this);
          }
        });
  }
}
