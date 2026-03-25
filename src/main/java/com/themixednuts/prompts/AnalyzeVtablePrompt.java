package com.themixednuts.prompts;

import com.themixednuts.annotation.GhidraMcpPrompt;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import io.modelcontextprotocol.common.McpTransportContext;
import io.modelcontextprotocol.spec.McpSchema.GetPromptResult;
import io.modelcontextprotocol.spec.McpSchema.PromptArgument;
import io.modelcontextprotocol.spec.McpSchema.PromptMessage;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import reactor.core.publisher.Mono;

/**
 * Prompt for analyzing a vtable at a specific address. Reads pointer-sized entries, resolves them
 * to functions, and guides the AI through vtable struct creation and documentation.
 */
@GhidraMcpPrompt(
    name = "analyze_vtable",
    title = "Analyze VTable",
    description =
        "VTable normalization \u2014 validate function pointers, create vtable struct, apply at"
            + " address.")
public class AnalyzeVtablePrompt extends BaseMcpPrompt {

  private static final int MAX_VTABLE_ENTRIES = 32;

  @Override
  public List<PromptArgument> getArguments() {
    return List.of(
        new PromptArgument("file_name", "Program file name", true),
        new PromptArgument("vtable_address", "Address of the vtable to analyze", true));
  }

  @Override
  public Mono<GetPromptResult> generate(
      McpTransportContext context, Map<String, Object> arguments, PluginTool tool) {
    return Mono.fromCallable(
        () -> {
          String programName = getRequiredArgument(arguments, "file_name");
          String vtableAddrStr = getRequiredArgument(arguments, "vtable_address");
          Program program = getProgramByName(programName);
          try {
            Address vtableAddr = program.getAddressFactory().getAddress(vtableAddrStr);
            if (vtableAddr == null) {
              throw new IllegalArgumentException("Invalid address: " + vtableAddrStr);
            }

            int pointerSize = program.getDefaultPointerSize();
            Memory memory = program.getMemory();

            StringBuilder promptText = new StringBuilder();
            promptText.append("# VTable Analysis\n\n");
            promptText.append("## Program: ").append(programName).append("\n");
            promptText.append("## VTable Address: ").append(vtableAddr).append("\n");
            promptText.append("## Pointer Size: ").append(pointerSize).append(" bytes\n\n");

            // Read vtable entries
            promptText.append("## VTable Entries (raw pointer reads)\n");
            List<String> entries = new ArrayList<>();
            Address currentAddr = vtableAddr;
            for (int i = 0; i < MAX_VTABLE_ENTRIES; i++) {
              try {
                long ptrValue;
                if (pointerSize == 8) {
                  ptrValue = memory.getLong(currentAddr);
                } else {
                  ptrValue = memory.getInt(currentAddr) & 0xFFFFFFFFL;
                }

                if (ptrValue == 0) {
                  break; // Null terminator — likely end of vtable
                }

                Address targetAddr =
                    program.getAddressFactory().getDefaultAddressSpace().getAddress(ptrValue);
                Function func = program.getFunctionManager().getFunctionAt(targetAddr);

                String entry;
                if (func != null) {
                  entry =
                      String.format(
                          "[%d] %s -> %s `%s`", i, currentAddr, targetAddr, func.getName());
                } else {
                  entry =
                      String.format(
                          "[%d] %s -> %s (no function defined)", i, currentAddr, targetAddr);
                }
                entries.add(entry);
                promptText.append("- ").append(entry).append("\n");

                currentAddr = currentAddr.add(pointerSize);
              } catch (MemoryAccessException e) {
                break; // End of readable memory
              }
            }
            if (entries.isEmpty()) {
              promptText.append("- Could not read any entries at this address\n");
            }
            promptText.append("\n");

            // Workflow instructions
            promptText.append("## VTable Analysis Workflow\n\n");
            promptText.append(
                """
                Follow this step-by-step workflow to normalize the vtable:

                1. **Run RTTI Analysis**: Use `analyze` with RTTI analysis at the vtable \
                address to identify the owning class and hierarchy
                2. **Validate Function Pointers**: For each entry listed above:
                   - If a function exists: use `inspect.decompile` to understand its purpose
                   - If no function exists: use `inspect.listing` to verify it is code, \
                then `functions.create` to define the function
                3. **Decompile Each Slot**: Use `inspect.decompile` on every resolved \
                function to determine:
                   - Virtual method name/purpose
                   - Parameter types (first param is typically `this`)
                   - Return type
                4. **Create VTable Struct**: Use `data_types.create` to define a struct with:
                   - One function pointer member per slot
                   - Named after the class (e.g., `ClassName_vtable`)
                   - Each member named after the virtual method
                5. **Apply at Address**: Use `memory.define` to apply the vtable struct at \
                the vtable address
                6. **Document**: Use `annotate.set_comment` to record:
                   - Class name and hierarchy
                   - Purpose of each virtual method
                   - Any overridden methods from parent classes

                Pay attention to:
                - The first 1-2 entries may be RTTI pointers (typeinfo, offset-to-top) in \
                Itanium ABI
                - MSVC vtables start directly with function pointers
                - Pure virtual slots often point to `__cxa_pure_virtual` or `_purecall`
                """);

            List<PromptMessage> messages = List.of(createUserMessage(promptText.toString()));
            return new GetPromptResult(
                "VTable analysis at " + vtableAddr + " in " + programName, messages);
          } finally {
            program.release(this);
          }
        });
  }
}
