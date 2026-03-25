package com.themixednuts.prompts;

import com.themixednuts.annotation.GhidraMcpPrompt;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.common.McpTransportContext;
import io.modelcontextprotocol.spec.McpSchema.GetPromptResult;
import io.modelcontextprotocol.spec.McpSchema.PromptArgument;
import io.modelcontextprotocol.spec.McpSchema.PromptMessage;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import reactor.core.publisher.Mono;

/**
 * Prompt for systematic bottom-up function renaming using call graph ordering. Leaf functions are
 * renamed first so that callers benefit from meaningful names in their decompilation.
 */
@GhidraMcpPrompt(
    name = "rename_analysis",
    title = "Rename Analysis",
    description =
        "Systematic bottom-up renaming using call graph ordering \u2014 the most effective agent"
            + " RE technique.")
public class RenameAnalysisPrompt extends BaseMcpPrompt {

  @Override
  public List<PromptArgument> getArguments() {
    return List.of(
        new PromptArgument("file_name", "Program file name to analyze", true),
        new PromptArgument(
            "start_function",
            "Optional function address to start from; if omitted, starts from leaf functions",
            false));
  }

  @Override
  public Mono<GetPromptResult> generate(
      McpTransportContext context, Map<String, Object> arguments, PluginTool tool) {
    return Mono.fromCallable(
        () -> {
          String programName = getRequiredArgument(arguments, "file_name");
          String startFunction = getOptionalArgument(arguments, "start_function", null);
          Program program = getProgramByName(programName);
          try {
            StringBuilder promptText = new StringBuilder();
            promptText.append("# Bottom-Up Rename Analysis\n\n");
            promptText.append("## Program: ").append(programName).append("\n");
            if (startFunction != null) {
              promptText.append("## Starting Function: ").append(startFunction).append("\n");
            }
            promptText.append("\n");

            // Find leaf functions and default-named functions
            List<String> leafFunctions = new ArrayList<>();
            List<String> defaultNamedFunctions = new ArrayList<>();
            int totalFunctions = 0;

            FunctionIterator funcIter = program.getFunctionManager().getFunctions(true);
            while (funcIter.hasNext()) {
              Function func = funcIter.next();
              totalFunctions++;

              String name = func.getName();
              boolean isDefaultNamed =
                  name.startsWith("FUN_")
                      || name.startsWith("thunk_FUN_")
                      || name.startsWith("Ordinal_");

              if (isDefaultNamed && defaultNamedFunctions.size() < 30) {
                defaultNamedFunctions.add(name + " at " + func.getEntryPoint());
              }

              // Identify leaf functions (no callees)
              if (leafFunctions.size() < 20) {
                Set<Function> callees = func.getCalledFunctions(TaskMonitor.DUMMY);
                boolean isLeaf = callees.isEmpty();
                if (isLeaf && isDefaultNamed) {
                  leafFunctions.add(name + " at " + func.getEntryPoint());
                }
              }
            }

            promptText.append("## Summary\n");
            promptText.append("- **Total Functions**: ").append(totalFunctions).append("\n");
            promptText
                .append("- **Default-Named Functions**: ~")
                .append(defaultNamedFunctions.size())
                .append("+\n\n");

            // Leaf functions
            promptText.append("## Leaf Functions with Default Names (first 20)\n");
            promptText.append("These have no callees — start here for bottom-up renaming:\n");
            if (leafFunctions.isEmpty()) {
              promptText.append("- No default-named leaf functions found\n");
            } else {
              for (String entry : leafFunctions) {
                promptText.append("- `").append(entry).append("`\n");
              }
            }
            promptText.append("\n");

            // Default-named functions
            promptText.append("## Default-Named Functions (first 30)\n");
            if (defaultNamedFunctions.isEmpty()) {
              promptText.append("- All functions already have meaningful names\n");
            } else {
              for (String entry : defaultNamedFunctions) {
                promptText.append("- `").append(entry).append("`\n");
              }
            }
            promptText.append("\n");

            // Instructions
            promptText.append("## Bottom-Up Renaming Workflow\n\n");
            promptText.append(
                """
                This is the most effective technique for agent-driven reverse engineering. \
                By renaming leaf functions first, callers automatically benefit from \
                meaningful names in their decompilation output.

                ### Step 1: Build Call Graph
                Use `analyze.call_graph` to understand the call hierarchy. Identify:
                - Leaf functions (no outgoing calls)
                - Hub functions (many incoming calls — likely utility functions)
                - Root functions (no incoming calls — likely entry points)

                ### Step 2: Start from Leaves
                For each leaf function with a default name:
                1. **Decompile**: Use `inspect.decompile` to read the decompiled code
                2. **Analyze**: Determine the function's purpose from:
                   - Constants and magic numbers
                   - System calls or API calls
                   - String references
                   - Arithmetic patterns (crypto, hashing, encoding)
                3. **Rename**: Use `functions.update_prototype` to set a meaningful name \
                and fix the signature (return type, parameter types and names)
                4. **Comment**: Use `annotate.set_comment` to document the function's purpose

                ### Step 3: Work Upward
                After renaming leaves, move to their callers:
                - The decompiled output now shows meaningful callee names
                - This makes understanding the caller much easier
                - Repeat: decompile → analyze → rename → comment

                ### Step 4: Group by Functionality
                As patterns emerge, group functions by capability:
                - **Networking**: socket, connect, send, recv wrappers
                - **Crypto**: encryption, decryption, hashing routines
                - **File I/O**: file read/write operations
                - **String processing**: parsing, formatting utilities
                - **C2 / Command handling**: command dispatch, protocol handlers
                - **Persistence**: registry, service, scheduled task operations

                ### Step 5: Apply Naming Conventions
                Use consistent prefixes for clarity:
                - `net_` for networking functions
                - `crypto_` for cryptographic operations
                - `io_` for file/registry I/O
                - `str_` or `parse_` for string processing
                - `cmd_` for command handlers
                - `init_` for initialization routines
                - `util_` for generic utilities
                """);

            List<PromptMessage> messages = List.of(createUserMessage(promptText.toString()));
            return new GetPromptResult("Bottom-up rename analysis for " + programName, messages);
          } finally {
            program.release(this);
          }
        });
  }
}
