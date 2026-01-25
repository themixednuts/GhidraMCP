package com.themixednuts.prompts;

import com.themixednuts.annotation.GhidraMcpPrompt;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.common.McpTransportContext;
import io.modelcontextprotocol.spec.McpSchema.GetPromptResult;
import io.modelcontextprotocol.spec.McpSchema.PromptArgument;
import io.modelcontextprotocol.spec.McpSchema.PromptMessage;
import java.util.List;
import java.util.Map;
import reactor.core.publisher.Mono;

/**
 * Prompt for analyzing a function in detail. Provides decompiled code and context for comprehensive
 * analysis.
 */
@GhidraMcpPrompt(
    name = "analyze_function",
    title = "Analyze Function",
    description =
        "Analyze a function in detail including decompiled code, references, and potential issues. "
            + "Provide comprehensive reverse engineering insights.")
public class AnalyzeFunctionPrompt extends BaseMcpPrompt {

  private static final int DECOMPILE_TIMEOUT_SECONDS = 30;

  @Override
  public List<PromptArgument> getArguments() {
    return List.of(
        new PromptArgument("file_name", "Program file name", true),
        new PromptArgument(
            "function_address", "Entry point address of the function to analyze", true),
        new PromptArgument(
            "analysis_focus",
            "Specific focus area: security, performance, logic, or general",
            false));
  }

  @Override
  public Mono<GetPromptResult> generate(
      McpTransportContext context, Map<String, Object> arguments, PluginTool tool) {
    return Mono.fromCallable(
        () -> {
          String programName = getRequiredArgument(arguments, "file_name");
          String addressStr = getRequiredArgument(arguments, "function_address");
          String focus = getOptionalArgument(arguments, "analysis_focus", "general");

          // Get the program using base class helper
          Program program = getProgramByName(programName);
          DecompInterface decompiler = null;
          try {
            // Parse address and find function
            Address address = program.getAddressFactory().getAddress(addressStr);
            if (address == null) {
              throw new IllegalArgumentException("Invalid address: " + addressStr);
            }

            Function function = program.getFunctionManager().getFunctionAt(address);
            if (function == null) {
              function = program.getFunctionManager().getFunctionContaining(address);
            }
            if (function == null) {
              throw new IllegalArgumentException("No function found at address: " + addressStr);
            }

            // Decompile
            decompiler = new DecompInterface();
            decompiler.openProgram(program);
            DecompileResults results =
                decompiler.decompileFunction(
                    function, DECOMPILE_TIMEOUT_SECONDS, TaskMonitor.DUMMY);

            // Build the prompt content
            StringBuilder promptText = new StringBuilder();
            promptText.append("# Function Analysis Request\n\n");
            promptText.append("## Function Information\n");
            promptText.append("- **Name**: ").append(function.getName()).append("\n");
            promptText.append("- **Entry Point**: ").append(function.getEntryPoint()).append("\n");
            promptText
                .append("- **Signature**: ")
                .append(function.getPrototypeString(false, false))
                .append("\n");
            promptText
                .append("- **Calling Convention**: ")
                .append(function.getCallingConventionName())
                .append("\n");
            promptText
                .append("- **Parameter Count**: ")
                .append(function.getParameterCount())
                .append("\n");
            promptText.append("- **Is Thunk**: ").append(function.isThunk()).append("\n");
            promptText.append("- **Is External**: ").append(function.isExternal()).append("\n\n");

            // Add decompiled code
            promptText.append("## Decompiled Code\n```c\n");
            if (results.decompileCompleted() && results.getDecompiledFunction() != null) {
              promptText.append(results.getDecompiledFunction().getC());
            } else {
              promptText.append("// Decompilation failed: ");
              promptText.append(
                  results.getErrorMessage() != null ? results.getErrorMessage() : "Unknown error");
            }
            promptText.append("\n```\n\n");

            // Add references
            promptText.append("## References\n");
            ReferenceIterator refIter =
                program.getReferenceManager().getReferencesTo(function.getEntryPoint());
            int refCount = 0;
            promptText.append("### Called By:\n");
            while (refIter.hasNext() && refCount < 10) {
              Reference ref = refIter.next();
              Function caller =
                  program.getFunctionManager().getFunctionContaining(ref.getFromAddress());
              if (caller != null) {
                promptText
                    .append("- ")
                    .append(caller.getName())
                    .append(" (")
                    .append(ref.getFromAddress())
                    .append(")\n");
              }
              refCount++;
            }
            if (refCount == 0) {
              promptText.append("- None found\n");
            }
            promptText.append("\n");

            // Add analysis focus instructions
            promptText.append("## Analysis Focus: ").append(focus.toUpperCase()).append("\n");
            promptText.append(getAnalysisFocusInstructions(focus));

            List<PromptMessage> messages = List.of(createUserMessage(promptText.toString()));

            return new GetPromptResult(
                "Analysis of function " + function.getName() + " at " + function.getEntryPoint(),
                messages);
          } finally {
            if (decompiler != null) {
              decompiler.dispose();
            }
            program.release(this);
          }
        });
  }

  private String getAnalysisFocusInstructions(String focus) {
    return switch (focus.toLowerCase()) {
      case "security" ->
          """
          Please analyze this function with a security focus:
          1. Identify potential buffer overflows, use-after-free, or memory corruption issues
          2. Check for unsafe function calls (strcpy, sprintf, etc.)
          3. Look for integer overflow/underflow vulnerabilities
          4. Identify potential format string vulnerabilities
          5. Check for proper input validation
          6. Identify potential race conditions or TOCTOU issues
          """;
      case "performance" ->
          """
          Please analyze this function with a performance focus:
          1. Identify inefficient loops or algorithms
          2. Look for unnecessary memory allocations
          3. Check for potential cache misses or memory access patterns
          4. Identify opportunities for optimization
          5. Look for redundant calculations
          """;
      case "logic" ->
          """
          Please analyze this function's logic:
          1. Explain the overall purpose and flow of the function
          2. Identify key decision points and branches
          3. Document the data transformations
          4. Suggest meaningful variable and function names
          5. Identify potential edge cases
          """;
      default ->
          """
          Please provide a comprehensive analysis:
          1. Explain what this function does
          2. Identify any potential issues or bugs
          3. Suggest improvements to variable/function names
          4. Note any security concerns
          5. Describe the overall code quality
          """;
    };
  }
}
