package com.themixednuts.prompts;

import com.themixednuts.annotation.GhidraMcpPrompt;
import ghidra.framework.plugintool.PluginTool;
import io.modelcontextprotocol.common.McpTransportContext;
import io.modelcontextprotocol.spec.McpSchema.GetPromptResult;
import io.modelcontextprotocol.spec.McpSchema.PromptArgument;
import io.modelcontextprotocol.spec.McpSchema.PromptMessage;
import java.util.List;
import java.util.Map;
import reactor.core.publisher.Mono;

/**
 * Prompt for binary diffing via Ghidra's Version Tracking (VT) system. Guides the AI through
 * session creation, correlator execution, match review, and markup application.
 */
@GhidraMcpPrompt(
    name = "compare_binaries",
    title = "Compare Binaries",
    description =
        "Binary diffing workflow via version tracking \u2014 set up session, run correlators,"
            + " review matches.")
public class CompareBinariesPrompt extends BaseMcpPrompt {

  @Override
  public List<PromptArgument> getArguments() {
    return List.of(
        new PromptArgument(
            "source_file", "Source program file name (older/reference version)", true),
        new PromptArgument(
            "destination_file", "Destination program file name (newer/target version)", true),
        new PromptArgument(
            "session_name", "Optional name for the VT session (auto-generated if omitted)", false));
  }

  @Override
  public Mono<GetPromptResult> generate(
      McpTransportContext context, Map<String, Object> arguments, PluginTool tool) {
    return Mono.fromCallable(
        () -> {
          String sourceFile = getRequiredArgument(arguments, "source_file");
          String destFile = getRequiredArgument(arguments, "destination_file");
          String sessionName =
              getOptionalArgument(arguments, "session_name", sourceFile + "_vs_" + destFile);

          StringBuilder promptText = new StringBuilder();
          promptText.append("# Binary Comparison Workflow\n\n");
          promptText.append("## Source: ").append(sourceFile).append("\n");
          promptText.append("## Destination: ").append(destFile).append("\n");
          promptText.append("## Session: ").append(sessionName).append("\n\n");

          promptText.append("## Version Tracking Workflow\n\n");
          promptText.append(
              """
              Follow these steps to compare the two binaries using Ghidra's Version \
              Tracking system:

              ### Step 1: Create VT Session
              Use `vt_sessions` to create a new version tracking session:
              - source_file: `%SOURCE%`
              - destination_file: `%DEST%`
              - session_name: `%SESSION%`

              ### Step 2: Run Correlators (in order of confidence)
              Run correlators sequentially — each narrows the remaining unmatched set:

              1. **Exact Bytes Match**: Use `run_vt_correlator` with the exact function \
              bytes correlator. This matches functions with identical compiled bytes — \
              highest confidence
              2. **Exact Instructions Match**: Use `run_vt_correlator` with the exact \
              instruction mnemonics correlator. Matches functions with same instructions \
              but different addresses/relocations
              3. **Symbol Name Match**: Use `run_vt_correlator` with the symbol name \
              correlator. Matches functions with identical names

              ### Step 3: Review Matches
              Use `read_vt_matches` to list all discovered matches:
              - Review match confidence scores
              - Identify high-confidence matches (similarity > 0.9)
              - Note any suspicious low-confidence matches for manual review

              ### Step 4: Review Unmatched Functions
              Use `read_vt_matches` with appropriate filters to find unmatched functions:
              - These are likely new functions, removed functions, or heavily modified ones
              - Prioritize analysis of unmatched functions in the destination (new version)

              ### Step 5: Accept High-Confidence Matches
              Use `manage_vt_matches` to accept matches with high confidence scores:
              - Accept all matches above 0.9 similarity in bulk
              - Review and manually accept/reject borderline matches

              ### Step 6: Apply Markup
              Use `manage_vt_markup` to transfer annotations from matched source functions \
              to destination:
              - Function names, signatures, and comments transfer to the new binary
              - Data type assignments carry over
              - This propagates all your reverse engineering work to the updated binary

              ### Analysis Summary
              After completing the workflow, provide:
              1. **Match Statistics**: Total matched, unmatched source, unmatched destination
              2. **Changed Functions**: Functions that matched but show differences
              3. **New Functions**: Functions only in the destination
              4. **Removed Functions**: Functions only in the source
              5. **Security Impact**: Any changes that affect security-relevant functions
              """
                  .replace("%SOURCE%", sourceFile)
                  .replace("%DEST%", destFile)
                  .replace("%SESSION%", sessionName));

          List<PromptMessage> messages = List.of(createUserMessage(promptText.toString()));
          return new GetPromptResult(
              "Binary comparison: " + sourceFile + " vs " + destFile, messages);
        });
  }
}
