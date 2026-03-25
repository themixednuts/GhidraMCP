package com.themixednuts.prompts;

import com.themixednuts.annotation.GhidraMcpPrompt;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import io.modelcontextprotocol.common.McpTransportContext;
import io.modelcontextprotocol.spec.McpSchema.GetPromptResult;
import io.modelcontextprotocol.spec.McpSchema.PromptArgument;
import io.modelcontextprotocol.spec.McpSchema.PromptMessage;
import java.util.List;
import java.util.Map;
import reactor.core.publisher.Mono;

/**
 * Prompt for initial binary triage. Gathers key metadata — architecture, entry points, imports,
 * strings, and function counts — to help an AI assistant quickly classify a binary.
 */
@GhidraMcpPrompt(
    name = "triage_binary",
    title = "Triage Binary",
    description =
        "Initial binary analysis \u2014 identify type, entry points, imports/exports, strings,"
            + " and key functions.")
public class TriageBinaryPrompt extends BaseMcpPrompt {

  @Override
  public List<PromptArgument> getArguments() {
    return List.of(new PromptArgument("file_name", "Program file name to triage", true));
  }

  @Override
  public Mono<GetPromptResult> generate(
      McpTransportContext context, Map<String, Object> arguments, PluginTool tool) {
    return Mono.fromCallable(
        () -> {
          String programName = getRequiredArgument(arguments, "file_name");
          Program program = getProgramByName(programName);
          try {
            StringBuilder promptText = new StringBuilder();
            promptText.append("# Binary Triage Report\n\n");

            // Program info
            promptText.append("## Program Information\n");
            promptText.append("- **File**: ").append(programName).append("\n");
            promptText
                .append("- **Architecture**: ")
                .append(program.getLanguage().getProcessor())
                .append(" (")
                .append(program.getLanguage().getLanguageDescription().getSize())
                .append("-bit)\n");
            promptText.append("- **Format**: ").append(program.getExecutableFormat()).append("\n");
            promptText
                .append("- **Compiler**: ")
                .append(program.getCompilerSpec().getCompilerSpecID())
                .append("\n");
            promptText.append("- **Image Base**: ").append(program.getImageBase()).append("\n\n");

            // Entry points
            promptText.append("## Entry Points (first 20)\n");
            int entryCount = 0;
            FunctionIterator funcIter = program.getFunctionManager().getFunctions(true);
            while (funcIter.hasNext() && entryCount < 20) {
              Function func = funcIter.next();
              if (program.getSymbolTable().isExternalEntryPoint(func.getEntryPoint())) {
                promptText
                    .append("- `")
                    .append(func.getName())
                    .append("` at ")
                    .append(func.getEntryPoint())
                    .append("\n");
                entryCount++;
              }
            }
            if (entryCount == 0) {
              promptText.append("- None found\n");
            }
            promptText.append("\n");

            // Imports (external symbols)
            promptText.append("## Imports (first 30)\n");
            SymbolIterator extSymbols = program.getSymbolTable().getExternalSymbols();
            int importCount = 0;
            while (extSymbols.hasNext() && importCount < 30) {
              Symbol sym = extSymbols.next();
              promptText
                  .append("- `")
                  .append(sym.getName())
                  .append("` (")
                  .append(sym.getParentNamespace().getName())
                  .append(")\n");
              importCount++;
            }
            if (importCount == 0) {
              promptText.append("- None found\n");
            }
            promptText.append("\n");

            // Defined strings
            promptText.append("## Defined Strings (first 20)\n");
            int stringCount = 0;
            DataIterator dataIter = program.getListing().getDefinedData(true);
            while (dataIter.hasNext() && stringCount < 20) {
              Data data = dataIter.next();
              StringDataInstance sdi = StringDataInstance.getStringDataInstance(data);
              if (sdi == StringDataInstance.NULL_INSTANCE) {
                continue;
              }
              String value = sdi.getStringValue();
              if (value == null || value.isEmpty()) {
                continue;
              }
              if (value.length() > 100) {
                value = value.substring(0, 100) + "...";
              }
              promptText
                  .append("- ")
                  .append(data.getAddress())
                  .append(": `")
                  .append(value)
                  .append("`\n");
              stringCount++;
            }
            if (stringCount == 0) {
              promptText.append("- None found\n");
            }
            promptText.append("\n");

            // Counts
            int totalFunctions = program.getFunctionManager().getFunctionCount();
            int totalSymbols = program.getSymbolTable().getNumSymbols();
            promptText.append("## Summary Counts\n");
            promptText.append("- **Total Functions**: ").append(totalFunctions).append("\n");
            promptText.append("- **Total Symbols**: ").append(totalSymbols).append("\n\n");

            // Instructions
            promptText.append("## Triage Instructions\n\n");
            promptText.append(
                """
                Please analyze the information above and provide:

                1. **Binary Type**: Identify what kind of binary this is (e.g., CLI tool, \
                library, service, driver, malware dropper)
                2. **Capability Classification**: Based on imports, classify the binary's \
                capabilities (networking, file I/O, crypto, process manipulation, registry, etc.)
                3. **Interesting Strings**: Flag any strings that suggest functionality, \
                configuration, C2 URLs, credentials, or debug messages
                4. **Priority Functions**: Recommend which functions to analyze first and why
                5. **Overall Assessment**: Summarize your initial assessment of this binary
                """);

            List<PromptMessage> messages = List.of(createUserMessage(promptText.toString()));
            return new GetPromptResult("Binary triage for " + programName, messages);
          } finally {
            program.release(this);
          }
        });
  }
}
