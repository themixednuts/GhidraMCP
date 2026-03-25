package com.themixednuts.prompts;

import com.themixednuts.annotation.GhidraMcpPrompt;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.common.McpTransportContext;
import io.modelcontextprotocol.spec.McpSchema.GetPromptResult;
import io.modelcontextprotocol.spec.McpSchema.PromptArgument;
import io.modelcontextprotocol.spec.McpSchema.PromptMessage;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import reactor.core.publisher.Mono;

/**
 * Prompt for mapping data structures in a binary. Identifies existing types and C++ mangled names
 * to guide struct/class recovery via RTTI, vtables, and usage patterns.
 */
@GhidraMcpPrompt(
    name = "map_data_structures",
    title = "Map Data Structures",
    description = "Identify and document structs/classes from RTTI, vtables, and usage patterns.")
public class MapDataStructuresPrompt extends BaseMcpPrompt {

  @Override
  public List<PromptArgument> getArguments() {
    return List.of(new PromptArgument("file_name", "Program file name to analyze", true));
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
            promptText.append("# Data Structure Mapping\n\n");
            promptText.append("## Program: ").append(programName).append("\n\n");

            // User-defined data types (non-builtin)
            promptText.append("## Existing User-Defined Data Types\n");
            DataTypeManager dtm = program.getDataTypeManager();
            int typeCount = 0;
            Iterator<DataType> dtIter = dtm.getAllDataTypes();
            while (dtIter.hasNext() && typeCount < 50) {
              DataType dt = dtIter.next();
              String catPath = dt.getCategoryPath().toString();
              // Skip built-in types
              if (catPath.startsWith("/BuiltInTypes") || catPath.equals("/")) {
                continue;
              }
              promptText
                  .append("- `")
                  .append(dt.getPathName())
                  .append("` (")
                  .append(dt.getClass().getSimpleName())
                  .append(", ")
                  .append(dt.getLength())
                  .append(" bytes)\n");
              typeCount++;
            }
            if (typeCount == 0) {
              promptText.append("- No user-defined types found\n");
            }
            promptText.append("\n");

            // Functions with C++ mangled names
            promptText.append("## C++ Functions (mangled/namespaced names)\n");
            List<String> cppFunctions = new ArrayList<>();
            FunctionIterator funcIter = program.getFunctionManager().getFunctions(true);
            while (funcIter.hasNext() && cppFunctions.size() < 50) {
              Function func = funcIter.next();
              String name = func.getName();
              String fullName = func.getName(true);
              if (name.startsWith("_Z") || name.startsWith("?") || fullName.contains("::")) {
                cppFunctions.add(fullName + " at " + func.getEntryPoint());
              }
            }
            if (cppFunctions.isEmpty()) {
              promptText.append("- No C++ mangled names detected\n");
            } else {
              for (String entry : cppFunctions) {
                promptText.append("- `").append(entry).append("`\n");
              }
            }
            promptText.append("\n");

            // Instructions
            promptText.append("## Data Structure Recovery Workflow\n\n");
            promptText.append(
                """
                Using the available MCP tools, follow this workflow to recover data structures:

                1. **Run RTTI Analysis**: Use `analyze` with RTTI options to discover class \
                hierarchies and type information
                2. **Identify VTable Locations**: Look for vtable references in constructors \
                and the data section. VTables are arrays of function pointers typically \
                referenced early in constructors
                3. **Create Struct Types**: Use `data_types` to create struct definitions for \
                discovered classes. Include:
                   - VTable pointer as first member (for polymorphic classes)
                   - Member fields identified from constructor initialization patterns
                   - Inherited fields from parent classes
                4. **Apply Types at Addresses**: Use `memory.define` to apply struct types at \
                global instances and `functions.update_prototype` to fix function signatures
                5. **Document Findings**: Use `annotate.set_comment` to add class hierarchy \
                notes and member descriptions

                Focus on:
                - Constructor/destructor pairs (often reveal full struct layout)
                - VTable cross-references (reveal class hierarchy)
                - Allocation sites (reveal struct sizes via malloc/new arguments)
                - Field access patterns (reveal member offsets and types)
                """);

            List<PromptMessage> messages = List.of(createUserMessage(promptText.toString()));
            return new GetPromptResult("Data structure mapping for " + programName, messages);
          } finally {
            program.release(this);
          }
        });
  }
}
