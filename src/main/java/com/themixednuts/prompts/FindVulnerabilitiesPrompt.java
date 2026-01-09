package com.themixednuts.prompts;

import com.themixednuts.annotation.GhidraMcpPrompt;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.common.McpTransportContext;
import io.modelcontextprotocol.spec.McpSchema.GetPromptResult;
import io.modelcontextprotocol.spec.McpSchema.PromptArgument;
import io.modelcontextprotocol.spec.McpSchema.PromptMessage;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Prompt for identifying potential vulnerabilities in a binary.
 * Searches for dangerous function calls and provides context for security analysis.
 */
@GhidraMcpPrompt(
    name = "find_vulnerabilities",
    title = "Find Vulnerabilities",
    description = "Scan the program for potential security vulnerabilities by identifying " +
                  "dangerous function calls and providing decompiled context for analysis."
)
public class FindVulnerabilitiesPrompt extends BaseMcpPrompt {

    private static final int DECOMPILE_TIMEOUT_SECONDS = 15;
    
    // Common dangerous functions
    private static final Set<String> DANGEROUS_FUNCTIONS = Set.of(
            // Buffer overflows
            "strcpy", "strcat", "sprintf", "vsprintf", "gets", "scanf",
            // Format strings
            "printf", "fprintf", "sprintf", "snprintf", "syslog",
            // Memory operations
            "memcpy", "memmove", "memset",
            // Integer overflows
            "atoi", "atol", "atoll",
            // Command injection
            "system", "popen", "exec", "execl", "execv", "execle", "execve",
            // File operations
            "fopen", "open", "access", "chmod", "chown",
            // Network
            "recv", "recvfrom", "read", "write", "send", "sendto"
    );

    @Override
    public List<PromptArgument> getArguments() {
        return List.of(
                new PromptArgument("file_name", "Program file name to analyze", true),
                new PromptArgument("max_functions", "Maximum number of suspicious functions to analyze (default 10)", false)
        );
    }

    @Override
    public Mono<GetPromptResult> generate(McpTransportContext context, Map<String, Object> arguments, PluginTool tool) {
        return Mono.fromCallable(() -> {
            String programName = getRequiredArgument(arguments, "file_name");
            int maxFunctions = Integer.parseInt(getOptionalArgument(arguments, "max_functions", "10"));
            
            // Use base class helper to get program
            Program program = getProgramByName(programName);
            DecompInterface decompiler = null;
            try {
                // Find dangerous function references
                Set<String> foundDangerous = new HashSet<>();
                List<Function> suspiciousFunctions = new ArrayList<>();
                
                // Search for imports/external calls to dangerous functions
                SymbolIterator symbols = program.getSymbolTable().getExternalSymbols();
                while (symbols.hasNext()) {
                    Symbol sym = symbols.next();
                    String name = sym.getName().toLowerCase();
                    for (String dangerous : DANGEROUS_FUNCTIONS) {
                        if (name.contains(dangerous.toLowerCase())) {
                            foundDangerous.add(sym.getName());
                            break;
                        }
                    }
                }
                
                // Find functions that call dangerous functions
                FunctionIterator funcIter = program.getFunctionManager().getFunctions(true);
                while (funcIter.hasNext() && suspiciousFunctions.size() < maxFunctions) {
                    Function func = funcIter.next();
                    // Check if this function contains calls to dangerous functions
                    Set<Function> calledFuncs = func.getCalledFunctions(TaskMonitor.DUMMY);
                    for (Function called : calledFuncs) {
                        String calledName = called.getName().toLowerCase();
                        for (String dangerous : DANGEROUS_FUNCTIONS) {
                            if (calledName.contains(dangerous.toLowerCase())) {
                                if (!suspiciousFunctions.contains(func)) {
                                    suspiciousFunctions.add(func);
                                }
                                foundDangerous.add(called.getName());
                                break;
                            }
                        }
                    }
                }
                
                // Build the prompt
                StringBuilder promptText = new StringBuilder();
                promptText.append("# Security Vulnerability Analysis\n\n");
                promptText.append("## Program: ").append(programName).append("\n\n");
                
                // Summary of dangerous functions found
                promptText.append("## Dangerous Functions Detected\n");
                if (foundDangerous.isEmpty()) {
                    promptText.append("No commonly dangerous functions were directly detected.\n");
                } else {
                    promptText.append("The following potentially dangerous functions were found:\n");
                    for (String name : foundDangerous) {
                        promptText.append("- `").append(name).append("`\n");
                    }
                }
                promptText.append("\n");
                
                // Decompile suspicious functions
                if (!suspiciousFunctions.isEmpty()) {
                    decompiler = new DecompInterface();
                    decompiler.openProgram(program);
                    
                    promptText.append("## Functions Using Dangerous Calls\n\n");
                    
                    for (Function func : suspiciousFunctions) {
                        promptText.append("### ").append(func.getName())
                                .append(" (").append(func.getEntryPoint()).append(")\n\n");
                        
                        DecompileResults results = decompiler.decompileFunction(func, DECOMPILE_TIMEOUT_SECONDS, TaskMonitor.DUMMY);
                        
                        promptText.append("```c\n");
                        if (results.decompileCompleted() && results.getDecompiledFunction() != null) {
                            promptText.append(results.getDecompiledFunction().getC());
                        } else {
                            promptText.append("// Decompilation failed\n");
                        }
                        promptText.append("```\n\n");
                    }
                }
                
                // Analysis instructions
                promptText.append("## Analysis Instructions\n\n");
                promptText.append("""
                        Please analyze the code above for security vulnerabilities:
                        
                        1. **Buffer Overflows**: Check for unchecked buffer operations, missing size validations
                        2. **Format String Bugs**: Look for user-controlled format specifiers
                        3. **Integer Overflows**: Check arithmetic operations that could wrap
                        4. **Memory Corruption**: Look for use-after-free, double-free patterns
                        5. **Command Injection**: Check if user input reaches system/exec calls
                        6. **Path Traversal**: Look for unsanitized file paths
                        7. **Race Conditions**: Check for TOCTOU issues
                        
                        For each vulnerability found, provide:
                        - Location (function and approximate line)
                        - Vulnerability type
                        - Severity (Critical/High/Medium/Low)
                        - Exploitation scenario
                        - Recommended fix
                        """);
                
                List<PromptMessage> messages = List.of(createUserMessage(promptText.toString()));
                
                return new GetPromptResult(
                        "Security vulnerability analysis for " + programName,
                        messages
                );
            } finally {
                if (decompiler != null) {
                    decompiler.dispose();
                }
                program.release(this);
            }
        });
    }
}
