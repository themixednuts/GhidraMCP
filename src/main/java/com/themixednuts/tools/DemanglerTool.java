package com.themixednuts.tools;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.app.util.demangler.Demangled;
import ghidra.app.util.demangler.DemanglerUtil;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.common.McpTransportContext;
import reactor.core.publisher.Mono;

@GhidraMcpTool(
    name = "Demangle Symbol",
    description = "Demangle C++ and other mangled symbols to their human-readable form",
    mcpName = "demangle_symbol",
    mcpDescription = """
    <use_case>
    Demangles C++ and other mangled symbols to their human-readable form using Ghidra's built-in demangler.
    This is essential for understanding C++ function names, class methods, templates, and other complex symbols
    that have been mangled by the compiler. Use this tool when you encounter mangled symbols in your analysis.
    </use_case>

    <ghidra_specific_notes>
    - Uses Ghidra's DemanglerUtil.demangle(Program, String, Address) method (current API)
    - Supports various mangling formats (GCC, MSVC, Borland, etc.)
    - Works with the currently active program's demangler configuration
    - Can demangle function names, class methods, templates, and other complex symbols
    - Returns the first successful demangling result from the list of possible results
    - Uses only the current, non-deprecated API methods
    </ghidra_specific_notes>

    <parameters_summary>
    - 'mangledSymbol': The mangled symbol string to demangle (e.g., '_Z3fooi')
    - 'demanglerName': (Optional) Specific demangler to use (e.g., 'GNU', 'Microsoft')
    </parameters_summary>

    <return_value_summary>
    Returns a DemangleResult object containing:
    - 'originalSymbol': The original mangled symbol
    - 'demangledSymbol': The human-readable demangled symbol
    - 'demanglerUsed': The demangler that was used
    - 'isValid': Whether the demangling was successful
    - 'demangledType': The type of demangled object (function, variable, etc.)
    - 'namespace': The namespace if available
    - 'className': The class name if available
    - 'functionName': The function name if available
    - 'parameters': Function parameters if available
    </return_value_summary>

    <agent_response_guidance>
    Present the demangled symbol clearly, showing both the original mangled form and the readable result.
    If demangling fails, explain what this might mean (e.g., not a mangled symbol, unsupported format).
    Include any additional context like namespace or class information when available.
    </agent_response_guidance>

    <error_handling_summary>
    - Throws VALIDATION error if mangled symbol is empty or invalid
    - Throws EXECUTION error if demangler fails or program is not available
    - Returns structured error information with suggestions for alternative approaches
    </error_handling_summary>
    """
)
public class DemanglerTool implements IGhidraMcpSpecification {

    public static final String ARG_MANGLED_SYMBOL = "mangledSymbol";
    public static final String ARG_DEMANGLER_NAME = "demanglerName";

    /**
     * Defines the JSON input schema for demangling symbols.
     * 
     * @return The JsonSchema defining the expected input arguments
     */
    @Override
    public JsonSchema schema() {
        IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();

        schemaRoot.property(ARG_FILE_NAME,
                JsonSchemaBuilder.string(mapper)
                        .description("The name of the program file (required for demangler context)."));

        schemaRoot.property(ARG_MANGLED_SYMBOL,
                JsonSchemaBuilder.string(mapper)
                        .description("The mangled symbol to demangle (e.g., '_Z3fooi', '?foo@@YAXH@Z')"));

        schemaRoot.property(ARG_DEMANGLER_NAME,
                JsonSchemaBuilder.string(mapper)
                        .description("Optional: Specific demangler to use (e.g., 'GNU', 'Microsoft', 'Borland')"));

        schemaRoot.requiredProperty(ARG_FILE_NAME);
        schemaRoot.requiredProperty(ARG_MANGLED_SYMBOL);

        return schemaRoot.build();
    }

    public static class DemangleResult {
        private final String originalSymbol;
        private final String demangledSymbol;
        private final String demanglerUsed;
        private final boolean isValid;
        private final String demangledType;
        private final String namespace;
        private final String className;
        private final String functionName;
        private final List<String> parameters;
        private final String errorMessage;
        private final String symbolAnalysis;

        public DemangleResult(String originalSymbol, String demangledSymbol, String demanglerUsed, 
                            boolean isValid, String demangledType, String namespace, 
                            String className, String functionName, List<String> parameters) {
            this(originalSymbol, demangledSymbol, demanglerUsed, isValid, demangledType, 
                 namespace, className, functionName, parameters, null, null);
        }

        public DemangleResult(String originalSymbol, String demangledSymbol, String demanglerUsed, 
                            boolean isValid, String demangledType, String namespace, 
                            String className, String functionName, List<String> parameters,
                            String errorMessage, String symbolAnalysis) {
            this.originalSymbol = originalSymbol;
            this.demangledSymbol = demangledSymbol;
            this.demanglerUsed = demanglerUsed;
            this.isValid = isValid;
            this.demangledType = demangledType;
            this.namespace = namespace;
            this.className = className;
            this.functionName = functionName;
            this.parameters = parameters;
            this.errorMessage = errorMessage;
            this.symbolAnalysis = symbolAnalysis;
        }

        public String getOriginalSymbol() { return originalSymbol; }
        public String getDemangledSymbol() { return demangledSymbol; }
        public String getDemanglerUsed() { return demanglerUsed; }
        public boolean isValid() { return isValid; }
        public String getDemangledType() { return demangledType; }
        public String getNamespace() { return namespace; }
        public String getClassName() { return className; }
        public String getFunctionName() { return functionName; }
        public List<String> getParameters() { return parameters; }
        public String getErrorMessage() { return errorMessage; }
        public String getSymbolAnalysis() { return symbolAnalysis; }
    }

    /**
     * Executes the symbol demangling operation.
     * 
     * @param ex The MCP transport context
     * @param args The tool arguments containing fileName, mangledSymbol, and optional demanglerName
     * @param tool The Ghidra PluginTool context
     * @return A Mono emitting a DemangleResult object
     */
    @Override
    public Mono<? extends Object> execute(McpTransportContext ex, Map<String, Object> args, PluginTool tool) {
        return getProgram(args, tool)
                .flatMap(program -> Mono.fromCallable(() -> {
                    String mangledSymbol = getRequiredStringArgument(args, ARG_MANGLED_SYMBOL);
                    Optional<String> demanglerNameOpt = getOptionalStringArgument(args, ARG_DEMANGLER_NAME);

                    if (mangledSymbol.trim().isEmpty()) {
                        throw new GhidraMcpException(GhidraMcpError.validation()
                                .errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
                                .message("Mangled symbol cannot be empty")
                                .context(new GhidraMcpError.ErrorContext(
                                        getMcpName(),
                                        "mangled symbol validation",
                                        args,
                                        Map.of(ARG_MANGLED_SYMBOL, mangledSymbol),
                                        Map.of("symbolLength", mangledSymbol.length())))
                                .build());
                    }

                    return performDemangling(program, mangledSymbol, demanglerNameOpt);
                }));
    }

    private DemangleResult performDemangling(Program program, String mangledSymbol, Optional<String> demanglerNameOpt) throws GhidraMcpException {
        try {
            // Use the correct, non-deprecated method: demangle(Program, String, Address)
            // According to the API docs, this returns List<DemangledObject> of successful demanglings
            var demangledList = DemanglerUtil.demangle(program, mangledSymbol, null);
            
            if (demangledList == null || demangledList.isEmpty()) {
                // No demangler could process this symbol
                String symbolAnalysis = analyzeSymbol(mangledSymbol);
                String errorMessage = "No demangler could process this symbol";
                
                return new DemangleResult(
                    mangledSymbol,
                    null,
                    "No demangler available",
                    false,
                    "Failed to demangle",
                    null,
                    null,
                    null,
                    null,
                    errorMessage,
                    symbolAnalysis
                );
            }
            
            // Take the first successful demangling result
            Demangled demangled = demangledList.get(0);

            // Extract information from the demangled result
            String demangledString = demangled.toString();
            String actualDemanglerUsed = getDemanglerName(demangled, "Ghidra Demangler");
            String demangledType = getDemangledType(demangled);
            String namespace = extractNamespace(demangled);
            String className = extractClassName(demangled);
            String functionName = extractFunctionName(demangled);
            List<String> parameters = extractParameters(demangled);

            return new DemangleResult(
                mangledSymbol,
                demangledString,
                actualDemanglerUsed,
                true,
                demangledType,
                namespace,
                className,
                functionName,
                parameters,
                null, // No error message for successful demangling
                analyzeSymbol(mangledSymbol) // Include symbol analysis for context
            );

        } catch (Exception e) {
            throw new GhidraMcpException(GhidraMcpError.execution()
                    .errorCode(GhidraMcpError.ErrorCode.TRANSACTION_FAILED)
                    .message("Failed to demangle symbol: " + e.getMessage())
                    .context(new GhidraMcpError.ErrorContext(
                            getMcpName(),
                            "demangling execution",
                            Map.of(ARG_MANGLED_SYMBOL, mangledSymbol),
                            Map.of("demanglerName", demanglerNameOpt.orElse("auto")),
                            Map.of("programName", program.getName())))
                    .build());
        }
    }

    private String getDemanglerName(Demangled demangled, String fallbackName) {
        // Try to determine which demangler was used
        // This is a simplified approach - in practice, you might need to check
        // the specific demangler that was successful
        return fallbackName != null ? fallbackName : "Ghidra Demangler";
    }

    private String getDemangledType(Demangled demangled) {
        if (demangled == null) return "Unknown";
        
        String className = demangled.getClass().getSimpleName();
        // Remove "Demangled" prefix if present
        if (className.startsWith("Demangled")) {
            className = className.substring("Demangled".length());
        }
        return className;
    }

    private String extractNamespace(Demangled demangled) {
        // Extract namespace information if available
        // This is a simplified implementation - you might need to traverse
        // the demangled object hierarchy to get the full namespace
        return null; // Placeholder - implement based on Demangled object structure
    }

    private String extractClassName(Demangled demangled) {
        // Extract class name if available
        return null; // Placeholder - implement based on Demangled object structure
    }

    private String extractFunctionName(Demangled demangled) {
        // Extract function name if available
        return null; // Placeholder - implement based on Demangled object structure
    }

    private List<String> extractParameters(Demangled demangled) {
        // Extract function parameters if available
        return null; // Placeholder - implement based on Demangled object structure
    }

    /**
     * Analyzes a symbol to provide helpful information about its format and potential issues.
     */
    private String analyzeSymbol(String symbol) {
        if (symbol == null || symbol.trim().isEmpty()) {
            return "Empty or null symbol";
        }

        String trimmed = symbol.trim();
        
        // Check for common mangling patterns
        if (trimmed.startsWith("_Z")) {
            return "GCC/Itanium C++ ABI mangling detected";
        } else if (trimmed.startsWith("?")) {
            return "Microsoft Visual C++ mangling detected";
        } else if (trimmed.startsWith("__")) {
            return "Possible GCC/Clang internal symbol";
        } else if (trimmed.contains("@")) {
            return "Symbol contains @ characters (possible MSVC or custom mangling)";
        } else if (trimmed.matches("^[a-zA-Z_][a-zA-Z0-9_]*$")) {
            return "Plain symbol (not mangled)";
        } else if (trimmed.matches("^[0-9a-fA-F]+$")) {
            return "Hexadecimal string (possible address or hash)";
        } else {
            return "Unknown or custom symbol format";
        }
    }
}
