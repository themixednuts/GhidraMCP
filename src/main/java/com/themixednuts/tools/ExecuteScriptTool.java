package com.themixednuts.tools;

import java.util.Map;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.common.McpTransportContext;
import reactor.core.publisher.Mono;

@GhidraMcpTool(
    name = "Script Guidance Tool",
    description = "Provides guidance on using Ghidra scripts like DemangleAllScript for advanced demangling",
    mcpName = "script_guidance",
    mcpDescription = """
    <use_case>
    Provides guidance on using Ghidra's built-in scripts, particularly DemangleAllScript.java which offers
    more powerful demangling capabilities than the basic DemanglerUtil API. This is especially useful for
    complex scenarios like Win64 DLLs with PDB files where standard demangling might fail.
    Use this tool when you need information about how to access and use Ghidra's advanced scripting capabilities.
    </use_case>

    <ghidra_specific_notes>
    - Provides step-by-step instructions for accessing Ghidra scripts
    - Explains how to use DemangleAllScript for advanced demangling
    - Covers both built-in scripts and custom script execution
    - Includes troubleshooting tips for common script execution issues
    - References the Script Manager interface in Ghidra
    </ghidra_specific_notes>

    <parameters_summary>
    - 'scriptName': Name of the script you want guidance on (e.g., 'DemangleAllScript')
    - 'guidanceType': Type of guidance needed (e.g., 'access', 'usage', 'troubleshooting')
    </parameters_summary>

    <return_value_summary>
    Returns a ScriptGuidance object containing:
    - 'scriptName': The script you requested guidance for
    - 'guidanceType': The type of guidance provided
    - 'instructions': Step-by-step instructions
    - 'tips': Additional tips and best practices
    - 'troubleshooting': Common issues and solutions
    </return_value_summary>

    <agent_response_guidance>
    Present the guidance in a clear, step-by-step format that's easy to follow.
    For DemangleAllScript, emphasize that it's more powerful than basic demangling tools.
    Include practical tips and troubleshooting advice for common issues.
    </agent_response_guidance>
    """
)
public class ExecuteScriptTool implements IGhidraMcpSpecification {

    public static final String ARG_SCRIPT_NAME = "scriptName";
    public static final String ARG_GUIDANCE_TYPE = "guidanceType";

    @Override
    public JsonSchema schema() {
        IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();

        schemaRoot.property(ARG_FILE_NAME,
                JsonSchemaBuilder.string(mapper)
                        .description("The name of the program file (required for context)."));

        schemaRoot.property(ARG_SCRIPT_NAME,
                JsonSchemaBuilder.string(mapper)
                        .description("Name of the script you want guidance on (e.g., 'DemangleAllScript')"));

        schemaRoot.property(ARG_GUIDANCE_TYPE,
                JsonSchemaBuilder.string(mapper)
                        .description("Type of guidance needed: 'access', 'usage', 'troubleshooting', or 'all'")
                        .enumValues(new String[]{"access", "usage", "troubleshooting", "all"}));

        schemaRoot.requiredProperty(ARG_FILE_NAME);
        schemaRoot.requiredProperty(ARG_SCRIPT_NAME);

        return schemaRoot.build();
    }

    public static class ScriptGuidance {
        private final String scriptName;
        private final String guidanceType;
        private final String instructions;
        private final String tips;
        private final String troubleshooting;

        public ScriptGuidance(String scriptName, String guidanceType, String instructions, String tips, String troubleshooting) {
            this.scriptName = scriptName;
            this.guidanceType = guidanceType;
            this.instructions = instructions;
            this.tips = tips;
            this.troubleshooting = troubleshooting;
        }

        public String getScriptName() { return scriptName; }
        public String getGuidanceType() { return guidanceType; }
        public String getInstructions() { return instructions; }
        public String getTips() { return tips; }
        public String getTroubleshooting() { return troubleshooting; }
    }

    @Override
    public Mono<? extends Object> execute(McpTransportContext ex, Map<String, Object> args, PluginTool tool) {
        return getProgram(args, tool)
                .flatMap(program -> Mono.fromCallable(() -> {
                    String scriptName = getRequiredStringArgument(args, ARG_SCRIPT_NAME);
                    String guidanceType = getOptionalStringArgument(args, ARG_GUIDANCE_TYPE).orElse("all");

                    if (scriptName.trim().isEmpty()) {
                        throw new GhidraMcpException(GhidraMcpError.validation()
                                .errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
                                .message("Script name cannot be empty")
                                .context(new GhidraMcpError.ErrorContext(
                                        getMcpName(),
                                        "script name validation",
                                        args,
                                        Map.of(ARG_SCRIPT_NAME, scriptName),
                                        Map.of("scriptNameLength", scriptName.length())))
                                .build());
                    }

                    return provideScriptGuidance(scriptName, guidanceType, program);
                }));
    }

    private ScriptGuidance provideScriptGuidance(String scriptName, String guidanceType, Program program) {
        if ("DemangleAllScript".equalsIgnoreCase(scriptName) || "DemangleAllScript.java".equalsIgnoreCase(scriptName)) {
            return provideDemangleAllScriptGuidance(guidanceType, program);
        } else {
            return provideGeneralScriptGuidance(scriptName, guidanceType, program);
        }
    }

    private ScriptGuidance provideDemangleAllScriptGuidance(String guidanceType, Program program) {
        String instructions = "";
        String tips = "";
        String troubleshooting = "";

        if ("access".equals(guidanceType) || "all".equals(guidanceType)) {
            instructions = """
                1. Open Ghidra and load your program
                2. Go to Window → Script Manager (or press Ctrl+Shift+S)
                3. In the Script Manager, navigate to the "Symbol" folder
                4. Find "DemangleAllScript.java" in the Symbol folder
                5. Select the script and click "Run" button
                6. The script will automatically demangle all symbols in your program
                """;
        }

        if ("usage".equals(guidanceType) || "all".equals(guidanceType)) {
            instructions += """
                
                Usage Details:
                - DemangleAllScript is more powerful than basic DemanglerUtil API
                - It can handle complex scenarios like Win64 DLLs with PDB files
                - Works better with Microsoft Visual C++ mangled symbols
                - Automatically processes all symbols in the program
                - No parameters needed - just run the script
                """;
        }

        if ("troubleshooting".equals(guidanceType) || "all".equals(guidanceType)) {
            troubleshooting = """
                Common Issues and Solutions:
                
                1. Script not found in Symbol folder:
                   - Make sure you're looking in the correct folder
                   - Try searching for "DemangleAllScript" in the search bar
                
                2. Script execution fails:
                   - Ensure your program is fully loaded and analyzed
                   - Check that you have a valid program open
                   - Try running Auto Analysis first if symbols aren't demangled
                
                3. Some symbols still not demangled:
                   - This is normal - not all symbols can be demangled
                   - The script will skip symbols it cannot process
                   - Check the Console window for any error messages
                
                4. For Win64 DLLs with PDB:
                   - Make sure the PDB file is loaded
                   - DemangleAllScript works better than basic demangling for these cases
                """;
        }

        tips = """
            Pro Tips:
            - DemangleAllScript is particularly effective for Microsoft Visual C++ symbols
            - It's better than the basic DemanglerUtil API for complex mangling scenarios
            - Run this script after initial analysis but before detailed reverse engineering
            - The script processes all symbols automatically - no manual selection needed
            - Results are immediately visible in the Symbol Tree and Listing windows
            """;

        return new ScriptGuidance("DemangleAllScript", guidanceType, instructions, tips, troubleshooting);
    }

    private ScriptGuidance provideGeneralScriptGuidance(String scriptName, String guidanceType, Program program) {
        String instructions = """
            1. Open Ghidra and load your program
            2. Go to Window → Script Manager (or press Ctrl+Shift+S)
            3. Browse or search for the script you want to run
            4. Select the script and click "Run" button
            5. Follow any prompts or parameter dialogs that appear
            """;

        String tips = """
            General Script Tips:
            - Most scripts work on the currently active program
            - Some scripts may require specific analysis to be completed first
            - Check the Console window for script output and error messages
            - Scripts are located in various folders based on their functionality
            """;

        String troubleshooting = """
            Common Issues:
            - Script not found: Check the correct folder or use search
            - Execution fails: Ensure program is loaded and analyzed
            - No results: Check Console window for error messages
            """;

        return new ScriptGuidance(scriptName, guidanceType, instructions, tips, troubleshooting);
    }

}
