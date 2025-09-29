package com.themixednuts.tools;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.models.ProgramFileInfo;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.common.McpTransportContext;
import reactor.core.publisher.Mono;

@GhidraMcpTool(
    name = "List Programs",
    description = "Lists all programs (both open and closed) in the Ghidra project.",
    mcpName = "list_programs",
    mcpDescription = """
    <use_case>
    List all program files within the active Ghidra project, including both currently open programs
    and programs that exist in the project but are not currently loaded. Use this to discover
    available programs before performing operations that require a fileName parameter.
    </use_case>

    <return_value_summary>
    Returns an array of ProgramFileInfo objects, where each entry includes the program's name, project path,
    version, open status, and metadata. Programs are sorted by name for consistent ordering.
    </return_value_summary>

    <important_notes>
    - Requires an active project in the current PluginTool context.
    - Only lists files with program content type (executables, libraries, etc.).
    - If no programs exist in the project, returns an empty list without raising an error.
    - Closed programs can be opened by providing their fileName to other tools.
    </important_notes>
    """
)
public class ListProgramsTool implements IGhidraMcpSpecification {

    private static final String CONTEXT_OPERATION = "list_programs";

    /**
     * Defines the JSON input schema for listing programs.
     * 
     * @return The JsonSchema defining the expected input arguments
     */
    @Override
    public JsonSchema schema() {
        IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
        return schemaRoot.build();
    }

    /**
     * Executes the program listing operation.
     * 
     * @param context The MCP transport context
     * @param args The tool arguments (no arguments required for this tool)
     * @param tool The Ghidra PluginTool context
     * @return A Mono emitting a list of ProgramFileInfo objects
     */
    @Override
    public Mono<? extends Object> execute(
        McpTransportContext context,
        Map<String, Object> args,
        PluginTool tool
    ) {
        return Mono.fromCallable(() -> listPrograms(tool)).onErrorMap(this::wrapExecutionError);
    }

    /**
     * Lists all programs in the current project.
     * 
     * @param tool The Ghidra PluginTool context
     * @return A list of ProgramFileInfo objects representing all programs in the project
     * @throws GhidraMcpException If there's an error accessing the project or programs
     */
    private List<ProgramFileInfo> listPrograms(PluginTool tool) throws GhidraMcpException {
        Project project = java.util.Optional.ofNullable(tool)
            .map(PluginTool::getProject)
            .orElseThrow(() -> new GhidraMcpException(GhidraMcpError.execution()
                .errorCode(GhidraMcpError.ErrorCode.UNEXPECTED_ERROR)
                .message("No active project found in the current tool context")
                .context(new GhidraMcpError.ErrorContext(
                    this.getMcpName(),
                    CONTEXT_OPERATION,
                    Map.of(),
                    Map.of(),
                    Map.of("projectAvailable", false)
                ))
                .suggestions(List.of(
                    new GhidraMcpError.ErrorSuggestion(
                        GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
                        "Open or activate a Ghidra project",
                        "Ensure a project is open in the current tool before listing programs",
                        null,
                        null
                    )
                ))
                .build()));

        // Get all domain files from the project (recursively)
        List<DomainFile> allFiles = new ArrayList<>();
        collectDomainFiles(project.getProjectData().getRootFolder(), allFiles);

        // Filter for program files and convert to ProgramFileInfo
        return allFiles.stream()
            .filter(file -> file.getContentType().equals(Program.class.getName()))
            .sorted(Comparator.comparing(DomainFile::getName, String.CASE_INSENSITIVE_ORDER))
            .map(file -> createProgramFileInfo(project, file))
            .collect(Collectors.toList());
    }

    /**
     * Recursively collect all domain files from a folder and its subfolders.
     */
    private void collectDomainFiles(DomainFolder folder, List<DomainFile> files) {
        // Add files in current folder
        files.addAll(List.of(folder.getFiles()));
        
        // Recursively process subfolders
        for (DomainFolder subfolder : folder.getFolders()) {
            collectDomainFiles(subfolder, files);
        }
    }

    /**
     * Create a ProgramFileInfo object from a DomainFile.
     */
    private ProgramFileInfo createProgramFileInfo(Project project, DomainFile file) {
        // Generate program ID similar to ProgramEndpoints
        String programId = project.getName() + ":" + file.getPathname();
        
        // Check if program is currently open
        boolean isOpen = isProgramOpen(file);
        
        // Initialize basic info
        String architecture = null;
        String imageBase = null;
        Long programSize = null;
        
        // If program is open, get additional metadata
        if (isOpen) {
            try {
                Program program = (Program) file.getDomainObject(this, false, false, null);
                if (program != null) {
                    architecture = program.getLanguage().getProcessor().toString();
                    imageBase = program.getImageBase().toString();
                    programSize = program.getMemory().getSize();
                }
            } catch (Exception e) {
                // Log but don't fail - just skip additional metadata
                ghidra.util.Msg.debug(this, "Could not get program metadata for " + file.getName() + ": " + e.getMessage());
            }
        }
        
        return new ProgramFileInfo(
            file.getName(),
            file.getPathname(),
            programId,
            file.getVersion(),
            isOpen,
            file.isChanged(),
            file.isReadOnly(),
            architecture,
            imageBase,
            programSize
        );
    }

    /**
     * Check if a program is currently open.
     */
    private boolean isProgramOpen(DomainFile file) {
        try {
            return file.getDomainObject(this, false, false, null) instanceof Program;
        } catch (Exception e) {
            return false;
        }
    }

    private Throwable wrapExecutionError(Throwable throwable) {
        if (throwable instanceof GhidraMcpException) {
            return throwable;
        }

        GhidraMcpError error = GhidraMcpError.execution()
            .errorCode(GhidraMcpError.ErrorCode.UNEXPECTED_ERROR)
            .message("Failed to list programs: " + throwable.getMessage())
            .context(new GhidraMcpError.ErrorContext(
                this.getMcpName(),
                CONTEXT_OPERATION,
                Map.of(),
                Map.of("exceptionType", throwable.getClass().getSimpleName()),
                Map.of()
            ))
            .suggestions(List.of(
                new GhidraMcpError.ErrorSuggestion(
                    GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
                    "Verify project state",
                    "Ensure the Ghidra project is accessible and contains program files",
                    null,
                    null
                )
            ))
            .build();
        return new GhidraMcpException(error);
    }
}