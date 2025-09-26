package com.themixednuts.tools;

import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.models.OpenFileInfo;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.framework.model.DomainFile;
import ghidra.framework.model.Project;
import ghidra.framework.plugintool.PluginTool;
import io.modelcontextprotocol.common.McpTransportContext;
import reactor.core.publisher.Mono;

@GhidraMcpTool(
    name = "List Files",
    description = "Lists all currently open programs in Ghidra.",
    mcpName = "list_files",
    mcpDescription = """
    <use_case>
    List all currently open program files within the active Ghidra project. Use this when you need
    to confirm which programs are open before performing other operations that require a fileName.
    </use_case>

    <return_value_summary>
    Returns an array where each entry includes the file's name, project path, version number, and
    flags indicating whether the file has unsaved changes or is read-only.
    </return_value_summary>

    <important_notes>
    - Requires an active project in the current PluginTool context.
    - If no files are open, returns an empty list without raising an error.
    </important_notes>
    """
)
public class ListFilesTool implements IGhidraMcpSpecification {

    private static final String CONTEXT_OPERATION = "list_files";

    @Override
    public JsonSchema schema() {
        IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
        return schemaRoot.build();
    }

    @Override
    public Mono<? extends Object> execute(
        McpTransportContext context,
        Map<String, Object> args,
        PluginTool tool
    ) {
        return Mono.fromCallable(() -> listFiles(tool)).onErrorMap(this::wrapExecutionError);
    }

    private List<OpenFileInfo> listFiles(PluginTool tool) throws GhidraMcpException {
        Project project = tool != null ? tool.getProject() : null;
        if (project == null) {
            GhidraMcpError error = GhidraMcpError.execution()
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
                        "Ensure a project is open in the current tool before listing files",
                        null,
                        null
                    )
                ))
                .build();
            throw new GhidraMcpException(error);
        }

        return project
            .getOpenData()
            .stream()
            .sorted(Comparator.comparing(DomainFile::getName, String.CASE_INSENSITIVE_ORDER))
            .map(file -> new OpenFileInfo(
                file.getName(),
                file.getPathname(),
                file.getVersion(),
                file.isChanged(),
                file.isReadOnly()
            ))
            .collect(Collectors.toList());
    }

    private Throwable wrapExecutionError(Throwable throwable) {
        if (throwable instanceof GhidraMcpException) {
            return throwable;
        }

        GhidraMcpError error = GhidraMcpError.execution()
            .errorCode(GhidraMcpError.ErrorCode.UNEXPECTED_ERROR)
            .message("Failed to list files: " + throwable.getMessage())
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
                    "Ensure the Ghidra project is accessible and files are open",
                    null,
                    null
                )
            ))
            .build();
        return new GhidraMcpException(error);
    }
}


