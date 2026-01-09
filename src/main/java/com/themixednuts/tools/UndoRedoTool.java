package com.themixednuts.tools;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.google.SchemaBuilder;
import com.themixednuts.utils.jsonschema.google.SchemaBuilder.IObjectSchemaBuilder;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import io.modelcontextprotocol.common.McpTransportContext;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Undo/Redo", description = "Undo or redo changes in a Ghidra program, or get undo/redo information.", mcpName = "undo_redo", mcpDescription = """
        <use_case>
        Manage undo/redo operations for Ghidra programs. Can undo or redo changes made to a program,
        or get information about available undo/redo operations.
        </use_case>

        <return_value_summary>
        Returns information about the undo/redo operation performed, including:
        - The action taken (undo, redo, or info)
        - Current undo/redo availability
        - Names of available undo/redo operations
        - Success status
        </return_value_summary>

        <important_notes>
        - Requires an open program with transaction history
        - Undo/redo operations are performed on the Swing EDT thread
        - Each undo/redo operation corresponds to a completed transaction
        - Use 'action: info' to see available undo/redo operations without modifying the program
        </important_notes>

        <examples>
        Undo the last change:
        {
          "file_name": "program.exe",
          "action": "undo"
        }

        Redo the last undone change:
        {
          "file_name": "program.exe",
          "action": "redo"
        }

        Get undo/redo information:
        {
          "file_name": "program.exe",
          "action": "info"
        }
        </examples>
        """)
public class UndoRedoTool extends BaseMcpTool {

    // Action types
    private static final String ACTION_UNDO = "undo";
    private static final String ACTION_REDO = "redo";
    private static final String ACTION_INFO = "info";

    @Override
    public JsonSchema schema() {
        IObjectSchemaBuilder schemaRoot = createBaseSchemaNode();

        schemaRoot.property(ARG_FILE_NAME,
                SchemaBuilder.string(mapper)
                        .description("The name of the program file."));

        schemaRoot.property(BaseMcpTool.ARG_ACTION,
                SchemaBuilder.string(mapper)
                        .description("Action to perform: 'undo', 'redo', or 'info'")
                        .enumValues(new String[] { ACTION_UNDO, ACTION_REDO, ACTION_INFO }));

        schemaRoot.requiredProperty(ARG_FILE_NAME)
                .requiredProperty(BaseMcpTool.ARG_ACTION);

        return schemaRoot.build();
    }

    @Override
    public Mono<? extends Object> execute(
            McpTransportContext context,
            Map<String, Object> args,
            PluginTool tool) {
        GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);

        return getProgram(args, tool).flatMap(program -> {
            String action;
            try {
                action = getRequiredStringArgument(args, ARG_ACTION);
            } catch (GhidraMcpException e) {
                return Mono.error(e);
            }

            return switch (action.toLowerCase()) {
                case ACTION_UNDO -> handleUndo(program, args, annotation);
                case ACTION_REDO -> handleRedo(program, args, annotation);
                case ACTION_INFO -> handleInfo(program, args, annotation);
                default -> {
                    GhidraMcpError error = GhidraMcpError.validation()
                            .errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
                            .message("Invalid action: " + action)
                            .context(new GhidraMcpError.ErrorContext(
                                    annotation.mcpName(),
                                    "action validation",
                                    args,
                                    Map.of(ARG_ACTION, action),
                                    Map.of("validActions", List.of(
                                            ACTION_UNDO,
                                            ACTION_REDO,
                                            ACTION_INFO))))
                            .suggestions(List.of(
                                    new GhidraMcpError.ErrorSuggestion(
                                            GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
                                            "Use a valid action",
                                            "Choose from: undo, redo, info",
                                            List.of(
                                                    ACTION_UNDO,
                                                    ACTION_REDO,
                                                    ACTION_INFO),
                                            null)))
                            .build();
                    yield Mono.error(new GhidraMcpException(error));
                }
            };
        });
    }

    private Mono<? extends Object> handleUndo(Program program, Map<String, Object> args, GhidraMcpTool annotation) {
        return executeInTransaction(program, "MCP - Undo Operation", () -> {
            if (!program.canUndo()) {
                GhidraMcpError error = GhidraMcpError.execution()
                        .errorCode(GhidraMcpError.ErrorCode.INVALID_PROGRAM_STATE)
                        .message("No operations available to undo")
                        .context(new GhidraMcpError.ErrorContext(
                                annotation.mcpName(),
                                "undo operation",
                                args,
                                Map.of("canUndo", false),
                                Map.of("undoAvailable", false)))
                        .suggestions(List.of(
                                new GhidraMcpError.ErrorSuggestion(
                                        GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
                                        "Check undo/redo status",
                                        "Use action 'info' to see available undo/redo operations",
                                        null,
                                        null)))
                        .build();
                throw new GhidraMcpException(error);
            }

            String undoName = program.getUndoName();
            program.undo();
            Msg.info(this, "Undone operation: " + undoName);

            return createUndoRedoResult("undo", undoName, program);
        });
    }

    private Mono<? extends Object> handleRedo(Program program, Map<String, Object> args, GhidraMcpTool annotation) {
        return executeInTransaction(program, "MCP - Redo Operation", () -> {
            if (!program.canRedo()) {
                GhidraMcpError error = GhidraMcpError.execution()
                        .errorCode(GhidraMcpError.ErrorCode.INVALID_PROGRAM_STATE)
                        .message("No operations available to redo")
                        .context(new GhidraMcpError.ErrorContext(
                                annotation.mcpName(),
                                "redo operation",
                                args,
                                Map.of("canRedo", false),
                                Map.of("redoAvailable", false)))
                        .suggestions(List.of(
                                new GhidraMcpError.ErrorSuggestion(
                                        GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
                                        "Check undo/redo status",
                                        "Use action 'info' to see available undo/redo operations",
                                        null,
                                        null)))
                        .build();
                throw new GhidraMcpException(error);
            }

            String redoName = program.getRedoName();
            program.redo();
            Msg.info(this, "Redone operation: " + redoName);

            return createUndoRedoResult("redo", redoName, program);
        });
    }

    private Mono<? extends Object> handleInfo(Program program, Map<String, Object> args, GhidraMcpTool annotation) {
        return Mono.fromCallable(() -> {
            Map<String, Object> result = new HashMap<>();
            result.put("action", "info");
            result.put("can_undo", program.canUndo());
            result.put("can_redo", program.canRedo());

            if (program.canUndo()) {
                result.put("next_undo", program.getUndoName());
            }
            if (program.canRedo()) {
                result.put("next_redo", program.getRedoName());
            }

            // Get all undo/redo names if available
            List<String> undoList = program.getAllUndoNames();
            List<String> redoList = program.getAllRedoNames();

            result.put("undo_list", undoList);
            result.put("redo_list", redoList);
            result.put("undo_count", undoList.size());
            result.put("redo_count", redoList.size());

            return result;
        });
    }

    private Map<String, Object> createUndoRedoResult(String action, String operationName, Program program) {
        Map<String, Object> result = new HashMap<>();
        result.put("action", action);
        result.put("success", true);

        if ("undo".equals(action)) {
            result.put("undone_operation", operationName);
        } else if ("redo".equals(action)) {
            result.put("redone_operation", operationName);
        }

        // Add current state info
        result.put("can_undo", program.canUndo());
        result.put("can_redo", program.canRedo());
        if (program.canUndo()) {
            result.put("next_undo", program.getUndoName());
        }
        if (program.canRedo()) {
            result.put("next_redo", program.getRedoName());
        }

        return result;
    }
}
