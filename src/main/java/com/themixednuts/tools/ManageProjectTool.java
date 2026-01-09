package com.themixednuts.tools;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.models.OperationResult;
import com.themixednuts.models.ProgramInfo;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.draft7.SchemaBuilder;

import ghidra.app.services.GoToService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.common.McpTransportContext;
import reactor.core.publisher.Mono;

import java.util.Map;

@GhidraMcpTool(name = "Manage Project", description = "Project-level operations covering bookmarks, navigation, analysis settings, and program metadata.", mcpName = "manage_project", mcpDescription = """
                <use_case>
                Perform common project-level actions such as navigating to addresses, creating bookmarks, inspecting
                analysis options, and retrieving program metadata. Use this tool when coordinating tasks that involve
                program context or project configuration.
                </use_case>

                <important_notes>
                - Requires an open program; provide fileName for every request.
                - Bookmark operations execute within transactions and can modify the database.
                - Navigation relies on GoToService being available in the active tool.
                - Analysis option listing reflects current values and flags options still using defaults.
                - Use DeleteBookmarkTool to delete bookmarks
                </important_notes>

                <return_value_summary>
                - get_program_info: returns ProgramInfo with metadata and memory layout overview.
                - list_analysis_options: returns a list of AnalysisOptionInfo objects sorted by option name.
                - create_bookmark / go_to_address: return OperationResult describing outcome.
                </return_value_summary>

                <agent_response_guidance>
                Summarize the performed action, highlight key fields (e.g., address, number of bookmarks affected,
                notable analysis options), and mention any suggested follow-up steps when appropriate. Avoid dumping raw
                JSON unless explicitly requested.
                </agent_response_guidance>
                """)
public class ManageProjectTool extends BaseMcpTool {

        public static final String ARG_BOOKMARK_TYPE = "bookmark_type";
        public static final String ARG_BOOKMARK_CATEGORY = "bookmark_category";
        public static final String ARG_COMMENT_CONTAINS = "comment_contains";

        private static final String ACTION_GET_PROGRAM_INFO = "get_program_info";
        private static final String ACTION_CREATE_BOOKMARK = "create_bookmark";
        private static final String ACTION_GO_TO_ADDRESS = "go_to_address";

        /**
         * Defines the JSON input schema for project management operations.
         * 
         * @return The JsonSchema defining the expected input arguments
         */
        @Override
        public JsonSchema schema() {
                // Use Draft 7 builder for conditional support
                var schemaRoot = createDraft7SchemaNode();

                schemaRoot.property(ARG_FILE_NAME,
                                SchemaBuilder.string(mapper)
                                                .description("The name of the program file."));

                schemaRoot.property(ARG_ACTION, SchemaBuilder.string(mapper)
                                .enumValues(
                                                ACTION_GET_PROGRAM_INFO,
                                                ACTION_CREATE_BOOKMARK,
                                                ACTION_GO_TO_ADDRESS)
                                .description("Project-level operation to perform"));

                schemaRoot.property(ARG_ADDRESS, SchemaBuilder.string(mapper)
                                .description("Target address for navigation or bookmark operations")
                                .pattern("^(0x)?[0-9a-fA-F]+$"));

                schemaRoot.property(ARG_BOOKMARK_TYPE, SchemaBuilder.string(mapper)
                                .description("Bookmark type (e.g., 'Note', 'Analysis')."));

                schemaRoot.property(ARG_BOOKMARK_CATEGORY, SchemaBuilder.string(mapper)
                                .description("Bookmark category (e.g., 'Default', 'My Analysis')."));

                schemaRoot.property(ARG_COMMENT, SchemaBuilder.string(mapper)
                                .description("Bookmark comment text."));

                schemaRoot.property(ARG_COMMENT_CONTAINS, SchemaBuilder.string(mapper)
                                .description("Filter for bookmark deletion: matches bookmarks whose comment contains this text."));

                schemaRoot.requiredProperty(ARG_FILE_NAME)
                                .requiredProperty(ARG_ACTION);

                // Add conditional requirements based on action (JSON Schema Draft 7)
                schemaRoot.allOf(
                                // action=create_bookmark requires address, bookmark_type, bookmark_category, comment
                                SchemaBuilder.objectDraft7(mapper)
                                                .ifThen(
                                                                SchemaBuilder.objectDraft7(mapper)
                                                                                .property(ARG_ACTION, SchemaBuilder
                                                                                                .string(mapper)
                                                                                                .constValue(ACTION_CREATE_BOOKMARK)),
                                                                SchemaBuilder.objectDraft7(mapper)
                                                                                .requiredProperty(ARG_ADDRESS)
                                                                                .requiredProperty(ARG_BOOKMARK_TYPE)
                                                                                .requiredProperty(ARG_BOOKMARK_CATEGORY)
                                                                                .requiredProperty(ARG_COMMENT)),
                                // action=go_to_address requires address
                                SchemaBuilder.objectDraft7(mapper)
                                                .ifThen(
                                                                SchemaBuilder.objectDraft7(mapper)
                                                                                .property(ARG_ACTION, SchemaBuilder
                                                                                                .string(mapper)
                                                                                                .constValue(ACTION_GO_TO_ADDRESS)),
                                                                SchemaBuilder.objectDraft7(mapper)
                                                                                .requiredProperty(ARG_ADDRESS)));

                return schemaRoot.build();
        }

        /**
         * Executes the project management operation.
         * 
         * @param context The MCP transport context
         * @param args    The tool arguments containing fileName, action, and
         *                action-specific parameters
         * @param tool    The Ghidra PluginTool context
         * @return A Mono emitting the result of the project operation
         */
        @Override
        public Mono<? extends Object> execute(McpTransportContext context, Map<String, Object> args, PluginTool tool) {
                GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);

                return getProgram(args, tool).flatMap(program -> {
                        String action;
                        try {
                                action = getRequiredStringArgument(args, ARG_ACTION);
                        } catch (GhidraMcpException e) {
                                return Mono.error(e);
                        }
                        String normalizedAction = action.toLowerCase();

                        return switch (normalizedAction) {
                                case ACTION_GET_PROGRAM_INFO -> handleGetProgramInfo(program);
                                case ACTION_CREATE_BOOKMARK -> handleCreateBookmark(program, args, annotation);
                                case ACTION_GO_TO_ADDRESS -> handleGoToAddress(program, args, tool, annotation);
                                default -> {
                                        GhidraMcpError error = GhidraMcpError.invalid(ARG_ACTION, action,
                                                        "must be one of: " + ACTION_GET_PROGRAM_INFO + ", "
                                                                        + ACTION_CREATE_BOOKMARK + ", " + ACTION_GO_TO_ADDRESS);
                                        yield Mono.error(new GhidraMcpException(error));
                                }
                        };
                });
        }

        private Mono<? extends Object> handleGetProgramInfo(Program program) {
                return Mono.fromCallable(() -> new ProgramInfo(program));
        }

        private Mono<? extends Object> handleCreateBookmark(Program program, Map<String, Object> args,
                        GhidraMcpTool annotation) {
                String addressStr;
                String bookmarkType;
                String bookmarkCategory;
                String comment;
                try {
                        addressStr = getRequiredStringArgument(args, ARG_ADDRESS);
                        bookmarkType = getRequiredStringArgument(args, ARG_BOOKMARK_TYPE);
                        bookmarkCategory = getRequiredStringArgument(args, ARG_BOOKMARK_CATEGORY);
                        comment = getRequiredStringArgument(args, ARG_COMMENT);
                } catch (GhidraMcpException e) {
                        return Mono.error(e);
                }

                // Validate arguments with early returns
                if (bookmarkType.isBlank()) {
                        return buildBlankArgumentError(annotation, args, ARG_BOOKMARK_TYPE, ACTION_CREATE_BOOKMARK,
                                        ARG_BOOKMARK_TYPE + " must not be blank");
                }
                if (bookmarkCategory.isBlank()) {
                        return buildBlankArgumentError(annotation, args, ARG_BOOKMARK_CATEGORY, ACTION_CREATE_BOOKMARK,
                                        ARG_BOOKMARK_CATEGORY + " must not be blank");
                }

                return parseAddress(program, addressStr, ACTION_CREATE_BOOKMARK)
                                        .flatMap(addressResult -> executeInTransaction(program, "MCP - Create Bookmark",
                                                        () -> {
                                                                Address address = addressResult.getAddress();
                                                                String normalizedAddress = addressResult
                                                                                .getAddressString();
                                                                try {
                                                                        BookmarkManager bookmarkManager = program
                                                                                        .getBookmarkManager();
                                                                        bookmarkManager.setBookmark(address,
                                                                                        bookmarkType, bookmarkCategory,
                                                                                        comment);

                                                                        return OperationResult.success(
                                                                                        ACTION_CREATE_BOOKMARK,
                                                                                        address.toString(),
                                                                                        "Bookmark created successfully.")
                                                                                        .setMetadata(Map.of(
                                                                                                        ARG_BOOKMARK_TYPE,
                                                                                                        bookmarkType,
                                                                                                        ARG_BOOKMARK_CATEGORY,
                                                                                                        bookmarkCategory));
                                                                } catch (Exception e) {
                                                                        GhidraMcpError error = GhidraMcpError.failed(
                                                                                        "create bookmark",
                                                                                        e.getMessage());
                                                                        throw new GhidraMcpException(error, e);
                                                                }
                                                        }));
        }

        private Mono<? extends Object> handleGoToAddress(Program program, Map<String, Object> args, PluginTool tool,
                        GhidraMcpTool annotation) {
                String addressStr;
                try {
                        addressStr = getRequiredStringArgument(args, ARG_ADDRESS);
                } catch (GhidraMcpException e) {
                        return Mono.error(e);
                }
                return parseAddress(program, addressStr, ACTION_GO_TO_ADDRESS)
                                        .flatMap(addressResult -> Mono.fromCallable(() -> {
                                                Address address = addressResult.getAddress();
                                                String normalizedAddress = addressResult.getAddressString();
                                                GoToService goToService = tool != null ? tool.getService(GoToService.class) : null;
                                                if (goToService == null) {
                                                        GhidraMcpError error = GhidraMcpError.of(
                                                                        "GoToService is not available in the current tool context.");
                                                        throw new GhidraMcpException(error);
                                                }

                                                boolean success = goToService.goTo(address, program);
                                                if (!success) {
                                                        GhidraMcpError error = GhidraMcpError.failed(
                                                                        "navigate to address " + normalizedAddress,
                                                                        "ensure Listing or Decompiler views are open");
                                                        throw new GhidraMcpException(error);
                                                }

                                                return OperationResult.success(ACTION_GO_TO_ADDRESS, address.toString(),
                                                                "Navigation completed successfully.");
                                        }));
        }

        private Mono<? extends Object> buildBlankArgumentError(GhidraMcpTool annotation, Map<String, Object> args,
                        String argumentName, String operation, String message) {
                GhidraMcpError error = GhidraMcpError.invalid(argumentName, "", "must not be blank");
                return Mono.error(new GhidraMcpException(error));
        }
}
