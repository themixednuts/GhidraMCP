package com.themixednuts.tools;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.AnalysisOptionInfo;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.models.OperationResult;
import com.themixednuts.models.ProgramInfo;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.app.services.GoToService;
import ghidra.framework.options.OptionType;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.common.McpTransportContext;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

@GhidraMcpTool(
    name = "Manage Project",
    description = "Project-level operations covering bookmarks, navigation, analysis settings, and program metadata.",
    mcpName = "manage_project",
    mcpDescription = """
        <use_case>
        Perform common project-level actions such as navigating to addresses, managing bookmarks, inspecting
        analysis options, and retrieving program metadata. Use this tool when coordinating tasks that involve
        program context or project configuration.
        </use_case>

        <important_notes>
        - Requires an open program; provide fileName for every request.
        - Bookmark operations execute within transactions and can modify the database.
        - Navigation relies on GoToService being available in the active tool.
        - Analysis option listing reflects current values and flags options still using defaults.
        </important_notes>

        <return_value_summary>
        - get_program_info: returns ProgramInfo with metadata and memory layout overview.
        - list_analysis_options: returns a list of AnalysisOptionInfo objects sorted by option name.
        - create_bookmark / delete_bookmark / go_to_address: return OperationResult describing outcome.
        </return_value_summary>

        <agent_response_guidance>
        Summarize the performed action, highlight key fields (e.g., address, number of bookmarks affected,
        notable analysis options), and mention any suggested follow-up steps when appropriate. Avoid dumping raw
        JSON unless explicitly requested.
        </agent_response_guidance>
        """
)
public class ManageProjectTool implements IGhidraMcpSpecification {

    public static final String ARG_ACTION = "action";
    public static final String ARG_BOOKMARK_TYPE = "bookmark_type";
    public static final String ARG_BOOKMARK_CATEGORY = "bookmark_category";
    public static final String ARG_COMMENT_CONTAINS = "comment_contains";

    private static final String ACTION_GET_PROGRAM_INFO = "get_program_info";
    private static final String ACTION_LIST_ANALYSIS_OPTIONS = "list_analysis_options";
    private static final String ACTION_CREATE_BOOKMARK = "create_bookmark";
    private static final String ACTION_DELETE_BOOKMARK = "delete_bookmark";
    private static final String ACTION_GO_TO_ADDRESS = "go_to_address";

    @Override
    public JsonSchema schema() {
        IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();

        schemaRoot.property(ARG_FILE_NAME,
                JsonSchemaBuilder.string(mapper)
                        .description("The name of the program file."));

        schemaRoot.property(ARG_ACTION, JsonSchemaBuilder.string(mapper)
                .enumValues(
                        ACTION_GET_PROGRAM_INFO,
                        ACTION_LIST_ANALYSIS_OPTIONS,
                        ACTION_CREATE_BOOKMARK,
                        ACTION_DELETE_BOOKMARK,
                        ACTION_GO_TO_ADDRESS)
                .description("Project-level operation to perform"));

        schemaRoot.property(ARG_ADDRESS, JsonSchemaBuilder.string(mapper)
                .description("Target address for navigation or bookmark operations")
                .pattern("^(0x)?[0-9a-fA-F]+$"));

        schemaRoot.property(ARG_BOOKMARK_TYPE, JsonSchemaBuilder.string(mapper)
                .description("Bookmark type (e.g., 'Note', 'Analysis')."));

        schemaRoot.property(ARG_BOOKMARK_CATEGORY, JsonSchemaBuilder.string(mapper)
                .description("Bookmark category (e.g., 'Default', 'My Analysis')."));

        schemaRoot.property(ARG_COMMENT, JsonSchemaBuilder.string(mapper)
                .description("Bookmark comment text."));

        schemaRoot.property(ARG_COMMENT_CONTAINS, JsonSchemaBuilder.string(mapper)
                .description("Filter for bookmark deletion: matches bookmarks whose comment contains this text."));

        schemaRoot.requiredProperty(ARG_FILE_NAME)
                .requiredProperty(ARG_ACTION);

        return schemaRoot.build();
    }

    @Override
    public Mono<? extends Object> execute(McpTransportContext context, Map<String, Object> args, PluginTool tool) {
        GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);

        return getProgram(args, tool).flatMap(program -> {
            String action = getRequiredStringArgument(args, ARG_ACTION);
            String normalizedAction = action.toLowerCase();

            return switch (normalizedAction) {
                case ACTION_GET_PROGRAM_INFO -> handleGetProgramInfo(program);
                case ACTION_LIST_ANALYSIS_OPTIONS -> handleListAnalysisOptions(program, args, annotation);
                case ACTION_CREATE_BOOKMARK -> handleCreateBookmark(program, args, annotation);
                case ACTION_DELETE_BOOKMARK -> handleDeleteBookmark(program, args, annotation);
                case ACTION_GO_TO_ADDRESS -> handleGoToAddress(program, args, tool, annotation);
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
                                            ACTION_GET_PROGRAM_INFO,
                                            ACTION_LIST_ANALYSIS_OPTIONS,
                                            ACTION_CREATE_BOOKMARK,
                                            ACTION_DELETE_BOOKMARK,
                                            ACTION_GO_TO_ADDRESS))))
                            .suggestions(List.of(
                                    new GhidraMcpError.ErrorSuggestion(
                                            GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
                                            "Use a valid action",
                                            "Choose one of the supported manage_project actions",
                                            List.of(
                                                    ACTION_GET_PROGRAM_INFO,
                                                    ACTION_LIST_ANALYSIS_OPTIONS,
                                                    ACTION_CREATE_BOOKMARK,
                                                    ACTION_DELETE_BOOKMARK,
                                                    ACTION_GO_TO_ADDRESS),
                                            null)))
                            .build();
                    yield Mono.error(new GhidraMcpException(error));
                }
            };
        });
    }

    private Mono<? extends Object> handleGetProgramInfo(Program program) {
        return Mono.fromCallable(() -> new ProgramInfo(program));
    }

    private Mono<? extends Object> handleListAnalysisOptions(Program program, Map<String, Object> args, GhidraMcpTool annotation) {
        return Mono.fromCallable(() -> {
            Options analysisOptions = program.getOptions(Program.ANALYSIS_PROPERTIES);
            if (analysisOptions == null) {
                GhidraMcpError error = GhidraMcpError.execution()
                        .errorCode(GhidraMcpError.ErrorCode.UNEXPECTED_ERROR)
                        .message("Analysis options are not available for program: " + program.getName())
                        .context(new GhidraMcpError.ErrorContext(
                                annotation.mcpName(),
                                ACTION_LIST_ANALYSIS_OPTIONS,
                                args,
                                Map.of("fileName", program.getName()),
                                Map.of("analysisOptionsAvailable", false)))
                        .build();
                throw new GhidraMcpException(error);
            }

            List<String> optionNames = analysisOptions.getOptionNames();
            List<AnalysisOptionInfo> results = new ArrayList<>(optionNames.size());

            for (String optionName : optionNames) {
                OptionType optionType = analysisOptions.getType(optionName);
                Object valueObj = analysisOptions.getObject(optionName, null);
                String value = valueObj != null ? valueObj.toString() : "null";
                boolean usingDefault = analysisOptions.isDefaultValue(optionName);

                String description = analysisOptions.getDescription(optionName);

                results.add(new AnalysisOptionInfo(
                        optionName,
                        description,
                        optionType != null ? optionType.toString() : "unknown",
                        value,
                        usingDefault));
            }

            results.sort(Comparator.comparing(AnalysisOptionInfo::getName, String.CASE_INSENSITIVE_ORDER));
            return results;
        });
    }

    private Mono<? extends Object> handleCreateBookmark(Program program, Map<String, Object> args, GhidraMcpTool annotation) {
        String addressStr = getRequiredStringArgument(args, ARG_ADDRESS);
        String bookmarkType = getRequiredStringArgument(args, ARG_BOOKMARK_TYPE);
        String bookmarkCategory = getRequiredStringArgument(args, ARG_BOOKMARK_CATEGORY);
        String comment = getRequiredStringArgument(args, ARG_COMMENT);

        if (bookmarkType.isBlank()) {
            return buildBlankArgumentError(annotation, args, ARG_BOOKMARK_TYPE, ACTION_CREATE_BOOKMARK, "Bookmark type must not be blank");
        }
        if (bookmarkCategory.isBlank()) {
            return buildBlankArgumentError(annotation, args, ARG_BOOKMARK_CATEGORY, ACTION_CREATE_BOOKMARK, "Bookmark category must not be blank");
        }

        return parseAddress(program, args, addressStr, ACTION_CREATE_BOOKMARK, annotation)
                .flatMap(addressResult -> executeInTransaction(program, "MCP - Create Bookmark", () -> {
            Address address = addressResult.getAddress();
            String normalizedAddress = addressResult.getAddressString();
            try {
                BookmarkManager bookmarkManager = program.getBookmarkManager();
                bookmarkManager.setBookmark(address, bookmarkType, bookmarkCategory, comment);

                return OperationResult.success(ACTION_CREATE_BOOKMARK, address.toString(),
                        "Bookmark created successfully.")
                        .setMetadata(Map.of(
                                ARG_BOOKMARK_TYPE, bookmarkType,
                                ARG_BOOKMARK_CATEGORY, bookmarkCategory));
            } catch (Exception e) {
                GhidraMcpError error = GhidraMcpError.execution()
                        .errorCode(GhidraMcpError.ErrorCode.TRANSACTION_FAILED)
                        .message("Failed to create bookmark: " + e.getMessage())
                        .context(new GhidraMcpError.ErrorContext(
                                annotation.mcpName(),
                                ACTION_CREATE_BOOKMARK,
                                args,
                                Map.of(
                                        ARG_ADDRESS, normalizedAddress,
                                        ARG_BOOKMARK_TYPE, bookmarkType,
                                        ARG_BOOKMARK_CATEGORY, bookmarkCategory),
                                Map.of("exceptionType", e.getClass().getSimpleName())))
                        .suggestions(List.of(
                                new GhidraMcpError.ErrorSuggestion(
                                        GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
                                        "Verify bookmark parameters",
                                        "Ensure the bookmark type and category are valid for the program",
                                        null,
                                        null)))
                        .build();
                throw new GhidraMcpException(error, e);
            }
        }));
    }

    private Mono<? extends Object> handleDeleteBookmark(Program program, Map<String, Object> args, GhidraMcpTool annotation) {
        String addressStr = getRequiredStringArgument(args, ARG_ADDRESS);
        Optional<String> bookmarkTypeOpt = getOptionalStringArgument(args, ARG_BOOKMARK_TYPE);
        Optional<String> bookmarkCategoryOpt = getOptionalStringArgument(args, ARG_BOOKMARK_CATEGORY);
        Optional<String> commentContainsOpt = getOptionalStringArgument(args, ARG_COMMENT_CONTAINS);

        return parseAddress(program, args, addressStr, ACTION_DELETE_BOOKMARK, annotation)
                .flatMap(addressResult -> executeInTransaction(program, "MCP - Delete Bookmark", () -> {
            Address address = addressResult.getAddress();
            String normalizedAddress = addressResult.getAddressString();
            try {
                BookmarkManager bookmarkManager = program.getBookmarkManager();
                Bookmark[] bookmarks = bookmarkManager.getBookmarks(address);

                if (bookmarks.length == 0) {
                    GhidraMcpError error = GhidraMcpError.resourceNotFound()
                            .errorCode(GhidraMcpError.ErrorCode.BOOKMARK_NOT_FOUND)
                            .message("No bookmarks found at address: " + addressStr)
                            .context(new GhidraMcpError.ErrorContext(
                                    annotation.mcpName(),
                                    ACTION_DELETE_BOOKMARK,
                                    args,
                                    Map.of(ARG_ADDRESS, normalizedAddress),
                                    Map.of("bookmarkCount", 0)))
                            .suggestions(List.of(
                                    new GhidraMcpError.ErrorSuggestion(
                                            GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
                                            "Inspect available bookmarks",
                                            "List bookmarks to verify available types and categories",
                                            null,
                                            List.of(annotation.mcpName()))))
                            .build();
                    throw new GhidraMcpException(error);
                }

                List<Bookmark> matched = Arrays.stream(bookmarks)
                        .filter(bookmark -> bookmarkTypeOpt
                                .map(type -> type.equals(bookmark.getTypeString()))
                                .orElse(true))
                        .filter(bookmark -> bookmarkCategoryOpt
                                .map(category -> category.equals(bookmark.getCategory()))
                                .orElse(true))
                        .filter(bookmark -> commentContainsOpt
                                .map(filter -> {
                                    String comment = bookmark.getComment();
                                    return comment != null && comment.contains(filter);
                                })
                                .orElse(true))
                        .collect(Collectors.toList());

                if (matched.isEmpty()) {
                    GhidraMcpError error = GhidraMcpError.resourceNotFound()
                            .errorCode(GhidraMcpError.ErrorCode.BOOKMARK_NOT_FOUND)
                            .message("No bookmarks matched the specified criteria at address: " + addressStr)
                            .context(new GhidraMcpError.ErrorContext(
                                    annotation.mcpName(),
                                    ACTION_DELETE_BOOKMARK,
                                    args,
                                    Map.of(
                                            ARG_ADDRESS, addressStr,
                                            ARG_BOOKMARK_TYPE, bookmarkTypeOpt.orElse("any"),
                                            ARG_BOOKMARK_CATEGORY, bookmarkCategoryOpt.orElse("any"),
                                            ARG_COMMENT_CONTAINS, commentContainsOpt.orElse("none")),
                                    Map.of("bookmarksInspected", bookmarks.length)))
                            .suggestions(List.of(
                                    new GhidraMcpError.ErrorSuggestion(
                                            GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
                                            "Review bookmark filters",
                                            "Adjust type, category, or comment filters to match existing bookmarks",
                                            null,
                                            null)))
                            .build();
                    throw new GhidraMcpException(error);
                }

                matched.forEach(bookmarkManager::removeBookmark);

                return OperationResult.success(ACTION_DELETE_BOOKMARK, address.toString(),
                        "Deleted " + matched.size() + " bookmark(s).")
                        .setMetadata(Map.of(
                                "deletedCount", matched.size(),
                                ARG_BOOKMARK_TYPE, bookmarkTypeOpt.orElse("any"),
                                ARG_BOOKMARK_CATEGORY, bookmarkCategoryOpt.orElse("any")));
            } catch (Exception e) {
                GhidraMcpError error = GhidraMcpError.execution()
                        .errorCode(GhidraMcpError.ErrorCode.TRANSACTION_FAILED)
                        .message("Failed to delete bookmark: " + e.getMessage())
                        .context(new GhidraMcpError.ErrorContext(
                                annotation.mcpName(),
                                ACTION_DELETE_BOOKMARK,
                                args,
                                Map.of("address", addressStr),
                                Map.of("exceptionType", e.getClass().getSimpleName())))
                        .suggestions(List.of(
                                new GhidraMcpError.ErrorSuggestion(
                                        GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
                                        "Verify program state and bookmark accessibility",
                                        "Ensure the program is writable and bookmark manager is available",
                                        null,
                                        null)))
                        .build();
                throw new GhidraMcpException(error, e);
            }
        }));
    }

    private Mono<? extends Object> handleGoToAddress(Program program, Map<String, Object> args, PluginTool tool, GhidraMcpTool annotation) {
        String addressStr = getRequiredStringArgument(args, ARG_ADDRESS);
        return parseAddress(program, args, addressStr, ACTION_GO_TO_ADDRESS, annotation)
                .flatMap(addressResult -> Mono.fromCallable(() -> {
            Address address = addressResult.getAddress();
            String normalizedAddress = addressResult.getAddressString();
            GoToService goToService = tool.getService(GoToService.class);
            if (goToService == null) {
                GhidraMcpError error = GhidraMcpError.internal()
                        .errorCode(GhidraMcpError.ErrorCode.CONFIGURATION_ERROR)
                        .message("GoToService is not available in the current tool context.")
                        .context(new GhidraMcpError.ErrorContext(
                                annotation.mcpName(),
                                ACTION_GO_TO_ADDRESS,
                                args,
                                Map.of("missingService", "GoToService"),
                                Map.of("serviceAvailable", false)))
                        .build();
                throw new GhidraMcpException(error);
            }

            boolean success = goToService.goTo(address, program);
            if (!success) {
                GhidraMcpError error = GhidraMcpError.execution()
                        .errorCode(GhidraMcpError.ErrorCode.UNEXPECTED_ERROR)
                        .message("Failed to navigate to address: " + addressStr)
                        .context(new GhidraMcpError.ErrorContext(
                                annotation.mcpName(),
                                ACTION_GO_TO_ADDRESS,
                                args,
                                Map.of(ARG_ADDRESS, normalizedAddress),
                                Map.of("navigationSucceeded", false)))
                        .suggestions(List.of(
                                new GhidraMcpError.ErrorSuggestion(
                                        GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
                                        "Verify program state and open views",
                                        "Ensure Listing or Decompiler views are open and the address is valid",
                                        null,
                                        null)))
                        .build();
                throw new GhidraMcpException(error);
            }

            return OperationResult.success(ACTION_GO_TO_ADDRESS, address.toString(),
                    "Navigation completed successfully.");
        }));
    }

    private Mono<? extends Object> buildBlankArgumentError(GhidraMcpTool annotation, Map<String, Object> args, String argumentName, String operation, String message) {
        GhidraMcpError error = GhidraMcpError.validation()
                .errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
                .message(message)
                .context(new GhidraMcpError.ErrorContext(
                        annotation.mcpName(),
                        operation,
                        args,
                        Map.of(argumentName, ""),
                        Map.of("blank", true)))
                .suggestions(List.of(
                        new GhidraMcpError.ErrorSuggestion(
                                GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
                                "Provide a non-empty value",
                                "Set the '" + argumentName + "' argument to a descriptive value",
                                List.of(argumentName + " = \"Example\""),
                                null)))
                .build();
        return Mono.error(new GhidraMcpException(error));
    }
}


