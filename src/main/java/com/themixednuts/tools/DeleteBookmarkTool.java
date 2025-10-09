package com.themixednuts.tools;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.models.OperationResult;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.google.SchemaBuilder;
import com.themixednuts.utils.jsonschema.google.SchemaBuilder.IObjectSchemaBuilder;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.common.McpTransportContext;
import reactor.core.publisher.Mono;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

@GhidraMcpTool(name = "Delete Bookmark", description = "Delete bookmarks at a specified address with optional filtering by type, category, and comment content.", mcpName = "delete_bookmark", mcpDescription = """
                <use_case>
                Deletes one or more bookmarks at a specified address. Supports filtering by bookmark type,
                category, and comment content to allow selective deletion of bookmarks.
                </use_case>

                <important_notes>
                - NOTE: If you plan to delete and recreate a bookmark at the same location, consider if updating the existing bookmark would be more appropriate
                - Address is required to identify bookmarks
                - Optional filters: bookmark_type, bookmark_category, comment_contains
                - Without filters, all bookmarks at the address will be deleted
                - Multiple bookmarks can be deleted in a single operation if they match the filters
                - Bookmark deletion is permanent and cannot be undone without undo/redo
                </important_notes>

                <examples>
                Delete all bookmarks at an address:
                {
                  "fileName": "program.exe",
                  "address": "0x401000"
                }

                Delete bookmarks of a specific type:
                {
                  "fileName": "program.exe",
                  "address": "0x401000",
                  "bookmark_type": "Note"
                }

                Delete bookmarks with specific comment:
                {
                  "fileName": "program.exe",
                  "address": "0x401000",
                  "comment_contains": "TODO"
                }

                Delete bookmarks matching all filters:
                {
                  "fileName": "program.exe",
                  "address": "0x401000",
                  "bookmark_type": "Note",
                  "bookmark_category": "Analysis",
                  "comment_contains": "review"
                }
                </examples>
                """)
public class DeleteBookmarkTool implements IGhidraMcpSpecification {

        public static final String ARG_ADDRESS = "address";
        public static final String ARG_BOOKMARK_TYPE = "bookmark_type";
        public static final String ARG_BOOKMARK_CATEGORY = "bookmark_category";
        public static final String ARG_COMMENT_CONTAINS = "comment_contains";

        @Override
        public JsonSchema schema() {
                IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();

                schemaRoot.property(ARG_FILE_NAME,
                                SchemaBuilder.string(mapper)
                                                .description("The name of the program file."));

                schemaRoot.property(ARG_ADDRESS, SchemaBuilder.string(mapper)
                                .description("Target address for bookmark deletion")
                                .pattern("^(0x)?[0-9a-fA-F]+$"));

                schemaRoot.property(ARG_BOOKMARK_TYPE, SchemaBuilder.string(mapper)
                                .description("Optional: Filter bookmarks by type (e.g., 'Note', 'Analysis')."));

                schemaRoot.property(ARG_BOOKMARK_CATEGORY, SchemaBuilder.string(mapper)
                                .description("Optional: Filter bookmarks by category (e.g., 'Default', 'My Analysis')."));

                schemaRoot.property(ARG_COMMENT_CONTAINS, SchemaBuilder.string(mapper)
                                .description("Optional: Filter bookmarks whose comment contains this text."));

                schemaRoot.requiredProperty(ARG_FILE_NAME)
                                .requiredProperty(ARG_ADDRESS);

                return schemaRoot.build();
        }

        @Override
        public Mono<? extends Object> execute(McpTransportContext context, Map<String, Object> args, PluginTool tool) {
                GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);

                return getProgram(args, tool).flatMap(program -> handleDeleteBookmark(program, args, annotation));
        }

        private Mono<? extends Object> handleDeleteBookmark(Program program, Map<String, Object> args,
                        GhidraMcpTool annotation) {
                String addressStr = getRequiredStringArgument(args, ARG_ADDRESS);
                Optional<String> bookmarkTypeOpt = getOptionalStringArgument(args, ARG_BOOKMARK_TYPE);
                Optional<String> bookmarkCategoryOpt = getOptionalStringArgument(args, ARG_BOOKMARK_CATEGORY);
                Optional<String> commentContainsOpt = getOptionalStringArgument(args, ARG_COMMENT_CONTAINS);

                try {
                        return parseAddress(program, args, addressStr, annotation.mcpName(), annotation)
                                        .flatMap(addressResult -> executeInTransaction(program, "MCP - Delete Bookmark",
                                                        () -> {
                                                                Address address = addressResult.getAddress();
                                                                String normalizedAddress = addressResult
                                                                                .getAddressString();
                                                                try {
                                                                        BookmarkManager bookmarkManager = program
                                                                                        .getBookmarkManager();
                                                                        Bookmark[] bookmarks = bookmarkManager
                                                                                        .getBookmarks(address);

                                                                        if (bookmarks.length == 0) {
                                                                                GhidraMcpError error = GhidraMcpError
                                                                                                .resourceNotFound()
                                                                                                .errorCode(GhidraMcpError.ErrorCode.BOOKMARK_NOT_FOUND)
                                                                                                .message("No bookmarks found at address: "
                                                                                                                + addressStr)
                                                                                                .context(new GhidraMcpError.ErrorContext(
                                                                                                                annotation.mcpName(),
                                                                                                                "bookmark lookup",
                                                                                                                args,
                                                                                                                Map.of(ARG_ADDRESS,
                                                                                                                                normalizedAddress),
                                                                                                                Map.of("bookmarkCount",
                                                                                                                                0)))
                                                                                                .suggestions(List.of(
                                                                                                                new GhidraMcpError.ErrorSuggestion(
                                                                                                                                GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
                                                                                                                                "Inspect available bookmarks",
                                                                                                                                "List bookmarks to verify available types and categories",
                                                                                                                                null,
                                                                                                                                null)))
                                                                                                .build();
                                                                                throw new GhidraMcpException(error);
                                                                        }

                                                                        List<Bookmark> matched = Arrays
                                                                                        .stream(bookmarks)
                                                                                        .filter(bookmark -> bookmarkTypeOpt
                                                                                                        .map(type -> type
                                                                                                                        .equals(bookmark.getTypeString()))
                                                                                                        .orElse(true))
                                                                                        .filter(bookmark -> bookmarkCategoryOpt
                                                                                                        .map(category -> category
                                                                                                                        .equals(bookmark.getCategory()))
                                                                                                        .orElse(true))
                                                                                        .filter(bookmark -> commentContainsOpt
                                                                                                        .map(filter -> Optional
                                                                                                                        .ofNullable(bookmark
                                                                                                                                        .getComment())
                                                                                                                        .map(comment -> comment
                                                                                                                                        .contains(filter))
                                                                                                                        .orElse(false))
                                                                                                        .orElse(true))
                                                                                        .collect(Collectors.toList());

                                                                        if (matched.isEmpty()) {
                                                                                GhidraMcpError error = GhidraMcpError
                                                                                                .resourceNotFound()
                                                                                                .errorCode(GhidraMcpError.ErrorCode.BOOKMARK_NOT_FOUND)
                                                                                                .message(
                                                                                                                "No bookmarks matched the specified criteria at address: "
                                                                                                                                + addressStr)
                                                                                                .context(new GhidraMcpError.ErrorContext(
                                                                                                                annotation.mcpName(),
                                                                                                                "bookmark filtering",
                                                                                                                args,
                                                                                                                Map.of(
                                                                                                                                ARG_ADDRESS,
                                                                                                                                addressStr,
                                                                                                                                ARG_BOOKMARK_TYPE,
                                                                                                                                bookmarkTypeOpt.orElse(
                                                                                                                                                "any"),
                                                                                                                                ARG_BOOKMARK_CATEGORY,
                                                                                                                                bookmarkCategoryOpt
                                                                                                                                                .orElse("any"),
                                                                                                                                ARG_COMMENT_CONTAINS,
                                                                                                                                commentContainsOpt
                                                                                                                                                .orElse("none")),
                                                                                                                Map.of("bookmarksInspected",
                                                                                                                                bookmarks.length)))
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

                                                                        return OperationResult.success(
                                                                                        annotation.mcpName(),
                                                                                        address.toString(),
                                                                                        "Deleted " + matched.size()
                                                                                                        + " bookmark(s).")
                                                                                        .setMetadata(Map.of(
                                                                                                        "deletedCount",
                                                                                                        matched.size(),
                                                                                                        ARG_BOOKMARK_TYPE,
                                                                                                        bookmarkTypeOpt.orElse(
                                                                                                                        "any"),
                                                                                                        ARG_BOOKMARK_CATEGORY,
                                                                                                        bookmarkCategoryOpt
                                                                                                                        .orElse("any")));
                                                                } catch (Exception e) {
                                                                        GhidraMcpError error = GhidraMcpError
                                                                                        .execution()
                                                                                        .errorCode(GhidraMcpError.ErrorCode.TRANSACTION_FAILED)
                                                                                        .message("Failed to delete bookmark: "
                                                                                                        + e.getMessage())
                                                                                        .context(new GhidraMcpError.ErrorContext(
                                                                                                        annotation.mcpName(),
                                                                                                        "bookmark deletion",
                                                                                                        args,
                                                                                                        Map.of("address",
                                                                                                                        addressStr),
                                                                                                        Map.of("exceptionType",
                                                                                                                        e.getClass().getSimpleName())))
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
                } catch (GhidraMcpException e) {
                        return Mono.error(e);
                }
        }
}
