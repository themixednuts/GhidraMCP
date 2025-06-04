package com.themixednuts.tools.projectmanagement;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.BookmarkInfo;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.tools.ToolCategory;
import com.themixednuts.utils.PaginatedResult;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "List Bookmarks", category = ToolCategory.PROJECT_MANAGEMENT, description = "Lists all bookmarks in the program with their details.", mcpName = "list_bookmarks", mcpDescription = "List all bookmarks in a Ghidra program with their addresses, types, categories, and comments. Useful for reviewing analysis annotations.")
public class GhidraListBookmarksTool implements IGhidraMcpSpecification {

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file (e.g., 'example.exe')."));

		schemaRoot.requiredProperty(ARG_FILE_NAME);

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool)
				.map(program -> {
					try {
						BookmarkManager bookmarkManager = program.getBookmarkManager();
						Iterator<Bookmark> bookmarkIterator = bookmarkManager.getBookmarksIterator();

						List<BookmarkInfo> bookmarks = new ArrayList<>();
						while (bookmarkIterator.hasNext()) {
							Bookmark bookmark = bookmarkIterator.next();
							bookmarks.add(new BookmarkInfo(
									bookmark.getAddress().toString(),
									bookmark.getTypeString(),
									bookmark.getCategory(),
									bookmark.getComment()));
						}

						return bookmarks;
					} catch (Exception e) {
						throw new GhidraMcpException(
								GhidraMcpError.execution()
										.errorCode(GhidraMcpError.ErrorCode.UNEXPECTED_ERROR)
										.message("Failed to list bookmarks: " + e.getMessage())
										.context(new GhidraMcpError.ErrorContext(
												"list_bookmarks",
												getMcpName(),
												Map.of("fileName", getRequiredStringArgument(args, ARG_FILE_NAME)),
												Map.of("operation", "list_bookmarks"),
												Map.of("exception_type", e.getClass().getSimpleName(),
														"exception_message", e.getMessage())))
										.suggestions(List.of(
												new GhidraMcpError.ErrorSuggestion(
														GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
														"Ensure the program is properly opened and accessible",
														"Verify program state and bookmark manager accessibility",
														null,
														List.of(getMcpName(GhidraGetCurrentProgramInfoTool.class)))))
										.build());
					}
				});
	}

}