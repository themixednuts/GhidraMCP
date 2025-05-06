package com.themixednuts.tools.projectmanagement;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.tools.ToolCategory;
import com.themixednuts.utils.PaginatedResult;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;
import com.themixednuts.models.BookmarkInfo;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "List Bookmarks", mcpName = "list_bookmarks", mcpDescription = "Lists bookmarks in the specified program", category = ToolCategory.PROJECT_MANAGEMENT, description = "Lists bookmarks in the specified program.")
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
					String cursorStr = getOptionalStringArgument(args, ARG_CURSOR).orElse(null);
					Address cursorAddr = null;
					if (cursorStr != null) {
						cursorAddr = program.getAddressFactory().getAddress(cursorStr);
						if (cursorAddr == null) {
							throw new IllegalArgumentException("Invalid cursor format (could not parse address): " + cursorStr);
						}
					}
					final Address finalCursorAddr = cursorAddr;

					BookmarkManager bookmarkManager = program.getBookmarkManager();

					// Get all bookmarks into a list first
					List<Bookmark> allBookmarks = new ArrayList<>();
					Iterator<Bookmark> iter = bookmarkManager.getBookmarksIterator();
					while (iter.hasNext()) {
						allBookmarks.add(iter.next());
					}

					// Sort by address, filter by cursor, limit page size + 1
					List<Bookmark> limitedBookmarks = allBookmarks.stream()
							.sorted(Comparator.comparing(Bookmark::getAddress))
							.dropWhile(bookmark -> finalCursorAddr != null && bookmark.getAddress().compareTo(finalCursorAddr) <= 0)
							.limit(DEFAULT_PAGE_LIMIT + 1)
							.collect(Collectors.toList());

					boolean hasMore = limitedBookmarks.size() > DEFAULT_PAGE_LIMIT;
					List<Bookmark> pageBookmarks = limitedBookmarks.subList(0,
							Math.min(limitedBookmarks.size(), DEFAULT_PAGE_LIMIT));

					List<BookmarkInfo> pageResults = pageBookmarks.stream()
							.map(bm -> new BookmarkInfo(
									bm.getAddress().toString(),
									bm.getTypeString(),
									bm.getCategory(),
									bm.getComment()))
							.collect(Collectors.toList());

					String nextCursor = null;
					if (hasMore && !pageBookmarks.isEmpty()) {
						nextCursor = pageBookmarks.get(pageBookmarks.size() - 1).getAddress().toString();
					}

					PaginatedResult<BookmarkInfo> paginatedResult = new PaginatedResult<>(pageResults, nextCursor);
					return paginatedResult;
				});
	}

}