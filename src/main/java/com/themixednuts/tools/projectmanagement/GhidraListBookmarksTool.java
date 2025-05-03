package com.themixednuts.tools.projectmanagement;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.themixednuts.annotation.GhidraMcpTool;
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
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import reactor.core.publisher.Mono;

@GhidraMcpTool(key = "List Bookmarks", mcpName = "list_bookmarks", mcpDescription = "Lists bookmarks in the specified program", category = ToolCategory.PROJECT_MANAGEMENT, description = "Lists bookmarks in the specified program.")
public class GhidraListBookmarksTool implements IGhidraMcpSpecification {

	record BookmarkInfo(
			@JsonProperty("address") String address,
			@JsonProperty("type") String type,
			@JsonProperty("category") String category,
			@JsonProperty("comment") String comment) {
	}

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
	public Mono<CallToolResult> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool)
				.flatMap(program -> {
					String cursorStr = getOptionalStringArgument(args, ARG_CURSOR).orElse(null);
					Address cursorAddr = null;
					if (cursorStr != null) {
						cursorAddr = program.getAddressFactory().getAddress(cursorStr);
						if (cursorAddr == null) {
							return createErrorResult("Invalid cursor format (could not parse address): " + cursorStr);
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
					return createSuccessResult(paginatedResult);
				})
				.onErrorResume(e -> createErrorResult(e));
	}

	@Override
	public AsyncToolSpecification specification(PluginTool tool) {
		GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
		if (annotation == null) {
			Msg.error(this, "Missing @GhidraMcpTool annotation on " + this.getClass().getSimpleName());
			return null;
		}

		JsonSchema schemaObject = schema();
		Optional<String> schemaStringOpt = parseSchema(schemaObject);
		if (schemaStringOpt.isEmpty()) {
			Msg.error(this, "Failed to generate schema for tool '" + annotation.mcpName() + "'. Tool will be disabled.");
			return null;
		}
		String schemaJson = schemaStringOpt.get();

		return new AsyncToolSpecification(
				new Tool(annotation.mcpName(), annotation.mcpDescription(), schemaJson),
				(ex, args) -> execute(ex, args, tool));
	}

}