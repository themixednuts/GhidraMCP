package com.themixednuts.tools.projectmanagement;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.tools.ToolCategory;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Delete Bookmark", category = ToolCategory.PROJECT_MANAGEMENT, description = "Removes a bookmark at the specified address, optionally filtering by properties.", mcpName = "delete_bookmark", mcpDescription = "Removes a bookmark at the specified address.")
public class GhidraDeleteBookmarkTool implements IGhidraMcpSpecification {

	private static final String ARG_BOOKMARK_TYPE = "bookmarkType";
	private static final String ARG_BOOKMARK_CATEGORY = "bookmarkCategory";
	private static final String ARG_COMMENT_CONTAINS = "commentContains";

	// Define a nested record for type-safe context passing
	private static record DeleteBookmarkContext(
			Address address,
			String addressStr,
			Optional<String> optType,
			Optional<String> optCategory,
			Optional<String> optCommentContains,
			Program program // Also pass program to flatMap
	) {
	}

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper).description("The name of the program file."));
		schemaRoot.property(ARG_ADDRESS,
				JsonSchemaBuilder.string(mapper)
						.description("The exact address of the bookmark to remove (e.g., '0x1004010')."));
		schemaRoot.property(ARG_BOOKMARK_TYPE,
				JsonSchemaBuilder.string(mapper)
						.description(
								"Optional: If multiple bookmarks exist at the address, only remove the one with this exact type."));
		schemaRoot.property(ARG_BOOKMARK_CATEGORY,
				JsonSchemaBuilder.string(mapper)
						.description(
								"Optional: If multiple bookmarks exist at the address, only remove the one with this exact category."));
		schemaRoot.property(ARG_COMMENT_CONTAINS,
				JsonSchemaBuilder.string(mapper)
						.description(
								"Optional: If multiple bookmarks exist at the address, only remove the one whose comment contains this text."));

		schemaRoot.requiredProperty(ARG_FILE_NAME);
		schemaRoot.requiredProperty(ARG_ADDRESS);

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool)
				.map(program -> {
					String addressStr = getRequiredStringArgument(args, ARG_ADDRESS);
					Optional<String> optType = getOptionalStringArgument(args, ARG_BOOKMARK_TYPE);
					Optional<String> optCategory = getOptionalStringArgument(args, ARG_BOOKMARK_CATEGORY);
					Optional<String> optCommentContains = getOptionalStringArgument(args, ARG_COMMENT_CONTAINS);
					Address addr;

					try {
						addr = program.getAddressFactory().getAddress(addressStr);
						if (addr == null) {
							throw new IllegalArgumentException("Invalid address format: " + addressStr);
						}
					} catch (Exception e) {
						throw new IllegalArgumentException("Invalid address format: " + addressStr, e);
					}

					// Return the type-safe context object
					return new DeleteBookmarkContext(addr, addressStr, optType, optCategory, optCommentContains, program);
				})
				.flatMap(context -> { // context is now DeleteBookmarkContext
					// Access fields directly from the context record
					return executeInTransaction(context.program(), "MCP - Remove Bookmark(s) at " + context.addressStr(), () -> {
						BookmarkManager bookmarkManager = context.program().getBookmarkManager();
						Bookmark[] bookmarksAtAddr = bookmarkManager.getBookmarks(context.address());

						if (bookmarksAtAddr.length == 0) {
							throw new IllegalArgumentException("No bookmark found at address: " + context.addressStr());
						}

						List<Bookmark> bookmarksToRemove = Arrays.stream(bookmarksAtAddr).filter(bm -> {
							// Use context fields directly
							boolean typeMatch = context.optType().map(t -> t.equals(bm.getTypeString())).orElse(true);
							boolean categoryMatch = context.optCategory().map(c -> c.equals(bm.getCategory())).orElse(true);
							boolean commentMatch = context.optCommentContains()
									.map(c -> bm.getComment() != null && bm.getComment().contains(c))
									.orElse(true);
							return typeMatch && categoryMatch && commentMatch;
						}).collect(Collectors.toList());

						if (bookmarksToRemove.isEmpty()) {
							throw new IllegalArgumentException(
									"No bookmark found matching the specified criteria at address: " + context.addressStr());
						}

						int initialCount = bookmarksToRemove.size();
						for (Bookmark bm : bookmarksToRemove) {
							bookmarkManager.removeBookmark(bm);
						}
						return "Attempted to remove " + initialCount + (initialCount == 1 ? " bookmark" : " bookmarks") + " from "
								+ context.addressStr();
					});
				});
	}
}