package com.themixednuts.tools.projectmanagement;

import java.util.Map;
import java.util.Optional;

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
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Remove Bookmark", mcpName = "remove_bookmark", mcpDescription = "Removes a bookmark at the specified address.", category = ToolCategory.PROJECT_MANAGEMENT, description = "Removes a specific bookmark at the given address.")
public class GhidraRemoveBookmarkTool implements IGhidraMcpSpecification {

	private static final String ARG_BOOKMARK_TYPE = "bookmarkType";
	private static final String ARG_BOOKMARK_CATEGORY = "bookmarkCategory";
	private static final String ARG_COMMENT_CONTAINS = "commentContains";

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
	public Mono<CallToolResult> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool)
				.flatMap(program -> {
					return executeInTransaction(program, "Remove Bookmark", () -> {
						final String finalAddressStr = getRequiredStringArgument(args, ARG_ADDRESS);
						Optional<String> optType = getOptionalStringArgument(args, ARG_BOOKMARK_TYPE);
						Optional<String> optCategory = getOptionalStringArgument(args, ARG_BOOKMARK_CATEGORY);
						Optional<String> optCommentContains = getOptionalStringArgument(args, ARG_COMMENT_CONTAINS);

						Address address = program.getAddressFactory().getAddress(finalAddressStr);
						if (address == null) {
							return createErrorResult("Invalid address format: " + finalAddressStr);
						}

						BookmarkManager bookmarkManager = program.getBookmarkManager();
						Bookmark[] bookmarksAtAddr = bookmarkManager.getBookmarks(address);

						if (bookmarksAtAddr.length == 0) {
							return createErrorResult("No bookmark found at address: " + finalAddressStr);
						}

						Bookmark bookmarkToRemove = null;
						if (bookmarksAtAddr.length == 1 && optType.isEmpty() && optCategory.isEmpty()
								&& optCommentContains.isEmpty()) {
							bookmarkToRemove = bookmarksAtAddr[0];
						} else {
							for (Bookmark bm : bookmarksAtAddr) {
								boolean typeMatch = optType.map(t -> t.equals(bm.getTypeString())).orElse(true);
								boolean categoryMatch = optCategory.map(c -> c.equals(bm.getCategory())).orElse(true);
								boolean commentMatch = optCommentContains
										.map(c -> bm.getComment() != null && bm.getComment().contains(c)).orElse(true);

								if (typeMatch && categoryMatch && commentMatch) {
									if (bookmarkToRemove != null) {
										return createErrorResult("Multiple bookmarks match the specified criteria at " + finalAddressStr
												+ ". Please provide more specific filters (type, category, commentContains).");
									}
									bookmarkToRemove = bm;
								}
							}
						}

						if (bookmarkToRemove == null) {
							return createErrorResult(
									"No bookmark found matching the specified criteria at address: " + finalAddressStr);
						}

						bookmarkManager.removeBookmark(bookmarkToRemove);
						return createSuccessResult("Bookmark removed successfully from " + finalAddressStr);
					});
				}).onErrorResume(e -> createErrorResult(e));
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