package com.themixednuts.tools.projectmanagement;

import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.tools.ToolCategory;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Delete Bookmark", category = ToolCategory.PROJECT_MANAGEMENT, description = "Removes a bookmark from the program at a specific address.", mcpName = "delete_bookmark", mcpDescription = "Delete a bookmark from a Ghidra program at a specific address. Supports optional filtering by bookmark type, category, or comment content.")
public class GhidraDeleteBookmarkTool implements IGhidraMcpSpecification {

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
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool)
				.flatMap(program -> {
					String addressStr = getRequiredStringArgument(args, ARG_ADDRESS);
					Optional<String> typeFilter = getOptionalStringArgument(args, ARG_BOOKMARK_TYPE);
					Optional<String> categoryFilter = getOptionalStringArgument(args, ARG_BOOKMARK_CATEGORY);
					Optional<String> commentFilter = getOptionalStringArgument(args, ARG_COMMENT_CONTAINS);

					Address addr;
					try {
						addr = program.getAddressFactory().getAddress(addressStr);
						if (addr == null) {
							throw new GhidraMcpException(
									GhidraMcpError.execution()
											.errorCode(GhidraMcpError.ErrorCode.ADDRESS_PARSE_FAILED)
											.message("Invalid address format: " + addressStr)
											.context(new GhidraMcpError.ErrorContext(
													"parse_address",
													getMcpName(),
													Map.of("fileName", getRequiredStringArgument(args, ARG_FILE_NAME),
															"address", addressStr),
													Map.of("input_address", addressStr),
													Map.of("validation_failed", "Address could not be parsed by Ghidra's AddressFactory")))
											.suggestions(List.of(
													new GhidraMcpError.ErrorSuggestion(
															GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
															"Use a valid address format for the current program",
															"Check address format and program's memory layout",
															List.of("0x401000", "0x00401000", "401000", "ram:00401000"),
															null)))
											.build());
						}
					} catch (Exception e) {
						if (e instanceof GhidraMcpException) {
							return Mono.error(e);
						}
						return Mono.error(new GhidraMcpException(
								GhidraMcpError.execution()
										.errorCode(GhidraMcpError.ErrorCode.ADDRESS_PARSE_FAILED)
										.message("Failed to parse address: " + addressStr + " - " + e.getMessage())
										.context(new GhidraMcpError.ErrorContext(
												"parse_address",
												getMcpName(),
												Map.of("fileName", getRequiredStringArgument(args, ARG_FILE_NAME),
														"address", addressStr),
												Map.of("input_address", addressStr),
												Map.of("exception_type", e.getClass().getSimpleName(),
														"exception_message", e.getMessage())))
										.suggestions(List.of(
												new GhidraMcpError.ErrorSuggestion(
														GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
														"Verify address format matches program's address space",
														"Use valid hexadecimal address format",
														List.of("0x401000", "0x00401000", "401000"),
														null)))
										.build()));
					}

					return executeInTransaction(program, "MCP - Delete Bookmark at " + addressStr, () -> {
						try {
							BookmarkManager bookmarkManager = program.getBookmarkManager();
							Bookmark[] bookmarks = bookmarkManager.getBookmarks(addr);

							if (bookmarks.length == 0) {
								throw new GhidraMcpException(
										GhidraMcpError.resourceNotFound()
												.errorCode(GhidraMcpError.ErrorCode.BOOKMARK_NOT_FOUND)
												.message("No bookmarks found at address: " + addressStr)
												.context(new GhidraMcpError.ErrorContext(
														"find_bookmark",
														getMcpName(),
														Map.of("fileName", program.getName(),
																"address", addressStr),
														Map.of("target_address", addr.toString()),
														Map.of("bookmark_count", 0)))
												.suggestions(List.of(
														new GhidraMcpError.ErrorSuggestion(
																GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
																"Verify that bookmarks exist at the specified address",
																"List existing bookmarks to find available addresses",
																null,
																List.of(getMcpName(GhidraListBookmarksTool.class)))))
												.build());
							}

							// Apply filters to find the right bookmark(s) to delete
							Iterator<Bookmark> iterator = java.util.Arrays.asList(bookmarks).iterator();
							boolean found = false;

							while (iterator.hasNext()) {
								Bookmark bookmark = iterator.next();
								boolean matches = true;

								if (typeFilter.isPresent() && !typeFilter.get().equals(bookmark.getTypeString())) {
									matches = false;
								}
								if (categoryFilter.isPresent() && !categoryFilter.get().equals(bookmark.getCategory())) {
									matches = false;
								}
								if (commentFilter.isPresent() && !bookmark.getComment().contains(commentFilter.get())) {
									matches = false;
								}

								if (matches) {
									bookmarkManager.removeBookmark(bookmark);
									found = true;
								}
							}

							if (!found) {
								throw new GhidraMcpException(
										GhidraMcpError.resourceNotFound()
												.errorCode(GhidraMcpError.ErrorCode.BOOKMARK_NOT_FOUND)
												.message("No bookmarks found at address " + addressStr + " matching the specified criteria")
												.context(new GhidraMcpError.ErrorContext(
														"filter_bookmarks",
														getMcpName(),
														Map.of("fileName", program.getName(),
																"address", addressStr,
																"typeFilter", typeFilter.orElse("none"),
																"categoryFilter", categoryFilter.orElse("none"),
																"commentFilter", commentFilter.orElse("none")),
														Map.of("total_bookmarks_at_address", bookmarks.length),
														Map.of("filtering_applied",
																typeFilter.isPresent() || categoryFilter.isPresent() || commentFilter.isPresent())))
												.suggestions(List.of(
														new GhidraMcpError.ErrorSuggestion(
																GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
																"Check available bookmarks at this address and adjust filters",
																"List bookmarks to see available types, categories, and comments",
																null,
																List.of(getMcpName(GhidraListBookmarksTool.class)))))
												.build());
							}

							return "Bookmark(s) deleted successfully at " + addressStr;
						} catch (Exception e) {
							if (e instanceof GhidraMcpException) {
								throw e;
							}
							throw new GhidraMcpException(
									GhidraMcpError.execution()
											.errorCode(GhidraMcpError.ErrorCode.TRANSACTION_FAILED)
											.message("Failed to delete bookmark: " + e.getMessage())
											.context(new GhidraMcpError.ErrorContext(
													"delete_bookmark",
													getMcpName(),
													Map.of("fileName", program.getName(),
															"address", addressStr),
													Map.of("operation", "delete_bookmark"),
													Map.of("exception_type", e.getClass().getSimpleName(),
															"exception_message", e.getMessage())))
											.suggestions(List.of(
													new GhidraMcpError.ErrorSuggestion(
															GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
															"Verify program state and bookmark accessibility",
															"Ensure the program is writable and bookmark manager is available",
															null,
															null)))
											.build());
						}
					});
				});
	}
}