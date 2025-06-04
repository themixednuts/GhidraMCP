package com.themixednuts.tools.projectmanagement;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

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
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Create Bookmark", category = ToolCategory.PROJECT_MANAGEMENT, description = "Adds a bookmark with a specified type, category, and comment at a given address.", mcpName = "create_bookmark", mcpDescription = "Create a bookmark at a specific address in a Ghidra program. Bookmarks help organize and annotate important locations during analysis.")
public class GhidraCreateBookmarkTool implements IGhidraMcpSpecification {

	// Define specific argument names for clarity
	private static final String ARG_BOOKMARK_TYPE = "bookmarkType";
	private static final String ARG_BOOKMARK_CATEGORY = "bookmarkCategory";

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper).description("The name of the program file."));
		schemaRoot.property(ARG_ADDRESS,
				JsonSchemaBuilder.string(mapper)
						.description("The address where the bookmark should be added (e.g., '0x1004010')."));
		schemaRoot.property(ARG_BOOKMARK_TYPE,
				JsonSchemaBuilder.string(mapper).description("The type of the bookmark (e.g., 'Note', 'Analysis', 'Error')."));
		schemaRoot.property(ARG_BOOKMARK_CATEGORY,
				JsonSchemaBuilder.string(mapper)
						.description("The category for the bookmark (e.g., 'Default', 'My Analysis')."));
		schemaRoot.property(ARG_COMMENT,
				JsonSchemaBuilder.string(mapper).description("The comment text for the bookmark."));

		schemaRoot.requiredProperty(ARG_FILE_NAME);
		schemaRoot.requiredProperty(ARG_ADDRESS);
		schemaRoot.requiredProperty(ARG_BOOKMARK_TYPE);
		schemaRoot.requiredProperty(ARG_BOOKMARK_CATEGORY);
		schemaRoot.requiredProperty(ARG_COMMENT);

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool)
				.map(program -> {
					String addressStr = getRequiredStringArgument(args, ARG_ADDRESS);
					String bookmarkType = getRequiredStringArgument(args, ARG_BOOKMARK_TYPE);
					String bookmarkCategory = getRequiredStringArgument(args, ARG_BOOKMARK_CATEGORY);
					String comment = getRequiredStringArgument(args, ARG_COMMENT);
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
															"address", addressStr,
															"bookmarkType", bookmarkType,
															"bookmarkCategory", bookmarkCategory),
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
							throw e;
						}
						throw new GhidraMcpException(
								GhidraMcpError.execution()
										.errorCode(GhidraMcpError.ErrorCode.ADDRESS_PARSE_FAILED)
										.message("Failed to parse address: " + addressStr + " - " + e.getMessage())
										.context(new GhidraMcpError.ErrorContext(
												"parse_address",
												getMcpName(),
												Map.of("fileName", getRequiredStringArgument(args, ARG_FILE_NAME),
														"address", addressStr,
														"bookmarkType", bookmarkType,
														"bookmarkCategory", bookmarkCategory),
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
										.build());
					}

					Map<String, Object> contextMap = new HashMap<>();
					contextMap.put("address", addr);
					contextMap.put("type", bookmarkType);
					contextMap.put("category", bookmarkCategory);
					contextMap.put("comment", comment);
					return Map.entry(program, contextMap);

				})
				.flatMap(contextEntry -> {
					Program program = contextEntry.getKey();
					Map<String, Object> context = contextEntry.getValue();
					Address addr = (Address) context.get("address");
					String type = (String) context.get("type");
					String category = (String) context.get("category");
					String comment = (String) context.get("comment");

					return executeInTransaction(program, "MCP - Add Bookmark at " + addr.toString(), () -> {
						try {
							BookmarkManager bookmarkManager = program.getBookmarkManager();
							bookmarkManager.setBookmark(addr, type, category, comment);
							return "Bookmark added successfully at " + addr.toString();
						} catch (Exception e) {
							throw new GhidraMcpException(
									GhidraMcpError.execution()
											.errorCode(GhidraMcpError.ErrorCode.TRANSACTION_FAILED)
											.message("Failed to create bookmark: " + e.getMessage())
											.context(new GhidraMcpError.ErrorContext(
													"create_bookmark",
													getMcpName(),
													Map.of("fileName", program.getName(),
															"address", addr.toString(),
															"bookmarkType", type,
															"bookmarkCategory", category,
															"comment", comment),
													Map.of("operation", "set_bookmark"),
													Map.of("exception_type", e.getClass().getSimpleName(),
															"exception_message", e.getMessage())))
											.suggestions(List.of(
													new GhidraMcpError.ErrorSuggestion(
															GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
															"Verify bookmark parameters are valid",
															"Check bookmark type and category formats",
															List.of("Type: 'Note', 'Analysis', 'Error'", "Category: 'Default', 'Analysis'"),
															null)))
											.build());
						}
					});
				});
	}
}