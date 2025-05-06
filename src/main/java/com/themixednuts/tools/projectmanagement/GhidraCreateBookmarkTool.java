package com.themixednuts.tools.projectmanagement;

import java.util.HashMap;
import java.util.Map;

import com.themixednuts.annotation.GhidraMcpTool;
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

@GhidraMcpTool(name = "Create Bookmark", category = ToolCategory.PROJECT_MANAGEMENT, description = "Adds a bookmark with a specified type, category, and comment at a given address.", mcpName = "create_bookmark", mcpDescription = "Adds a bookmark at the specified address.")
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
							throw new IllegalArgumentException("Invalid address format: " + addressStr);
						}
					} catch (Exception e) {
						throw new IllegalArgumentException("Invalid address format: " + addressStr, e);
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
						BookmarkManager bookmarkManager = program.getBookmarkManager();
						bookmarkManager.setBookmark(addr, type, category, comment);
						return "Bookmark added successfully at " + addr.toString();
					});
				});
	}
}