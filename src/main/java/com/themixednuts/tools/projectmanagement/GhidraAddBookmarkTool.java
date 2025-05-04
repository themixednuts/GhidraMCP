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
import ghidra.program.model.listing.BookmarkManager;
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Add Bookmark", mcpName = "add_bookmark", mcpDescription = "Adds a bookmark at the specified address.", category = ToolCategory.PROJECT_MANAGEMENT, description = "Adds a bookmark at the specified address in the program.")
public class GhidraAddBookmarkTool implements IGhidraMcpSpecification {

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
	public Mono<CallToolResult> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool) // Handles fileName validation
				.flatMap(program -> {
					return executeInTransaction(program, "Add Bookmark", () -> {
						final String finalAddressStr = getRequiredStringArgument(args, ARG_ADDRESS);
						final String finalBookmarkType = getRequiredStringArgument(args, ARG_BOOKMARK_TYPE);
						final String finalBookmarkCategory = getRequiredStringArgument(args, ARG_BOOKMARK_CATEGORY);
						final String finalComment = getRequiredStringArgument(args, ARG_COMMENT);

						Address address = program.getAddressFactory().getAddress(finalAddressStr);
						if (address == null) {
							return createErrorResult("Invalid address format: " + finalAddressStr);
						}

						BookmarkManager bookmarkManager = program.getBookmarkManager();
						bookmarkManager.setBookmark(address, finalBookmarkType, finalBookmarkCategory, finalComment);

						return createSuccessResult("Bookmark added successfully at " + finalAddressStr);
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