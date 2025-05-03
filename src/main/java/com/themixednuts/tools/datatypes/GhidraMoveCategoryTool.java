package com.themixednuts.tools.datatypes;

import java.util.Map;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.utils.JsonSchemaBuilder;
import com.themixednuts.utils.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.program.model.data.Category;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataTypeManager;
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import reactor.core.publisher.Mono;
import ghidra.framework.plugintool.PluginTool;

@GhidraMcpTool(key = "Move Category", category = "Data Types", description = "Enable the MCP tool to move a data type category.", mcpName = "move_category", mcpDescription = "Moves an existing data type category (and its contents) to a new parent category.")
public class GhidraMoveCategoryTool implements IGhidraMcpSpecification {

	@Override
	public AsyncToolSpecification specification(PluginTool tool) {
		GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
		if (annotation == null) {
			Msg.error(this, "Missing @GhidraMcpTool annotation on " + this.getClass().getSimpleName());
			return null;
		}
		String schema = parseSchema(schema()).orElse(null);
		if (schema == null) {
			return null;
		}

		return new AsyncToolSpecification(
				new Tool(annotation.mcpName(), annotation.mcpDescription(), schema),
				(ex, args) -> execute(ex, args, tool));
	}

	@Override
	public ObjectNode schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();

		schemaRoot.property("fileName",
				JsonSchemaBuilder.string(mapper)
						.description("The file name of the Ghidra tool window to target"));

		schemaRoot.property("sourceCategoryPath",
				JsonSchemaBuilder.string(mapper)
						.description(
								"The full path of the category to move (e.g., /MyTypes/OldLocation/MyCategory). Cannot be the root '/'.")
						.pattern("^/.+$"));

		schemaRoot.property("destinationParentPath",
				JsonSchemaBuilder.string(mapper)
						.description(
								"The full path of the parent category where the source category should be moved (e.g., /MyTypes/NewLocation or / for root).")
						.pattern("^/.*$"));

		schemaRoot.requiredProperty("fileName")
				.requiredProperty("sourceCategoryPath")
				.requiredProperty("destinationParentPath");

		return schemaRoot.build();
	}

	@Override
	public Mono<CallToolResult> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).flatMap(program -> {
			String sourceCategoryPathString = getRequiredStringArgument(args, "sourceCategoryPath");
			String destinationParentPathString = getRequiredStringArgument(args, "destinationParentPath");

			CategoryPath sourceCategoryPath;
			sourceCategoryPath = new CategoryPath(sourceCategoryPathString);
			if (sourceCategoryPath.isRoot()) {
				return createErrorResult("Cannot move the root category.");
			}

			CategoryPath destinationParentPath;
			destinationParentPath = new CategoryPath(destinationParentPathString);

			DataTypeManager dtm = program.getDataTypeManager();

			final Category sourceCategory = dtm.getCategory(sourceCategoryPath);
			if (sourceCategory == null) {
				return createErrorResult("Source category not found: " + sourceCategoryPathString);
			}

			final Category destinationParentCategory = dtm.getCategory(destinationParentPath);
			if (destinationParentCategory == null) {
				return createErrorResult("Destination parent category not found: " + destinationParentPathString);
			}

			if (destinationParentPath.isAncestorOrSelf(sourceCategoryPath)) {
				return createErrorResult("Cannot move a category into itself or one of its descendants.");
			}

			final String finalSourceCategoryPathName = sourceCategoryPath.getName();

			return executeInTransaction(program, "MCP - Move Category", () -> {
				destinationParentCategory.moveCategory(sourceCategory, null);
				String newPath = destinationParentCategory.getCategoryPath().getPath() + finalSourceCategoryPathName;
				return createSuccessResult("Category moved successfully to: " + newPath);
			});

		}).onErrorResume(e -> {
			return createErrorResult(e);
		});
	}
}