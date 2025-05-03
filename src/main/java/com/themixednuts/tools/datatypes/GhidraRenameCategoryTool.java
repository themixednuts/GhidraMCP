package com.themixednuts.tools.datatypes;

import java.util.Map;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.utils.JsonSchemaBuilder;
import com.themixednuts.utils.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.*;
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import reactor.core.publisher.Mono;

@GhidraMcpTool(key = "Rename Category", category = "Data Types", description = "Enable the MCP tool to rename a data type category.", mcpName = "rename_category", mcpDescription = "Renames an existing data type category (folder).")
public class GhidraRenameCategoryTool implements IGhidraMcpSpecification {

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

		schemaRoot.property("oldCategoryPath",
				JsonSchemaBuilder.string(mapper)
						.description("The current full path of the category to rename (e.g., /MyOldName).")
						.pattern("^/.+$"));

		schemaRoot.property("newName",
				JsonSchemaBuilder.string(mapper)
						.description("The desired new name for the category (not the full path)."));

		schemaRoot.requiredProperty("fileName")
				.requiredProperty("oldCategoryPath")
				.requiredProperty("newName");

		return schemaRoot.build();
	}

	@Override
	public Mono<CallToolResult> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).flatMap(program -> {
			String oldCategoryPathString = getRequiredStringArgument(args, "oldCategoryPath");
			final String newName = getRequiredStringArgument(args, "newName");

			final CategoryPath oldCategoryPath;
			oldCategoryPath = new CategoryPath(oldCategoryPathString);
			if (oldCategoryPath.isRoot()) {
				return createErrorResult("Cannot rename the root category.");
			}

			DataTypeManager dtm = program.getDataTypeManager();
			final Category category = dtm.getCategory(oldCategoryPath);

			if (category == null) {
				return createErrorResult("Category not found at path: " + oldCategoryPathString);
			}

			return executeInTransaction(program, "MCP - Rename Category", () -> {
				category.setName(newName);
				CategoryPath parentPath = oldCategoryPath.getParent();
				String newPath = (parentPath != null ? parentPath.getPath() : "/") + newName;
				return createSuccessResult("Category renamed successfully to: " + newPath);
			});

		}).onErrorResume(e -> {
			return createErrorResult(e);
		});
	}
}