package com.themixednuts.tools.datatypes;

import java.util.Map;
import java.util.Optional;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.Category;
import ghidra.program.model.data.DataTypeManager;
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import reactor.core.publisher.Mono;

@GhidraMcpTool(key = "Rename Category", category = "Data Types", description = "Rename an existing data type category.", mcpName = "rename_category", mcpDescription = "Renames an existing data type category.")
public class GhidraRenameCategoryTool implements IGhidraMcpSpecification {

	@Override
	public AsyncToolSpecification specification(PluginTool tool) {
		GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
		if (annotation == null) {
			Msg.error(this, "Missing @GhidraMcpTool annotation on " + this.getClass().getSimpleName());
			return null;
		}

		JsonSchema schemaObject = schema();
		Optional<String> schemaStringOpt = schemaObject.toJsonString(mapper);
		if (schemaStringOpt.isEmpty()) {
			Msg.error(this, "Failed to serialize schema for tool '" + annotation.mcpName() + "'. Tool will be disabled.");
			return null;
		}
		String schemaJson = schemaStringOpt.get();

		return new AsyncToolSpecification(
				new Tool(annotation.mcpName(), annotation.mcpDescription(), schemaJson),
				(ex, args) -> execute(ex, args, tool));
	}

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property("fileName",
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file."));
		schemaRoot.property("originalCategoryPath",
				JsonSchemaBuilder.string(mapper)
						.description("The current full path of the category to rename (e.g., '/OldCategory/SubCategory')."));
		schemaRoot.property("newCategoryName",
				JsonSchemaBuilder.string(mapper)
						.description("The desired new name for the category (just the final part of the path)."));

		schemaRoot.requiredProperty("fileName")
				.requiredProperty("originalCategoryPath")
				.requiredProperty("newCategoryName");

		return schemaRoot.build();
	}

	@Override
	public Mono<CallToolResult> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).flatMap(program -> {
			String originalPathString = getRequiredStringArgument(args, "originalCategoryPath");
			String newName = getRequiredStringArgument(args, "newCategoryName");
			DataTypeManager dtm = program.getDataTypeManager();
			Category category = dtm.getCategory(new ghidra.program.model.data.CategoryPath(originalPathString));

			if (category == null) {
				return createErrorResult("Category not found at path: " + originalPathString);
			}

			return executeInTransaction(program, "MCP - Rename Category", () -> {
				category.setName(newName);
				String newPath = category.getCategoryPath().getPath();
				return createSuccessResult("Category renamed successfully to: " + newPath);
			});

		}).onErrorResume(e -> createErrorResult(e));
	}
}