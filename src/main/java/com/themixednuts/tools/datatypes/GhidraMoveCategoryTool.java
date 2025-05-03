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
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataTypeManager;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import reactor.core.publisher.Mono;

@GhidraMcpTool(key = "Move Category", category = "Data Types", description = "Move an existing data type category to a different parent category.", mcpName = "move_category", mcpDescription = "Moves an existing data type category (folder) to a new parent category.")
public class GhidraMoveCategoryTool implements IGhidraMcpSpecification {

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
		schemaRoot.property("categoryToMovePath",
				JsonSchemaBuilder.string(mapper)
						.description("The current full path of the category to move (e.g., '/SourceCategory/MyCategory')."));
		schemaRoot.property("newParentCategoryPath",
				JsonSchemaBuilder.string(mapper)
						.description(
								"The full path of the destination parent category (e.g., '/DestinationCategory'). Use '/' for the root."));

		schemaRoot.requiredProperty("fileName")
				.requiredProperty("categoryToMovePath")
				.requiredProperty("newParentCategoryPath");

		return schemaRoot.build();
	}

	@Override
	public Mono<CallToolResult> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).flatMap(program -> {
			String categoryToMovePathString = getRequiredStringArgument(args, "categoryToMovePath");
			String newParentPathString = getRequiredStringArgument(args, "newParentCategoryPath");

			final CategoryPath categoryToMovePath = new CategoryPath(categoryToMovePathString);
			final CategoryPath newParentPath = new CategoryPath(newParentPathString);

			if (categoryToMovePath.isRoot()) {
				return createErrorResult("Cannot move the root category.");
			}

			DataTypeManager dtm = program.getDataTypeManager();
			Category categoryToMove = dtm.getCategory(categoryToMovePath);
			if (categoryToMove == null) {
				return createErrorResult("Category to move not found: " + categoryToMovePathString);
			}

			Category newParentCategory = dtm.getCategory(newParentPath);
			if (newParentCategory == null) {
				return createErrorResult("New parent category not found: " + newParentPathString);
			}

			return executeInTransaction(program, "MCP - Move Category", () -> {
				try {
					newParentCategory.moveCategory(categoryToMove, null);
					String finalPath = categoryToMove.getCategoryPath().getPath();
					return createSuccessResult("Category '" + categoryToMovePathString
							+ "' moved successfully to: " + finalPath);
				} catch (DuplicateNameException e) {
					return createErrorResult("Failed to move category: A category with the same name already exists in '"
							+ newParentPathString + "'. Error: " + e.getMessage());
				}
			});

		}).onErrorResume(e -> {
			return createErrorResult(e);
		});
	}
}