package com.themixednuts.tools.datatypes;

import java.util.Map;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.utils.JsonSchemaBuilder;
import com.themixednuts.utils.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataTypeManager;
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import reactor.core.publisher.Mono;
import ghidra.framework.plugintool.PluginTool;

@GhidraMcpTool(key = "Create Category", category = "Data Types", description = "Enable the MCP tool to create a new data type category.", mcpName = "create_category", mcpDescription = "Creates a new data type category (folder) at the specified path if it doesn't already exist.")
public class GhidraCreateCategoryTool implements IGhidraMcpSpecification {

	@Override
	public AsyncToolSpecification specification(PluginTool tool) {
		GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
		if (annotation == null) {
			Msg.error(this, "Missing @GhidraMcpTool annotation on " + this.getClass().getSimpleName());
			return null;
		}
		String schema = parseSchema(schema()).orElse(null);
		if (schema == null) {
			Msg.error(this, "Failed to generate schema for tool '" + annotation.mcpName() + "'. Tool will be disabled.");
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

		schemaRoot.property("categoryPath",
				JsonSchemaBuilder.string(mapper)
						.description(
								"The full path for the new category (e.g., /MyTypes/SubFolder). Must start with '/'.")
						.pattern("^/.+$")); // Basic check: must start with / and not be root

		schemaRoot.requiredProperty("fileName")
				.requiredProperty("categoryPath");

		return schemaRoot.build();
	}

	@Override
	public Mono<CallToolResult> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).flatMap(program -> {
			// Setup: Parse args, validate path
			// Argument parsing errors caught by onErrorResume
			String categoryPathString = getRequiredStringArgument(args, "categoryPath");

			final CategoryPath categoryPath; // Final for lambda
			try {
				categoryPath = new CategoryPath(categoryPathString);
				if (categoryPath.isRoot()) { // createCategory cannot create root
					return createErrorResult("Cannot explicitly create the root category '/'.");
				}
			} catch (IllegalArgumentException e) {
				return createErrorResult("Invalid category path format: " + categoryPathString);
			}

			final DataTypeManager dtm = program.getDataTypeManager(); // Final for lambda

			// --- Execute modification in transaction ---
			final String finalCategoryPathString = categoryPathString; // Capture for message
			return executeInTransaction(program, "MCP - Create Category", () -> {
				// Inner Callable logic (just the modification):
				// createCategory handles existence check internally and returns existing if
				// found.
				dtm.createCategory(categoryPath);
				// Assume success if no exception was thrown.
				return createSuccessResult(
						"Category '" + finalCategoryPathString + "' ensured successfully (created if not existing).");
			}); // End of Callable for executeInTransaction

		}).onErrorResume(e -> {
			// Catch errors from getProgram, setup (incl. arg parsing), or transaction
			// execution
			// Logging handled by createErrorResult
			return createErrorResult(e);
		});
	}
}