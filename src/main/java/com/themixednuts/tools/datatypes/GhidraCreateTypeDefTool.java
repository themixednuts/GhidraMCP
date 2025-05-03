package com.themixednuts.tools.datatypes;

import java.util.Map;
import java.util.Optional;

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

@GhidraMcpTool(key = "Create Typedef", category = "Data Types", description = "Enable the MCP tool to create a new typedef.", mcpName = "create_typedef", mcpDescription = "Creates a new typedef data type, aliasing an existing data type.")
public class GhidraCreateTypeDefTool implements IGhidraMcpSpecification {

	public GhidraCreateTypeDefTool() {
	}

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

		schemaRoot.property("typedefPath",
				JsonSchemaBuilder.string(mapper)
						.description("The full path for the new typedef (e.g., /MyTypes/MyIntPtr)"));

		schemaRoot.property("underlyingTypePath",
				JsonSchemaBuilder.string(mapper)
						.description("Full path or name of the data type to alias (e.g., 'int *', '/MyStruct')."));

		schemaRoot.property("description",
				JsonSchemaBuilder.string(mapper)
						.description("Optional description for the typedef."));

		schemaRoot.requiredProperty("fileName")
				.requiredProperty("typedefPath")
				.requiredProperty("underlyingTypePath");

		return schemaRoot.build();
	}

	@Override
	public Mono<CallToolResult> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).flatMap(program -> {
			// Setup: Parse args, resolve path, check existence, resolve underlying type,
			// ensure category
			// Argument parsing errors caught by onErrorResume
			String typedefPathString = getRequiredStringArgument(args, "typedefPath");
			String underlyingTypePath = getRequiredStringArgument(args, "underlyingTypePath");
			final Optional<String> descriptionOpt = getOptionalStringArgument(args, "description"); // Final for lambda

			CategoryPath categoryPath; // Not final here
			final String typedefName; // Final for lambda
			try {
				CategoryPath fullPath = new CategoryPath(typedefPathString);
				typedefName = fullPath.getName();
				categoryPath = fullPath.getParent();
				if (categoryPath == null) {
					categoryPath = CategoryPath.ROOT;
				}
				if (typedefName.isBlank()) {
					return createErrorResult("Invalid typedef path: Name cannot be blank.");
				}
			} catch (IllegalArgumentException e) { // Includes InvalidNameException potential from CategoryPath
				return createErrorResult("Invalid typedef path format: " + typedefPathString);
			}

			final DataTypeManager dtm = program.getDataTypeManager(); // Final for lambda

			// Check if typedef path already exists
			if (dtm.getDataType(typedefPathString) != null) {
				return createErrorResult("Data type already exists at path: " + typedefPathString);
			}

			// Resolve Underlying Type
			final DataType underlyingDt = dtm.getDataType(underlyingTypePath); // Final for lambda
			if (underlyingDt == null) {
				return createErrorResult("Underlying data type not found: " + underlyingTypePath);
			}
			// Typedef constructor handles cloning if necessary

			// Ensure category exists (can be done outside tx)
			dtm.createCategory(categoryPath);

			// --- Execute modification in transaction ---
			final String finalTypedefPathString = typedefPathString; // Capture for message
			final CategoryPath finalCategoryPath = categoryPath; // Capture for lambda
			return executeInTransaction(program, "MCP - Create Typedef", () -> {
				// Inner Callable logic:
				// Create the new Typedef
				TypeDef newTypeDef = new TypedefDataType(finalCategoryPath, typedefName, underlyingDt, dtm);

				// Set optional description
				descriptionOpt.ifPresent(newTypeDef::setDescription);

				// Add the new typedef to the manager
				DataType addedType = dtm.addDataType(newTypeDef, DataTypeConflictHandler.DEFAULT_HANDLER);

				if (addedType != null) {
					// Return success
					return createSuccessResult("Typedef '" + finalTypedefPathString + "' created successfully.");
				} else {
					// This might indicate an unexpected conflict despite pre-check
					return createErrorResult(
							"Failed to add typedef '" + finalTypedefPathString + "' after creation (unexpected conflict?).");
				}
			}); // End of Callable for executeInTransaction

		}).onErrorResume(e -> {
			// Catch errors from getProgram, setup (incl. arg parsing), or transaction
			// execution
			// Logging handled by createErrorResult
			return createErrorResult(e);
		});
	}
}