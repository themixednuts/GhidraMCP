package com.themixednuts.tools.datatypes;

import java.util.Map;
import java.util.Optional;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;
import com.themixednuts.tools.ToolCategory;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.*;
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Create TypeDef", category = ToolCategory.DATATYPES, description = "Creates a new typedef data type.", mcpName = "create_typedef", mcpDescription = "Defines a new typedef based on an existing data type.")
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

		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The file name of the Ghidra tool window to target"));

		schemaRoot.property(ARG_TYPEDEF_PATH,
				JsonSchemaBuilder.string(mapper)
						.description("The full path for the new typedef (e.g., /MyTypes/MyIntPtr)"));

		schemaRoot.property(ARG_DATA_TYPE_PATH,
				JsonSchemaBuilder.string(mapper)
						.description("Full path or name of the data type to alias (e.g., 'int *', '/MyStruct')."));

		schemaRoot.property(ARG_COMMENT,
				JsonSchemaBuilder.string(mapper)
						.description("Optional description for the typedef."));

		schemaRoot.requiredProperty(ARG_FILE_NAME)
				.requiredProperty(ARG_TYPEDEF_PATH)
				.requiredProperty(ARG_DATA_TYPE_PATH);

		return schemaRoot.build();
	}

	@Override
	public Mono<CallToolResult> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).flatMap(program -> {
			// Setup: Parse args, resolve path, check existence, resolve underlying type,
			// ensure category
			// Argument parsing errors caught by onErrorResume
			String typedefPathString = getRequiredStringArgument(args, ARG_TYPEDEF_PATH);
			String underlyingTypePath = getRequiredStringArgument(args, ARG_DATA_TYPE_PATH);
			final Optional<String> descriptionOpt = getOptionalStringArgument(args, ARG_COMMENT); // Final for lambda

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