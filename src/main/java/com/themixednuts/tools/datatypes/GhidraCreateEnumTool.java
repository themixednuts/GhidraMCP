package com.themixednuts.tools.datatypes;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.utils.JsonSchemaBuilder;
import com.themixednuts.utils.JsonSchemaBuilder.IArraySchemaBuilder;
import com.themixednuts.utils.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.framework.plugintool.PluginTool;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import ghidra.util.Msg;
import ghidra.program.model.data.*;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import reactor.core.publisher.Mono;

@GhidraMcpTool(key = "Create Enum", category = "Data Types", description = "Enable the MCP tool to create a new enum data type.", mcpName = "create_enum", mcpDescription = "Creates a new enum data type with specified entries at the given path.")
public class GhidraCreateEnumTool implements IGhidraMcpSpecification {

	// Simple record to hold resolved entry details
	private record ResolvedEnumEntry(String name, long value, String comment) {
	}

	public GhidraCreateEnumTool() {
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

		schemaRoot.property("enumPath",
				JsonSchemaBuilder.string(mapper)
						.description("The full path for the new enum (e.g., /MyCategory/MyEnum)"));

		schemaRoot.property("enumSize",
				JsonSchemaBuilder.integer(mapper)
						.description("The size of the enum in bytes (1, 2, 4, or 8)."));

		IObjectSchemaBuilder entrySchema = JsonSchemaBuilder.object(mapper)
				.description("Definition for a single enum entry.")
				.property("entryName",
						JsonSchemaBuilder.string(mapper)
								.description("Name for the enum entry."))
				.property("entryValue",
						JsonSchemaBuilder.integer(mapper)
								.description("Integer value for the enum entry."))
				.property("entryComment",
						JsonSchemaBuilder.string(mapper)
								.description("Optional comment for the enum entry."))
				.requiredProperty("entryName")
				.requiredProperty("entryValue");

		IArraySchemaBuilder entriesArraySchema = JsonSchemaBuilder.array(mapper)
				.items(entrySchema)
				.minItems(1)
				.description("Optional list of entries (name/value pairs) for the enum.");

		schemaRoot.property("entries", entriesArraySchema);

		schemaRoot.requiredProperty("fileName")
				.requiredProperty("enumPath")
				.requiredProperty("enumSize"); // entries is optional

		return schemaRoot.build();
	}

	@Override
	public Mono<CallToolResult> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).flatMap(program -> {
			// Setup: Parse args, validate, resolve path, check existence, ensure category,
			// resolve entries
			// Argument parsing errors caught by onErrorResume
			String enumPathString = getRequiredStringArgument(args, "enumPath");
			final Integer enumSizeInt = getRequiredIntArgument(args, "enumSize"); // Final for lambda
			Optional<ArrayNode> entriesOpt = getOptionalArrayNodeArgument(args, "entries");

			// Validate size
			final int enumSize = enumSizeInt.intValue(); // Final for lambda
			if (enumSize != 1 && enumSize != 2 && enumSize != 4 && enumSize != 8) {
				return createErrorResult("Invalid enumSize: Must be 1, 2, 4, or 8.");
			}

			CategoryPath categoryPath; // Not final here
			final String enumName; // Final for lambda
			try {
				CategoryPath fullPath = new CategoryPath(enumPathString);
				enumName = fullPath.getName();
				categoryPath = fullPath.getParent();
				if (categoryPath == null) {
					categoryPath = CategoryPath.ROOT;
				}
				if (enumName.isBlank()) {
					return createErrorResult("Invalid enum path: Name cannot be blank.");
				}
			} catch (IllegalArgumentException e) {
				return createErrorResult("Invalid enum path format: " + enumPathString);
			}

			final DataTypeManager dtm = program.getDataTypeManager(); // Final for lambda

			// Check if data type already exists
			if (dtm.getDataType(enumPathString) != null) {
				return createErrorResult("Data type already exists at path: " + enumPathString);
			}

			// Resolve entries (outside transaction)
			final List<ResolvedEnumEntry> resolvedEntries = new ArrayList<>(); // Final for lambda
			if (entriesOpt.isPresent()) {
				ArrayNode entriesArray = entriesOpt.get();
				for (JsonNode entryNode : entriesArray) {
					if (!entryNode.isObject()) {
						return createErrorResult("Invalid entry definition: Expected an object.");
					}
					String entryName = getRequiredStringArgument(entryNode, "entryName");
					Long entryValue = getRequiredLongArgument(entryNode, "entryValue");
					String entryComment = getOptionalStringArgument(entryNode, "entryComment").orElse(null);
					resolvedEntries.add(new ResolvedEnumEntry(entryName, entryValue, entryComment));
				}
			}

			// Ensure category exists (can be done outside tx)
			dtm.createCategory(categoryPath);

			// --- Execute modification in transaction ---
			final String finalEnumPathString = enumPathString; // Capture for message
			final CategoryPath finalCategoryPath = categoryPath; // Capture for lambda
			return executeInTransaction(program, "MCP - Create Enum", () -> {
				// Inner Callable logic:
				// Create the new enum
				EnumDataType newEnum = new EnumDataType(finalCategoryPath, enumName, enumSize, dtm);

				// Add resolved entries
				for (ResolvedEnumEntry entry : resolvedEntries) {
					// EnumDataType.add handles replacing entries with same name OR value
					// No specific exception needs to be caught here usually
					newEnum.add(entry.name(), entry.value(), entry.comment());
				}

				// Add the populated enum to the manager
				DataType addedType = dtm.addDataType(newEnum, DataTypeConflictHandler.DEFAULT_HANDLER);

				if (addedType != null) {
					// Return success
					return createSuccessResult("Enum '" + finalEnumPathString + "' created successfully.");
				} else {
					// This might indicate an unexpected conflict despite pre-check
					return createErrorResult(
							"Failed to add enum '" + finalEnumPathString + "' after creation (unexpected conflict?).");
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