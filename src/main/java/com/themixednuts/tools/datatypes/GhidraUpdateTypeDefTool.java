package com.themixednuts.tools.datatypes;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;
import com.themixednuts.tools.ToolCategory;

import ghidra.program.model.data.*;
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import reactor.core.publisher.Mono;
import ghidra.framework.plugintool.PluginTool;

@GhidraMcpTool(key = "Update TypeDef", category = ToolCategory.DATATYPES, description = "Updates an existing typedef data type.", mcpName = "update_typedef", mcpDescription = "Changes the underlying data type that an existing typedef aliases.")
public class GhidraUpdateTypeDefTool implements IGhidraMcpSpecification {

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

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();

		schemaRoot.property("fileName",
				JsonSchemaBuilder.string(mapper)
						.description("The file name of the Ghidra tool window to target"));

		schemaRoot.property("typedefPath",
				JsonSchemaBuilder.string(mapper)
						.description("The full path of the typedef to update (e.g., /MyTypes/MyIntPtr)"));

		schemaRoot.property("newUnderlyingTypePath",
				JsonSchemaBuilder.string(mapper)
						.description("Optional new underlying data type path (e.g., 'long *', '/OtherStruct')."));

		schemaRoot.property("newDescription",
				JsonSchemaBuilder.string(mapper)
						.description("Optional new description text. An empty string clears the description."));

		schemaRoot.requiredProperty("fileName")
				.requiredProperty("typedefPath");

		// Note: The logic for requiring at least one 'new...' property is handled
		// in the execute method, as standard JSON Schema doesn't easily express
		// 'at least one of property X OR property Y must exist'.
		// The previous `minProperties` approach was brittle.

		return schemaRoot.build();
	}

	@Override
	public Mono<CallToolResult> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).flatMap(program -> {
			final String typedefPathString = getRequiredStringArgument(args, "typedefPath"); // Final for lambda
			Optional<String> newUnderlyingTypePathOpt = getOptionalStringArgument(args, "newUnderlyingTypePath");
			Optional<String> newDescriptionOpt = getOptionalStringArgument(args, "newDescription");

			if (newUnderlyingTypePathOpt.isEmpty() && newDescriptionOpt.isEmpty()) {
				return createErrorResult("No changes specified. Provide at least newUnderlyingTypePath or newDescription.");
			}

			DataTypeManager dtm = program.getDataTypeManager();
			DataType dt = dtm.getDataType(typedefPathString);

			if (dt == null) {
				return createErrorResult("Typedef not found at path: " + typedefPathString);
			}
			if (!(dt instanceof TypeDef)) { // Use interface for safety
				return createErrorResult("Data type at path is not a Typedef: " + typedefPathString);
			}
			final TypeDef oldTypeDef = (TypeDef) dt; // Final for lambda

			final List<String> updatedFields = new ArrayList<>(); // Final for lambda
			DataType underlyingType = oldTypeDef.getDataType();
			String description = oldTypeDef.getDescription();

			// Resolve new Underlying Type if provided
			if (newUnderlyingTypePathOpt.isPresent()) {
				String newUnderlyingTypePath = newUnderlyingTypePathOpt.get();
				DataType newUnderlyingDt = dtm.getDataType(newUnderlyingTypePath);
				if (newUnderlyingDt == null) {
					return createErrorResult("New underlying data type not found: " + newUnderlyingTypePath);
				}
				// Check for cyclic dependency
				if (newUnderlyingDt instanceof TypeDef) {
					DataType base = ((TypeDef) newUnderlyingDt).getBaseDataType();
					if (base.isEquivalent(oldTypeDef)) {
						return createErrorResult(
								"Update creates cyclic dependency: " + typedefPathString + " -> " + newUnderlyingTypePath);
					}
				}
				underlyingType = newUnderlyingDt;
				updatedFields.add("underlyingType");
			}

			// Resolve new Description if provided
			if (newDescriptionOpt.isPresent()) {
				description = newDescriptionOpt.get();
				updatedFields.add("description");
			}

			final DataType resolvedUnderlyingType = underlyingType; // Final for lambda
			final String resolvedDescription = description; // Final for lambda

			// --- Execute modification in transaction ---
			return executeInTransaction(program, "MCP - Update Typedef", () -> {
				// Inner Callable logic (just the modification):
				// Create the replacement Typedef
				TypeDef newTypeDef = new TypedefDataType(oldTypeDef.getCategoryPath(), oldTypeDef.getName(),
						resolvedUnderlyingType.clone(dtm), dtm);
				if (resolvedDescription != null) {
					newTypeDef.setDescription(resolvedDescription);
				}
				// Replace the old data type - returns the resolved DataType
				DataType replacedDt = dtm.replaceDataType(oldTypeDef, newTypeDef, true);

				if (replacedDt != null) {
					return createSuccessResult("Typedef '" + typedefPathString + "' updated successfully. Modified fields: "
							+ String.join(", ", updatedFields));
				} else {
					return createErrorResult(
							"Failed to replace typedef '" + typedefPathString + "' after creating replacement.");
				}
			}); // End of Callable for executeInTransaction

		}).onErrorResume(e -> {
			return createErrorResult(e);
		});
	}
}