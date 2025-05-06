package com.themixednuts.tools.datatypes;

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
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;
import ghidra.framework.plugintool.PluginTool;

@GhidraMcpTool(name = "Update TypeDef", category = ToolCategory.DATATYPES, description = "Updates an existing typedef data type.", mcpName = "update_typedef", mcpDescription = "Changes the underlying data type that an existing typedef aliases.")
public class GhidraUpdateTypeDefTool implements IGhidraMcpSpecification {

	// Context Record
	private static record TypeDefUpdateContext(
			Program program,
			TypeDef oldTypeDef,
			DataType resolvedUnderlyingType,
			String resolvedDescription,
			String originalPath,
			List<String> updatedFields) {
	}

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();

		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The file name of the Ghidra tool window to target"));

		schemaRoot.property(ARG_TYPEDEF_PATH,
				JsonSchemaBuilder.string(mapper)
						.description("The full path of the typedef to update (e.g., /MyTypes/MyIntPtr)"));

		schemaRoot.property(ARG_DATA_TYPE_PATH,
				JsonSchemaBuilder.string(mapper)
						.description("Optional new underlying data type path (e.g., 'long *', '/OtherStruct')."));

		schemaRoot.property(ARG_COMMENT,
				JsonSchemaBuilder.string(mapper)
						.description("Optional new description text. An empty string clears the description."));

		schemaRoot.requiredProperty(ARG_FILE_NAME)
				.requiredProperty(ARG_TYPEDEF_PATH);

		// Note: The logic for requiring at least one 'new...' property is handled
		// in the execute method, as standard JSON Schema doesn't easily express
		// 'at least one of property X OR property Y must exist'.
		// The previous `minProperties` approach was brittle.

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).map(program -> { // .map for synchronous setup
			final String typedefPathString = getRequiredStringArgument(args, ARG_TYPEDEF_PATH);
			Optional<String> newUnderlyingTypePathOpt = getOptionalStringArgument(args, ARG_DATA_TYPE_PATH);
			Optional<String> newDescriptionOpt = getOptionalStringArgument(args, ARG_COMMENT);

			if (newUnderlyingTypePathOpt.isEmpty() && newDescriptionOpt.isEmpty()) {
				throw new IllegalArgumentException(
						"No changes specified. Provide at least newUnderlyingTypePath or newDescription.");
			}

			DataType dt = program.getDataTypeManager().getDataType(typedefPathString);

			if (dt == null) {
				throw new IllegalArgumentException("Typedef not found at path: " + typedefPathString);
			}
			if (!(dt instanceof TypeDef)) { // Use interface for safety
				throw new IllegalArgumentException("Data type at path is not a Typedef: " + typedefPathString);
			}
			final TypeDef oldTypeDef = (TypeDef) dt;

			final List<String> updatedFields = new java.util.ArrayList<>();
			DataType underlyingType = oldTypeDef.getDataType();
			String description = oldTypeDef.getDescription();

			// Resolve new Underlying Type if provided
			if (newUnderlyingTypePathOpt.isPresent()) {
				String newUnderlyingTypePath = newUnderlyingTypePathOpt.get();
				DataType newUnderlyingDt = program.getDataTypeManager().getDataType(newUnderlyingTypePath);
				if (newUnderlyingDt == null) {
					throw new IllegalArgumentException("New underlying data type not found: " + newUnderlyingTypePath);
				}
				// Check for cyclic dependency
				if (newUnderlyingDt instanceof TypeDef) {
					DataType base = ((TypeDef) newUnderlyingDt).getBaseDataType();
					if (base.isEquivalent(oldTypeDef)) {
						throw new IllegalArgumentException(
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

			final DataType resolvedUnderlyingType = underlyingType;
			final String resolvedDescription = description;

			return new TypeDefUpdateContext(program, oldTypeDef, resolvedUnderlyingType, resolvedDescription,
					typedefPathString, updatedFields);

		}).flatMap(context -> { // .flatMap for transaction
			// --- Execute modification in transaction ---
			return executeInTransaction(context.program(), "MCP - Update Typedef", () -> {
				DataTypeManager dtmInTx = context.program().getDataTypeManager();
				// Create the replacement Typedef
				TypeDef newTypeDef = new TypedefDataType(context.oldTypeDef().getCategoryPath(), context.oldTypeDef().getName(),
						context.resolvedUnderlyingType().clone(dtmInTx), dtmInTx);
				if (context.resolvedDescription() != null) {
					newTypeDef.setDescription(context.resolvedDescription());
				}
				// Replace the old data type - returns the resolved DataType
				DataType replacedDt = dtmInTx.replaceDataType(context.oldTypeDef(), newTypeDef, true);

				if (replacedDt != null) {
					return "Typedef '" + context.originalPath() + "' updated successfully. Modified fields: "
							+ String.join(", ", context.updatedFields());
				} else {
					throw new RuntimeException(
							"Failed to replace typedef '" + context.originalPath() + "' after creating replacement.");
				}
			}); // End of Callable for executeInTransaction
		});
	}
}