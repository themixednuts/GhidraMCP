package com.themixednuts.tools.datatypes;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.tools.ToolCategory;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;
import com.themixednuts.utils.DataTypeUtils;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Update Typedef", category = ToolCategory.DATATYPES, description = "Updates properties of an existing Typedef.", mcpName = "update_typedef", mcpDescription = "Updates the underlying data type or description of an existing Typedef.")
public class GhidraUpdateTypedefTool implements IGhidraMcpSpecification {

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();

		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The file name of the Ghidra tool window to target."),
				true);
		schemaRoot.property(ARG_TYPEDEF_PATH,
				JsonSchemaBuilder.string(mapper)
						.description("The full path of the typedef to update (e.g., /MyTypes/MyIntPtr)"),
				true);
		schemaRoot.property(ARG_DATA_TYPE_PATH,
				JsonSchemaBuilder.string(mapper)
						.description(
								"Optional new underlying data type path (e.g., 'long *', '/OtherStruct', 'int[4]'). Array and pointer notations are supported."));
		schemaRoot.property(ARG_COMMENT,
				JsonSchemaBuilder.string(mapper)
						.description("Optional new description text. An empty string clears the description."));

		schemaRoot.requiredProperty(ARG_FILE_NAME);
		schemaRoot.requiredProperty(ARG_TYPEDEF_PATH);

		return schemaRoot.build();
	}

	private static record TypeDefUpdateContext(
			Program program,
			TypeDef oldTypeDef,
			DataType resolvedUnderlyingType,
			String resolvedDescription,
			String originalPath,
			List<String> updatedFields) {
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).map(program -> {
			GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
			final String typedefPathString = getRequiredStringArgument(args, ARG_TYPEDEF_PATH);
			Optional<String> newUnderlyingTypePathOpt = getOptionalStringArgument(args, ARG_DATA_TYPE_PATH);
			Optional<String> newDescriptionOpt = getOptionalStringArgument(args, ARG_COMMENT);

			if (newUnderlyingTypePathOpt.isEmpty() && newDescriptionOpt.isEmpty()) {
				GhidraMcpError error = GhidraMcpError.validation()
						.errorCode(GhidraMcpError.ErrorCode.MISSING_REQUIRED_ARGUMENT)
						.message("No changes specified. Provide at least one update argument.")
						.context(new GhidraMcpError.ErrorContext(
								annotation.mcpName(),
								"argument validation",
								args,
								Map.of("providedArguments", 0),
								Map.of("minimumRequired", 1)))
						.suggestions(List.of(
								new GhidraMcpError.ErrorSuggestion(
										GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
										"Provide at least one update argument",
										"Include dataTypePath or comment",
										List.of("\"dataTypePath\": \"int *\"", "\"comment\": \"Updated typedef\""),
										null)))
						.build();
				throw new GhidraMcpException(error);
			}

			DataType dt;
			try {
				dt = DataTypeUtils.parseDataTypeString(program, typedefPathString, tool);
			} catch (IllegalArgumentException e) {
				GhidraMcpError error = GhidraMcpError.resourceNotFound()
						.errorCode(GhidraMcpError.ErrorCode.DATA_TYPE_NOT_FOUND)
						.message("Typedef not found at path: " + typedefPathString)
						.context(new GhidraMcpError.ErrorContext(
								annotation.mcpName(),
								"typedef lookup",
								Map.of(ARG_TYPEDEF_PATH, typedefPathString),
								Map.of("typedefPath", typedefPathString),
								Map.of("dataTypeExists", false)))
						.suggestions(List.of(
								new GhidraMcpError.ErrorSuggestion(
										GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
										"List available typedefs",
										"Check what typedefs exist",
										null,
										List.of(getMcpName(GhidraListDataTypesTool.class)))))
						.build();
				throw new GhidraMcpException(error);
			} catch (InvalidDataTypeException e) {
				GhidraMcpError error = GhidraMcpError.validation()
						.errorCode(GhidraMcpError.ErrorCode.INVALID_TYPE_PATH)
						.message("Invalid typedef format for path: " + typedefPathString)
						.context(new GhidraMcpError.ErrorContext(
								annotation.mcpName(),
								"typedef path validation",
								Map.of(ARG_TYPEDEF_PATH, typedefPathString),
								Map.of("typedefPath", typedefPathString),
								Map.of("formatError", e.getMessage())))
						.suggestions(List.of(
								new GhidraMcpError.ErrorSuggestion(
										GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
										"Check typedef path format",
										"Use correct typedef path format",
										List.of("'/MyTypes/MyIntPtr'", "'/MyTypedef'"),
										null)))
						.build();
				throw new GhidraMcpException(error);
			} catch (CancelledException e) {
				throw new RuntimeException("Parsing cancelled for typedef path '" + typedefPathString + "'.", e);
			} catch (RuntimeException e) {
				throw new RuntimeException(
						"Unexpected error parsing typedef path '" + typedefPathString + "': " + e.getMessage(), e);
			}

			if (!(dt instanceof TypeDef)) {
				GhidraMcpError error = GhidraMcpError.validation()
						.errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
						.message("Data type at path is not a Typedef: " + typedefPathString)
						.context(new GhidraMcpError.ErrorContext(
								annotation.mcpName(),
								"data type validation",
								Map.of(ARG_TYPEDEF_PATH, typedefPathString),
								Map.of("typedefPath", typedefPathString, "actualDataType", dt.getDisplayName()),
								Map.of("isTypedef", false, "actualTypeName", dt.getClass().getSimpleName())))
						.suggestions(List.of(
								new GhidraMcpError.ErrorSuggestion(
										GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
										"Use a typedef data type",
										"Ensure the path points to a typedef, not " + dt.getClass().getSimpleName(),
										null,
										null)))
						.build();
				throw new GhidraMcpException(error);
			}
			final TypeDef oldTypeDef = (TypeDef) dt;

			final List<String> updatedFields = new java.util.ArrayList<>();
			DataType underlyingType = oldTypeDef.getDataType();
			String description = oldTypeDef.getDescription();

			// Resolve new Underlying Type if provided
			if (newUnderlyingTypePathOpt.isPresent()) {
				String newUnderlyingTypePath = newUnderlyingTypePathOpt.get();
				DataType newUnderlyingDt;
				try {
					newUnderlyingDt = DataTypeUtils.parseDataTypeString(program, newUnderlyingTypePath, tool);
				} catch (IllegalArgumentException e) {
					throw e;
				} catch (InvalidDataTypeException e) {
					GhidraMcpError error = GhidraMcpError.validation()
							.errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
							.message("Invalid new underlying data type format: " + newUnderlyingTypePath)
							.context(new GhidraMcpError.ErrorContext(
									annotation.mcpName(),
									"underlying type format validation",
									Map.of(ARG_DATA_TYPE_PATH, newUnderlyingTypePath),
									Map.of("underlyingTypePath", newUnderlyingTypePath),
									Map.of("formatError", e.getMessage())))
							.suggestions(List.of(
									new GhidraMcpError.ErrorSuggestion(
											GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
											"Check underlying type format",
											"Use correct data type path format",
											List.of("'int *'", "'/MyStruct'", "'char[10]'"),
											null)))
							.build();
					throw new GhidraMcpException(error);
				} catch (CancelledException e) {
					throw new RuntimeException(
							"Parsing cancelled for new underlying data type '" + newUnderlyingTypePath + "'.", e);
				} catch (RuntimeException e) {
					throw new RuntimeException(
							"Unexpected error parsing new underlying data type '" + newUnderlyingTypePath + "': " + e.getMessage(),
							e);
				}

				if (newUnderlyingDt instanceof TypeDef) {
					DataType base = ((TypeDef) newUnderlyingDt).getBaseDataType();
					if (base.isEquivalent(oldTypeDef)) {
						GhidraMcpError error = GhidraMcpError.validation()
								.errorCode(GhidraMcpError.ErrorCode.CIRCULAR_TYPE_REFERENCE)
								.message("Update creates cyclic dependency: " + typedefPathString + " -> " + newUnderlyingTypePath)
								.context(new GhidraMcpError.ErrorContext(
										annotation.mcpName(),
										"circular dependency validation",
										Map.of(ARG_TYPEDEF_PATH, typedefPathString, ARG_DATA_TYPE_PATH, newUnderlyingTypePath),
										Map.of("sourceTypedef", typedefPathString, "targetTypedef", newUnderlyingTypePath),
										Map.of("circularReference", true)))
								.suggestions(List.of(
										new GhidraMcpError.ErrorSuggestion(
												GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
												"Use a different underlying type",
												"Avoid circular dependencies between typedefs",
												null,
												null)))
								.build();
						throw new GhidraMcpException(error);
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