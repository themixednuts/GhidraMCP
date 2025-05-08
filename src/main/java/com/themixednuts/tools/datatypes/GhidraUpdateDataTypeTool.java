package com.themixednuts.tools.datatypes;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.tools.ToolCategory;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Update Data Type", category = ToolCategory.DATATYPES, description = "Updates properties of an existing Function Definition or Typedef.", mcpName = "update_data_type", mcpDescription = "Updates properties (return type, parameters, comment, calling convention, varargs) of an existing Function Definition, or the underlying type/comment of a Typedef.")
public class GhidraUpdateDataTypeTool implements IGhidraMcpSpecification {

	public static final String ARG_NEW_RETURN_TYPE = "newReturnType";
	public static final String ARG_NEW_PARAMETERS = "newParameters";
	public static final String ARG_NEW_CALLING_CONVENTION = "newCallingConvention";
	public static final String ARG_REMOVE_VAR_ARGS = "removeVarArgs";
	public static final String ARG_ADD_VAR_ARGS = "addVarArgs";

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();

		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The file name of the Ghidra tool window to target."));

		IObjectSchemaBuilder parameterSchema = JsonSchemaBuilder.object(mapper)
				.property(ARG_NAME, JsonSchemaBuilder.string(mapper).description("Parameter name"), true)
				.property(ARG_DATA_TYPE_PATH, JsonSchemaBuilder.string(mapper).description("Parameter data type name"), true)
				.property(ARG_COMMENT, JsonSchemaBuilder.string(mapper).description("Optional parameter comment"))
				.description("Definition of a single parameter.");

		List<String> standardCallingConventions = List.of(
				CompilerSpec.CALLING_CONVENTION_cdecl,
				CompilerSpec.CALLING_CONVENTION_stdcall,
				CompilerSpec.CALLING_CONVENTION_fastcall,
				CompilerSpec.CALLING_CONVENTION_thiscall,
				CompilerSpec.CALLING_CONVENTION_pascal,
				CompilerSpec.CALLING_CONVENTION_vectorcall,
				CompilerSpec.CALLING_CONVENTION_rustcall);

		IObjectSchemaBuilder functionDefinitionSchema = JsonSchemaBuilder.object(mapper)
				.property(ARG_DATA_TYPE,
						JsonSchemaBuilder.string(mapper).description("The data type to update.")
								.enumValues(DataTypeKind.FUNCTION_DEFINITION.name()))
				.property(ARG_FUNC_DEF_PATH,
						JsonSchemaBuilder.string(mapper)
								.description("The name of the function definition data type to update."))
				.property(ARG_NEW_RETURN_TYPE,
						JsonSchemaBuilder.string(mapper)
								.description("Optional: The new return data type name."))
				.property(ARG_NEW_PARAMETERS,
						JsonSchemaBuilder.array(mapper)
								.items(parameterSchema)
								.description("Optional: A new list of parameters. Replaces existing parameters."))
				.property(ARG_COMMENT,
						JsonSchemaBuilder.string(mapper)
								.description("Optional: A new comment for the function definition."))
				.property(ARG_COMMENT,
						JsonSchemaBuilder.string(mapper)
								.description("Optional: A new comment for the function definition."))
				.property(ARG_NEW_CALLING_CONVENTION,
						JsonSchemaBuilder.string(mapper)
								.description(
										"Optional: The new calling convention name. Must be one of the standard known conventions.")
								.enumValues(standardCallingConventions))
				.property(ARG_REMOVE_VAR_ARGS,
						JsonSchemaBuilder.bool(mapper)
								.description("Optional: Set to true to remove varargs. Defaults to false.")
								.defaultValue(false))
				.property(ARG_ADD_VAR_ARGS,
						JsonSchemaBuilder.bool(mapper)
								.description("Optional: Set to true to add varargs. Defaults to false.")
								.defaultValue(false))
				.requiredProperty(ARG_DATA_TYPE)
				.requiredProperty(ARG_FILE_NAME)
				.requiredProperty(ARG_FUNC_DEF_PATH);

		IObjectSchemaBuilder typeDefSchema = JsonSchemaBuilder.object(mapper)
				.property(ARG_DATA_TYPE,
						JsonSchemaBuilder.string(mapper).description("The data type to update.")
								.enumValues(DataTypeKind.TYPEDEF.name()))
				.property(ARG_TYPEDEF_PATH,
						JsonSchemaBuilder.string(mapper)
								.description("The full path of the typedef to update (e.g., /MyTypes/MyIntPtr)"))
				.property(ARG_DATA_TYPE_PATH,
						JsonSchemaBuilder.string(mapper)
								.description("Optional new underlying data type path (e.g., 'long *', '/OtherStruct')."))
				.property(ARG_COMMENT,
						JsonSchemaBuilder.string(mapper)
								.description("Optional new description text. An empty string clears the description."))
				.requiredProperty(ARG_DATA_TYPE)
				.requiredProperty(ARG_TYPEDEF_PATH);

		schemaRoot.anyOf(List.of(functionDefinitionSchema, typeDefSchema));

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		String dataType = getRequiredStringArgument(args, ARG_DATA_TYPE);
		DataTypeKind dataTypeKind = DataTypeKind.valueOf(dataType);

		switch (dataTypeKind) {
			case FUNCTION_DEFINITION:
				return updateFunctionDefinition(ex, args, tool);
			case TYPEDEF:
				return updateTypeDef(ex, args, tool);
			default:
				throw new IllegalArgumentException("Invalid data type: " + dataType);
		}
	}

	private static record FuncDefUpdateContext(
			Program program,
			FunctionDefinition funcDef,
			Optional<DataType> newReturnTypeOpt,
			Optional<List<ParameterDefinition>> newParametersOpt,
			Optional<String> newCommentOpt,
			Optional<String> newCallingConventionOpt,
			boolean removeVarArgs,
			boolean addVarArgs,
			String originalPath) {
	}

	private Mono<? extends Object> updateFunctionDefinition(McpAsyncServerExchange ex, Map<String, Object> args,
			PluginTool tool) {
		return getProgram(args, tool)
				.map(program -> { // .map for sync setup
					String funcDefPath = getRequiredStringArgument(args, ARG_FUNC_DEF_PATH);
					Optional<String> newReturnTypePathOpt = getOptionalStringArgument(args, ARG_NEW_RETURN_TYPE);
					Optional<List<Map<String, Object>>> newParamsListOpt = getOptionalListArgument(args, ARG_NEW_PARAMETERS);
					Optional<String> newCommentOpt = getOptionalStringArgument(args, ARG_COMMENT);
					Optional<String> newCallingConventionOpt = getOptionalStringArgument(args, ARG_NEW_CALLING_CONVENTION);
					boolean removeVarArgs = getOptionalBooleanArgument(args, ARG_REMOVE_VAR_ARGS).orElse(false);
					boolean addVarArgs = getOptionalBooleanArgument(args, ARG_ADD_VAR_ARGS).orElse(false);

					// Validate: At least one change specified
					if (newReturnTypePathOpt.isEmpty() && newParamsListOpt.isEmpty() && newCommentOpt.isEmpty()
							&& newCallingConventionOpt.isEmpty() && !removeVarArgs && !addVarArgs) {
						throw new IllegalArgumentException(
								"No changes specified. Provide at least one update argument (e.g., newReturnType, newParameters).");
					}

					if (removeVarArgs && addVarArgs) {
						throw new IllegalArgumentException("Cannot both add and remove varargs in the same operation.");
					}

					DataType dt = program.getDataTypeManager().getDataType(funcDefPath);
					if (dt == null) {
						throw new IllegalArgumentException("Function definition data type not found: " + funcDefPath);
					}
					if (!(dt instanceof FunctionDefinition)) {
						throw new IllegalArgumentException("Data type '" + funcDefPath + "' is not a Function Definition.");
					}
					FunctionDefinition funcDef = (FunctionDefinition) dt;

					// Resolve return type if provided
					Optional<DataType> newReturnTypeResolvedOpt = Optional.empty();
					if (newReturnTypePathOpt.isPresent()) {
						DataType returnDt = program.getDataTypeManager().getDataType(newReturnTypePathOpt.get());
						if (returnDt == null) {
							throw new IllegalArgumentException("New return data type not found: " + newReturnTypePathOpt.get());
						}
						newReturnTypeResolvedOpt = Optional.of(returnDt);
					}

					// Resolve parameters if provided
					Optional<List<ParameterDefinition>> newParamsResolvedOpt = Optional.empty();
					if (newParamsListOpt.isPresent()) {
						List<ParameterDefinition> params = new ArrayList<>();
						for (Map<String, Object> paramMap : newParamsListOpt.get()) {
							String paramName = getRequiredStringArgument(paramMap, ARG_NAME);
							String paramTypeName = getRequiredStringArgument(paramMap, ARG_DATA_TYPE_PATH);
							String paramComment = getOptionalStringArgument(paramMap, ARG_COMMENT).orElse(null);
							DataType paramDt = program.getDataTypeManager().getDataType(paramTypeName);
							if (paramDt == null) {
								throw new IllegalArgumentException("Parameter data type not found: " + paramTypeName);
							}
							params.add(new ParameterDefinitionImpl(paramName, paramDt, paramComment));
						}
						newParamsResolvedOpt = Optional.of(params);
					}

					return new FuncDefUpdateContext(program, funcDef, newReturnTypeResolvedOpt, newParamsResolvedOpt,
							newCommentOpt, newCallingConventionOpt, removeVarArgs, addVarArgs, funcDefPath);
				})
				.flatMap(context -> { // .flatMap for transaction
					return executeInTransaction(context.program(), "Update Function Definition: " + context.originalPath(),
							() -> {
								// Apply updates within the transaction
								if (context.newReturnTypeOpt().isPresent()) {
									context.funcDef().setReturnType(context.newReturnTypeOpt().get());
								}
								if (context.newParametersOpt().isPresent()) {
									context.funcDef()
											.setArguments(context.newParametersOpt().get().toArray(new ParameterDefinition[0]));
								}
								if (context.newCommentOpt().isPresent()) {
									context.funcDef().setComment(context.newCommentOpt().get());
								}
								if (context.newCallingConventionOpt().isPresent()) {
									context.funcDef().setCallingConvention(context.newCallingConventionOpt().get());
								}

								if (context.removeVarArgs()) {
									context.funcDef().setVarArgs(false);
								}
								if (context.addVarArgs()) {
									context.funcDef().setVarArgs(true);
								}

								// Return simple success string
								return "Function definition '" + context.originalPath() + "' updated successfully.";
							});
				});
	}

	private static record TypeDefUpdateContext(
			Program program,
			TypeDef oldTypeDef,
			DataType resolvedUnderlyingType,
			String resolvedDescription,
			String originalPath,
			List<String> updatedFields) {
	}

	private Mono<? extends Object> updateTypeDef(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).map(program -> {
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
