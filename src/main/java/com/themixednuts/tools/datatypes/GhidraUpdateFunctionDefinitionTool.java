package com.themixednuts.tools.datatypes;

import java.util.ArrayList;
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
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Update Function Definition", category = ToolCategory.DATATYPES, description = "Updates properties of an existing Function Definition.", mcpName = "update_function_definition", mcpDescription = "Updates properties (return type, parameters, comment, calling convention, varargs) of an existing Function Definition.")
public class GhidraUpdateFunctionDefinitionTool implements IGhidraMcpSpecification {

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
						.description("The file name of the Ghidra tool window to target."),
				true);
		schemaRoot.property(ARG_FUNC_DEF_PATH,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the function definition data type to update."),
				true);

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

		schemaRoot.property(ARG_NEW_RETURN_TYPE,
				JsonSchemaBuilder.string(mapper)
						.description("Optional: The new return data type name."));
		schemaRoot.property(ARG_NEW_PARAMETERS,
				JsonSchemaBuilder.array(mapper)
						.items(parameterSchema)
						.description("Optional: A new list of parameters. Replaces existing parameters."));
		schemaRoot.property(ARG_COMMENT,
				JsonSchemaBuilder.string(mapper)
						.description("Optional: A new comment for the function definition."));
		schemaRoot.property(ARG_NEW_CALLING_CONVENTION,
				JsonSchemaBuilder.string(mapper)
						.description(
								"Optional: The new calling convention name. Must be one of the standard known conventions.")
						.enumValues(standardCallingConventions));
		schemaRoot.property(ARG_REMOVE_VAR_ARGS,
				JsonSchemaBuilder.bool(mapper)
						.description("Optional: Set to true to remove varargs. Defaults to false.")
						.defaultValue(false));
		schemaRoot.property(ARG_ADD_VAR_ARGS,
				JsonSchemaBuilder.bool(mapper)
						.description("Optional: Set to true to add varargs. Defaults to false.")
						.defaultValue(false));

		schemaRoot.requiredProperty(ARG_FILE_NAME);
		schemaRoot.requiredProperty(ARG_FUNC_DEF_PATH);

		return schemaRoot.build();
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

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool)
				.map(program -> {
					GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
					String funcDefPath = getRequiredStringArgument(args, ARG_FUNC_DEF_PATH);
					Optional<String> newReturnTypePathOpt = getOptionalStringArgument(args, ARG_NEW_RETURN_TYPE);
					Optional<List<Map<String, Object>>> newParamsListOpt = getOptionalListArgument(args, ARG_NEW_PARAMETERS);
					Optional<String> newCommentOpt = getOptionalStringArgument(args, ARG_COMMENT);
					Optional<String> newCallingConventionOpt = getOptionalStringArgument(args, ARG_NEW_CALLING_CONVENTION);
					boolean removeVarArgs = getOptionalBooleanArgument(args, ARG_REMOVE_VAR_ARGS).orElse(false);
					boolean addVarArgs = getOptionalBooleanArgument(args, ARG_ADD_VAR_ARGS).orElse(false);

					if (newReturnTypePathOpt.isEmpty() && newParamsListOpt.isEmpty() && newCommentOpt.isEmpty()
							&& newCallingConventionOpt.isEmpty() && !removeVarArgs && !addVarArgs) {
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
												"Include one of: newReturnType, newParameters, comment, newCallingConvention, addVarArgs, removeVarArgs",
												List.of("\"newReturnType\": \"int\"", "\"comment\": \"Updated function\""),
												null)))
								.build();
						throw new GhidraMcpException(error);
					}

					if (removeVarArgs && addVarArgs) {
						GhidraMcpError error = GhidraMcpError.validation()
								.errorCode(GhidraMcpError.ErrorCode.CONFLICTING_ARGUMENTS)
								.message("Cannot both add and remove varargs in the same operation.")
								.context(new GhidraMcpError.ErrorContext(
										annotation.mcpName(),
										"varargs validation",
										Map.of(ARG_ADD_VAR_ARGS, addVarArgs, ARG_REMOVE_VAR_ARGS, removeVarArgs),
										Map.of("conflictingFlags", true),
										Map.of("bothVarArgsFlags", true)))
								.suggestions(List.of(
										new GhidraMcpError.ErrorSuggestion(
												GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
												"Use only one varargs flag",
												"Set either addVarArgs or removeVarArgs, not both",
												List.of("\"addVarArgs\": true", "\"removeVarArgs\": true"),
												null)))
								.build();
						throw new GhidraMcpException(error);
					}

					DataType dt = program.getDataTypeManager().getDataType(funcDefPath);
					if (dt == null) {
						GhidraMcpError error = GhidraMcpError.resourceNotFound()
								.errorCode(GhidraMcpError.ErrorCode.DATA_TYPE_NOT_FOUND)
								.message("Function definition data type not found: " + funcDefPath)
								.context(new GhidraMcpError.ErrorContext(
										annotation.mcpName(),
										"function definition lookup",
										Map.of(ARG_FUNC_DEF_PATH, funcDefPath),
										Map.of("functionDefinitionPath", funcDefPath),
										Map.of("dataTypeExists", false)))
								.suggestions(List.of(
										new GhidraMcpError.ErrorSuggestion(
												GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
												"List available function definitions",
												"Check what function definitions exist",
												null,
												List.of(getMcpName(GhidraListDataTypesTool.class)))))
								.build();
						throw new GhidraMcpException(error);
					}
					if (!(dt instanceof FunctionDefinition)) {
						GhidraMcpError error = GhidraMcpError.validation()
								.errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
								.message("Data type '" + funcDefPath + "' is not a Function Definition.")
								.context(new GhidraMcpError.ErrorContext(
										annotation.mcpName(),
										"data type validation",
										Map.of(ARG_FUNC_DEF_PATH, funcDefPath),
										Map.of("functionDefinitionPath", funcDefPath, "actualDataType", dt.getDisplayName()),
										Map.of("isFunctionDefinition", false, "actualTypeName", dt.getClass().getSimpleName())))
								.suggestions(List.of(
										new GhidraMcpError.ErrorSuggestion(
												GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
												"Use a function definition data type",
												"Ensure the path points to a function definition, not " + dt.getClass().getSimpleName(),
												null,
												null)))
								.build();
						throw new GhidraMcpException(error);
					}
					FunctionDefinition funcDef = (FunctionDefinition) dt;

					// Resolve return type if provided
					Optional<DataType> newReturnTypeResolvedOpt = Optional.empty();
					if (newReturnTypePathOpt.isPresent()) {
						try {
							DataType returnDt = DataTypeUtils.parseDataTypeString(program, newReturnTypePathOpt.get(), tool);
							newReturnTypeResolvedOpt = Optional.of(returnDt);
						} catch (IllegalArgumentException e) {
							throw e;
						} catch (InvalidDataTypeException e) {
							GhidraMcpError error = GhidraMcpError.validation()
									.errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
									.message("Invalid return data type format '" + newReturnTypePathOpt.get() + "': " + e.getMessage())
									.context(new GhidraMcpError.ErrorContext(
											annotation.mcpName(),
											"return type format validation",
											Map.of(ARG_NEW_RETURN_TYPE, newReturnTypePathOpt.get()),
											Map.of("returnTypePath", newReturnTypePathOpt.get()),
											Map.of("formatError", e.getMessage())))
									.suggestions(List.of(
											new GhidraMcpError.ErrorSuggestion(
													GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
													"Check return type format",
													"Use correct data type path format",
													List.of("'int'", "'char *'", "'/MyStruct'"),
													null)))
									.build();
							throw new GhidraMcpException(error);
						} catch (CancelledException e) {
							throw new RuntimeException(
									"Return data type parsing cancelled for '" + newReturnTypePathOpt.get() + "': " + e.getMessage(), e);
						} catch (RuntimeException e) {
							throw new RuntimeException(
									"Unexpected runtime error during return type parsing for '" + newReturnTypePathOpt.get() + "': "
											+ e.getMessage(),
									e);
						}
					}

					// Resolve parameters if provided
					Optional<List<ParameterDefinition>> newParamsResolvedOpt = Optional.empty();
					if (newParamsListOpt.isPresent()) {
						List<ParameterDefinition> params = new ArrayList<>();
						for (Map<String, Object> paramMap : newParamsListOpt.get()) {
							String paramName = getRequiredStringArgument(paramMap, ARG_NAME);
							String paramTypeName = getRequiredStringArgument(paramMap, ARG_DATA_TYPE_PATH);
							String paramComment = getOptionalStringArgument(paramMap, ARG_COMMENT).orElse(null);

							try {
								DataType paramDt = DataTypeUtils.parseDataTypeString(program, paramTypeName, tool);
								params.add(new ParameterDefinitionImpl(paramName, paramDt, paramComment));
							} catch (IllegalArgumentException e) {
								throw e;
							} catch (InvalidDataTypeException e) {
								GhidraMcpError error = GhidraMcpError.validation()
										.errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
										.message("Invalid parameter data type format '" + paramTypeName + "': " + e.getMessage())
										.context(new GhidraMcpError.ErrorContext(
												annotation.mcpName(),
												"parameter type format validation",
												Map.of(ARG_DATA_TYPE_PATH, paramTypeName, ARG_NAME, paramName),
												Map.of("parameterTypePath", paramTypeName, "parameterName", paramName),
												Map.of("formatError", e.getMessage())))
										.suggestions(List.of(
												new GhidraMcpError.ErrorSuggestion(
														GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
														"Check parameter type format",
														"Use correct data type path format",
														List.of("'int'", "'char *'", "'/MyStruct'"),
														null)))
										.build();
								throw new GhidraMcpException(error);
							} catch (CancelledException e) {
								throw new RuntimeException(
										"Parameter data type parsing cancelled for '" + paramTypeName + "': " + e.getMessage(), e);
							} catch (RuntimeException e) {
								throw new RuntimeException(
										"Unexpected runtime error during parameter type parsing for '" + paramTypeName + "': "
												+ e.getMessage(),
										e);
							}
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
}