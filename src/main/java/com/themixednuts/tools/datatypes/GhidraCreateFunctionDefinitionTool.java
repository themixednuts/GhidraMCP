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
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.data.VoidDataType;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.exception.CancelledException;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Create Function Definition", mcpName = "create_function_definition", category = ToolCategory.DATATYPES, description = "Creates a new function definition data type.", mcpDescription = """
		<use_case>
		Create a function definition data type in Ghidra for documenting function signatures without implementations. Essential for defining API interfaces and function pointer types.
		</use_case>

		<important_notes>
		- Category path auto-created if it doesn't exist
		- Supports all calling conventions available in Ghidra (e.g., __stdcall, __cdecl)
		- Parameters defined with structured format including name and data type path
		- Return type defaults to 'void' if not specified
		- Supports variable arguments (varargs) and noreturn annotations
		</important_notes>

		<example>
		Create function definition:
		{
		  "fileName": "program.exe",
		  "name": "ApiFunction",
		  "path": "/WindowsAPI",
		  "returnTypePath": "int",
		  "parameters": [
		    {"name": "handle", "dataTypePath": "HANDLE"},
		    {"name": "buffer", "dataTypePath": "char *"}
		  ],
		  "callingConventionName": "__stdcall"
		}
		</example>

		<workflow>
		1. Validate function definition name doesn't already exist
		2. Create category path if needed
		3. Parse return type and parameter data types
		4. Create function definition with specified attributes
		5. Add to data type manager with proper categorization
		</workflow>
		""")
public class GhidraCreateFunctionDefinitionTool implements IGhidraMcpSpecification {

	protected static final String ARG_FD_RETURN_TYPE_PATH = "returnTypePath";
	protected static final String ARG_FD_PARAMETERS = "parameters";
	protected static final String ARG_FD_CALLING_CONVENTION_NAME = "callingConventionName";
	protected static final String ARG_FD_HAS_VAR_ARGS = "hasVarArgs";
	protected static final String ARG_FD_NO_RETURN = "noReturn";

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();

		schemaRoot.property(ARG_FILE_NAME, JsonSchemaBuilder.string(mapper)
				.description("The file name of the Ghidra tool window to target."), true);
		schemaRoot.property(ARG_NAME, JsonSchemaBuilder.string(mapper)
				.description("Name for the new function definition (e.g., MyFunctionDef)."), true);
		schemaRoot.property(ARG_PATH, JsonSchemaBuilder.string(mapper)
				.description(
						"Optional category path for the new function definition (e.g., /MyCategory). If omitted, uses default/root path."));
		schemaRoot.property(ARG_COMMENT, JsonSchemaBuilder.string(mapper)
				.description("Optional comment for the new function definition."));
		schemaRoot.property(ARG_FD_RETURN_TYPE_PATH, JsonSchemaBuilder.string(mapper)
				.description(
						"Data type path for the return type (e.g., 'void', 'int', '/MyStructs/Result'). Defaults to 'void' if not specified."));

		IObjectSchemaBuilder fdParamSchema = JsonSchemaBuilder.object(mapper)
				.description("Definition for a single function parameter.")
				.property(ARG_NAME, JsonSchemaBuilder.string(mapper).description("Parameter name."))
				.property(ARG_DATA_TYPE_PATH, JsonSchemaBuilder.string(mapper)
						.description("Data type path for the parameter (e.g., 'float *', '/MyEnums/Status')."))
				.property(ARG_COMMENT,
						JsonSchemaBuilder.string(mapper).description("Optional comment for the parameter."))
				.requiredProperty(ARG_NAME)
				.requiredProperty(ARG_DATA_TYPE_PATH);

		schemaRoot.property(ARG_FD_PARAMETERS, JsonSchemaBuilder.array(mapper)
				.description("Optional ordered list of parameters.")
				.items(fdParamSchema));
		schemaRoot.property(ARG_FD_CALLING_CONVENTION_NAME, JsonSchemaBuilder.string(mapper)
				.description(
						"Optional calling convention name (e.g., '__stdcall', 'default'). Defaults to program's default calling convention."));
		schemaRoot.property(ARG_FD_HAS_VAR_ARGS, JsonSchemaBuilder.bool(mapper)
				.description("Whether the function accepts variable arguments. Defaults to false.")
				.defaultValue(false));
		schemaRoot.property(ARG_FD_NO_RETURN, JsonSchemaBuilder.bool(mapper)
				.description("Whether the function has no return (annotated as noreturn). Defaults to false.")
				.defaultValue(false));

		schemaRoot.requiredProperty(ARG_FILE_NAME);
		schemaRoot.requiredProperty(ARG_NAME);

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool)
				.flatMap(program -> {
					String funcDefName = getRequiredStringArgument(args, ARG_NAME);
					Optional<String> pathOpt = getOptionalStringArgument(args, ARG_PATH);
					CategoryPath categoryPath = pathOpt.map(CategoryPath::new).orElse(CategoryPath.ROOT);
					String transactionName = "Create Function Definition: " + funcDefName;

					// All argument parsing for function definition happens inside the transaction
					// to ensure DataTypeManager is available for resolving type paths.
					return executeInTransaction(program, transactionName, () -> {
						return createFunctionDefinitionInternal(program, args, tool, funcDefName, categoryPath);
					});
				});
	}

	private String createFunctionDefinitionInternal(ghidra.program.model.listing.Program program,
			Map<String, Object> args,
			PluginTool tool,
			String funcDefName, CategoryPath categoryPath) {
		GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);

		DataTypeManager dtm = program.getDataTypeManager();
		ensureCategoryExists(dtm, categoryPath);

		if (dtm.getDataType(categoryPath, funcDefName) != null) {
			GhidraMcpError error = GhidraMcpError.validation()
					.errorCode(GhidraMcpError.ErrorCode.CONFLICTING_ARGUMENTS)
					.message("Data type already exists: " + categoryPath.getPath() + CategoryPath.DELIMITER_CHAR + funcDefName)
					.context(new GhidraMcpError.ErrorContext(
							annotation.mcpName(),
							"function definition creation",
							Map.of(ARG_NAME, funcDefName, ARG_PATH, categoryPath.getPath()),
							Map.of("proposedFunctionDefinitionPath",
									categoryPath.getPath() + CategoryPath.DELIMITER_CHAR + funcDefName),
							Map.of("dataTypeExists", true, "categoryPath", categoryPath.getPath(), "functionDefinitionName",
									funcDefName)))
					.suggestions(List.of(
							new GhidraMcpError.ErrorSuggestion(
									GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
									"Choose a different function definition name",
									"Use a unique name for the function definition",
									null,
									null),
							new GhidraMcpError.ErrorSuggestion(
									GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
									"Check existing data types",
									"List existing data types to avoid conflicts",
									null,
									List.of(getMcpName(GhidraListDataTypesTool.class)))))
					.build();
			throw new GhidraMcpException(error);
		}

		Optional<String> commentOpt = getOptionalStringArgument(args, ARG_COMMENT);
		String returnTypePath = getOptionalStringArgument(args, ARG_FD_RETURN_TYPE_PATH)
				.orElse(VoidDataType.dataType.getPathName()); // Default to void
		DataType returnDt;
		try {
			returnDt = DataTypeUtils.parseDataTypeString(program, returnTypePath, tool);
		} catch (IllegalArgumentException e) {
			GhidraMcpError error = GhidraMcpError.resourceNotFound()
					.errorCode(GhidraMcpError.ErrorCode.DATA_TYPE_NOT_FOUND)
					.message("Return data type not found or invalid for FUNCTION_DEFINITION: '" + returnTypePath + "'. "
							+ e.getMessage())
					.context(new GhidraMcpError.ErrorContext(
							annotation.mcpName(),
							"return type parsing",
							Map.of(ARG_FD_RETURN_TYPE_PATH, returnTypePath),
							Map.of("returnTypePath", returnTypePath),
							Map.of("parseError", e.getMessage())))
					.suggestions(List.of(
							new GhidraMcpError.ErrorSuggestion(
									GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
									"Check return data type path",
									"Verify the return data type exists",
									List.of("'void'", "'int'", "'/MyStructs/Result'"),
									null),
							new GhidraMcpError.ErrorSuggestion(
									GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
									"List available data types",
									"See what data types are available",
									null,
									List.of(getMcpName(GhidraListDataTypesTool.class)))))
					.build();
			throw new GhidraMcpException(error);
		} catch (InvalidDataTypeException e) {
			GhidraMcpError error = GhidraMcpError.validation()
					.errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
					.message(
							"Invalid return data type format for FUNCTION_DEFINITION: '" + returnTypePath + "'. " + e.getMessage())
					.context(new GhidraMcpError.ErrorContext(
							annotation.mcpName(),
							"return type format validation",
							Map.of(ARG_FD_RETURN_TYPE_PATH, returnTypePath),
							Map.of("returnTypePath", returnTypePath),
							Map.of("formatError", e.getMessage())))
					.suggestions(List.of(
							new GhidraMcpError.ErrorSuggestion(
									GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
									"Check return data type format",
									"Use correct data type path format",
									List.of("'void'", "'int'", "'/MyCategory/MyStruct'"),
									null)))
					.build();
			throw new GhidraMcpException(error);
		} catch (CancelledException e) {
			throw new RuntimeException("Parsing cancelled for return data type '" + returnTypePath + "'.", e);
		} catch (RuntimeException e) {
			throw new RuntimeException(
					"Unexpected error parsing return data type '" + returnTypePath + "': " + e.getMessage(), e);
		}

		List<ParameterDefinition> paramDefs = new ArrayList<>();
		Optional<List<Map<String, Object>>> paramsListOpt = getOptionalListArgument(args, ARG_FD_PARAMETERS);
		if (paramsListOpt.isPresent()) {
			for (Map<String, Object> paramMap : paramsListOpt.get()) {
				String paramName = getRequiredStringArgument(paramMap, ARG_NAME);
				String paramDtPath = getRequiredStringArgument(paramMap, ARG_DATA_TYPE_PATH);
				Optional<String> paramCommentOpt = getOptionalStringArgument(paramMap, ARG_COMMENT);
				DataType paramDt;
				try {
					paramDt = DataTypeUtils.parseDataTypeString(program, paramDtPath, tool);
				} catch (IllegalArgumentException e) {
					GhidraMcpError error = GhidraMcpError.resourceNotFound()
							.errorCode(GhidraMcpError.ErrorCode.DATA_TYPE_NOT_FOUND)
							.message("Parameter data type '" + paramDtPath + "' not found or invalid for parameter '" + paramName
									+ "'. " + e.getMessage())
							.context(new GhidraMcpError.ErrorContext(
									annotation.mcpName(),
									"parameter type parsing",
									Map.of("parameterName", paramName, ARG_DATA_TYPE_PATH, paramDtPath),
									Map.of("parameterDataTypePath", paramDtPath, "parameterName", paramName),
									Map.of("parseError", e.getMessage())))
							.suggestions(List.of(
									new GhidraMcpError.ErrorSuggestion(
											GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
											"Check parameter data type path",
											"Verify the parameter data type exists",
											List.of("'float *'", "'/MyEnums/Status'", "'int'"),
											null),
									new GhidraMcpError.ErrorSuggestion(
											GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
											"List available data types",
											"See what data types are available",
											null,
											List.of(getMcpName(GhidraListDataTypesTool.class)))))
							.build();
					throw new GhidraMcpException(error);
				} catch (InvalidDataTypeException e) {
					GhidraMcpError error = GhidraMcpError.validation()
							.errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
							.message("Invalid parameter data type format for '" + paramDtPath + "' for parameter '" + paramName
									+ "'. " + e.getMessage())
							.context(new GhidraMcpError.ErrorContext(
									annotation.mcpName(),
									"parameter type format validation",
									Map.of("parameterName", paramName, ARG_DATA_TYPE_PATH, paramDtPath),
									Map.of("parameterDataTypePath", paramDtPath, "parameterName", paramName),
									Map.of("formatError", e.getMessage())))
							.suggestions(List.of(
									new GhidraMcpError.ErrorSuggestion(
											GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
											"Check parameter data type format",
											"Use correct data type path format",
											List.of("'float *'", "'int'", "'/MyCategory/MyStruct'"),
											null)))
							.build();
					throw new GhidraMcpException(error);
				} catch (CancelledException e) {
					throw new RuntimeException(
							"Parsing cancelled for parameter data type '" + paramDtPath + "' for parameter '" + paramName + "'.",
							e);
				} catch (RuntimeException e) {
					throw new RuntimeException("Unexpected error parsing parameter data type '" + paramDtPath
							+ "' for parameter '" + paramName + "': " + e.getMessage(), e);
				}
				paramDefs.add(new ParameterDefinitionImpl(paramName, paramDt, paramCommentOpt.orElse(null)));
			}
		}

		String callingConvention = getOptionalStringArgument(args, ARG_FD_CALLING_CONVENTION_NAME)
				.orElse(program.getCompilerSpec().getDefaultCallingConvention().getName());
		boolean hasVarArgs = getOptionalBooleanArgument(args, ARG_FD_HAS_VAR_ARGS).orElse(false);
		boolean noReturn = getOptionalBooleanArgument(args, ARG_FD_NO_RETURN).orElse(false);

		FunctionDefinitionDataType newFuncDef = new FunctionDefinitionDataType(categoryPath, funcDefName, dtm);
		newFuncDef.setReturnType(returnDt);
		newFuncDef.setArguments(paramDefs.toArray(new ParameterDefinition[0]));
		try {
			newFuncDef.setCallingConvention(callingConvention);
		} catch (InvalidInputException e) {
			throw new RuntimeException("Invalid calling convention name '" + callingConvention + "': " + e.getMessage(), e);
		}
		newFuncDef.setVarArgs(hasVarArgs);
		newFuncDef.setNoReturn(noReturn);

		DataType newDt = dtm.addDataType(newFuncDef, DataTypeConflictHandler.REPLACE_HANDLER);
		if (newDt == null) {
			throw new RuntimeException("Failed to add function definition '" + funcDefName + "' to data type manager.");
		}
		commentOpt.ifPresent(comment -> newDt.setDescription(comment));
		return "Function Definition '" + newDt.getPathName() + "' created.";
	}

	private static void ensureCategoryExists(DataTypeManager dtm, CategoryPath categoryPath) {
		if (categoryPath == null || categoryPath.equals(CategoryPath.ROOT)) {
			return;
		}
		if (dtm.getCategory(categoryPath) == null) {
			ghidra.program.model.data.Category created = dtm.createCategory(categoryPath);
			if (created == null) {
				// Attempt to re-fetch in case of race condition
				if (dtm.getCategory(categoryPath) == null) {
					throw new RuntimeException("Failed to create or find category: " + categoryPath.getPath());
				}
			}
		}
	}
}