package com.themixednuts.tools.functions;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.StreamSupport;
import java.util.stream.Collectors;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.utils.GhidraMcpTaskMonitor;
import com.themixednuts.utils.DataTypeUtils;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;
import com.themixednuts.tools.ToolCategory;

import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.services.DataTypeQueryService;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.util.exception.CancelledException;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Update Function Prototype", category = ToolCategory.FUNCTIONS, description = "Updates the prototype (signature) of an existing function using structured components.", mcpName = "update_function_prototype", mcpDescription = """
		<use_case>
		Update a function's signature by specifying structured components rather than raw prototype strings. Modifies return type, calling convention, parameters, and name using individual fields.
		</use_case>

		<important_notes>
		- Function identified by Symbol ID (preferred), address, or name
		- Uses structured parameter format with name and dataType fields
		- Supports pointer notation and full data type paths
		- Changes immediately affect decompiler output
		</important_notes>

		<example>
		To update a function signature: provide function address, return type "int", parameters array with name/dataType pairs, and optional calling convention.
		</example>

		<workflow>
		1. Identify target function using provided identifiers
		2. Parse and validate structured components (return type, parameters, etc.)
		3. Build proper C-style prototype from components
		4. Apply updated signature to function
		</workflow>
		""")
public class GhidraUpdateFunctionPrototypeTool implements IGhidraMcpSpecification {

	public static final String ARG_RETURN_TYPE = "returnType";
	public static final String ARG_CALLING_CONVENTION = "callingConvention";
	public static final String ARG_NEW_FUNCTION_NAME = "newFunctionName";
	public static final String ARG_PARAMETERS = "parameters";
	public static final String ARG_NO_RETURN = "noReturn";

	// Parameter field constants
	public static final String ARG_PARAM_NAME = "name";
	public static final String ARG_PARAM_DATA_TYPE = "dataType";

	/**
	 * Helper method to get MCP tool name from annotation for error suggestions.
	 */
	private String getRelatedToolMcpName(Class<? extends IGhidraMcpSpecification> toolClass) {
		GhidraMcpTool annotation = toolClass.getAnnotation(GhidraMcpTool.class);
		return annotation != null ? annotation.mcpName() : toolClass.getSimpleName();
	}

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file."));

		// Function identification
		schemaRoot.property(ARG_FUNCTION_SYMBOL_ID,
				JsonSchemaBuilder.integer(mapper)
						.description("The Symbol ID of the function. Preferred identifier."))
				.property(ARG_ADDRESS,
						JsonSchemaBuilder.string(mapper)
								.description("The entry point address of the function. Used if Symbol ID is not provided.")
								.pattern("^(0x)?[0-9a-fA-F]+$"))
				.property(ARG_FUNCTION_NAME,
						JsonSchemaBuilder.string(mapper)
								.description("The name of the function. Used if Symbol ID and Address are not provided."));

		// Prototype components
		schemaRoot.property(ARG_RETURN_TYPE,
				JsonSchemaBuilder.string(mapper)
						.description(
								"The return data type name. Supports full paths and simple names. Example: 'int', 'DWORD', '/MyTypes/CustomStruct'."));

		List<String> standardCallingConventions = List.of(
				CompilerSpec.CALLING_CONVENTION_cdecl,
				CompilerSpec.CALLING_CONVENTION_stdcall,
				CompilerSpec.CALLING_CONVENTION_fastcall,
				CompilerSpec.CALLING_CONVENTION_thiscall,
				CompilerSpec.CALLING_CONVENTION_pascal,
				CompilerSpec.CALLING_CONVENTION_vectorcall,
				CompilerSpec.CALLING_CONVENTION_rustcall);

		schemaRoot.property(ARG_CALLING_CONVENTION,
				JsonSchemaBuilder.string(mapper)
						.description("Optional calling convention prefix.")
						.enumValues(standardCallingConventions));

		schemaRoot.property(ARG_NEW_FUNCTION_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("Optional new name for the function. If not provided, keeps current name."));

		schemaRoot.property(ARG_NO_RETURN,
				JsonSchemaBuilder.bool(mapper)
						.description(
								"Optional flag to indicate whether the function has no return (noreturn annotation). Defaults to false.")
						.defaultValue(false));

		// Parameters array schema
		IObjectSchemaBuilder parameterItemSchema = JsonSchemaBuilder.object(mapper)
				.property(ARG_PARAM_NAME, JsonSchemaBuilder.string(mapper)
						.description("The parameter name."), true)
				.property(ARG_PARAM_DATA_TYPE, JsonSchemaBuilder.string(mapper)
						.description(
								"The parameter data type. Supports full paths, simple names, and pointer notation. Use '...' for variadic parameters."),
						true);

		schemaRoot.property(ARG_PARAMETERS,
				JsonSchemaBuilder.array(mapper)
						.items(parameterItemSchema)
						.description("Array of parameter objects, each with '" + ARG_PARAM_NAME + "' and '" + ARG_PARAM_DATA_TYPE
								+ "' fields. Order matters for function signature."));

		schemaRoot.requiredProperty(ARG_FILE_NAME)
				.requiredProperty(ARG_RETURN_TYPE);

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);

		return getProgram(args, tool).map(program -> {
			Optional<Long> funcSymbolIdOpt = getOptionalLongArgument(args, ARG_FUNCTION_SYMBOL_ID);
			Optional<String> funcAddressOpt = getOptionalStringArgument(args, ARG_ADDRESS);
			Optional<String> funcNameOpt = getOptionalStringArgument(args, ARG_FUNCTION_NAME);

			String returnTypeName = getRequiredStringArgument(args, ARG_RETURN_TYPE);
			Optional<String> callingConventionOpt = getOptionalStringArgument(args, ARG_CALLING_CONVENTION);
			Optional<String> newFunctionNameOpt = getOptionalStringArgument(args, ARG_NEW_FUNCTION_NAME);
			Optional<List<Map<String, Object>>> parametersOpt = getOptionalListArgument(args, ARG_PARAMETERS);
			boolean noReturn = getOptionalBooleanArgument(args, ARG_NO_RETURN).orElse(false);

			// Check if at least one function identifier is provided
			if (funcSymbolIdOpt.isEmpty() && funcAddressOpt.isEmpty() && funcNameOpt.isEmpty()) {
				Map<String, Object> providedIdentifiers = Map.of(
						ARG_FUNCTION_SYMBOL_ID, "not provided",
						ARG_ADDRESS, "not provided",
						ARG_FUNCTION_NAME, "not provided");

				GhidraMcpError error = GhidraMcpError.validation()
						.errorCode(GhidraMcpError.ErrorCode.MISSING_REQUIRED_ARGUMENT)
						.message("At least one function identifier must be provided")
						.context(new GhidraMcpError.ErrorContext(
								annotation.mcpName(),
								"function identifier validation",
								args,
								providedIdentifiers,
								Map.of("identifiersProvided", 0, "minimumRequired", 1)))
						.suggestions(List.of(
								new GhidraMcpError.ErrorSuggestion(
										GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
										"Provide at least one function identifier",
										"Include at least one of: " + ARG_FUNCTION_SYMBOL_ID + ", " + ARG_ADDRESS + ", or "
												+ ARG_FUNCTION_NAME,
										List.of(
												"\"" + ARG_FUNCTION_SYMBOL_ID + "\": 12345",
												"\"" + ARG_ADDRESS + "\": \"0x401000\"",
												"\"" + ARG_FUNCTION_NAME + "\": \"main\""),
										null)))
						.build();
				throw new GhidraMcpException(error);
			}

			return resolveFunction(program, funcSymbolIdOpt, funcAddressOpt, funcNameOpt, returnTypeName,
					callingConventionOpt, newFunctionNameOpt, parametersOpt, noReturn, tool);

		}).flatMap(context -> {
			Function functionToUpdate = context.function();
			String prototypeStr = context.prototypeString();
			Program program = context.program();

			return executeInTransaction(program,
					"MCP - Update Function Prototype: " + functionToUpdate.getName(),
					() -> {
						try {
							DataTypeManager dtm = program.getDataTypeManager();
							DataTypeQueryService service = tool.getService(DataTypeQueryService.class);
							FunctionSignatureParser parser = new FunctionSignatureParser(dtm, service);
							FunctionDefinitionDataType parsedSignature = parser.parse(functionToUpdate.getSignature(), prototypeStr);

							ApplyFunctionSignatureCmd cmd = new ApplyFunctionSignatureCmd(
									functionToUpdate.getEntryPoint(),
									parsedSignature,
									SourceType.USER_DEFINED);

							GhidraMcpTaskMonitor mcpMonitor = new GhidraMcpTaskMonitor(ex, this.getClass().getSimpleName());
							if (!cmd.applyTo(program, mcpMonitor)) {
								String cmdStatus = cmd.getStatusMsg() != null ? cmd.getStatusMsg() : "Unknown error";
								GhidraMcpError error = GhidraMcpError.execution()
										.errorCode(GhidraMcpError.ErrorCode.TRANSACTION_FAILED)
										.message("Failed to apply function prototype: " + cmdStatus)
										.context(new GhidraMcpError.ErrorContext(
												annotation.mcpName(),
												"function prototype update command",
												Map.of("builtPrototype", prototypeStr, ARG_FUNCTION_NAME, functionToUpdate.getName()),
												Map.of("commandStatus", cmdStatus),
												Map.of("commandSuccess", false, "prototypeValid", true)))
										.suggestions(List.of(
												new GhidraMcpError.ErrorSuggestion(
														GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
														"Verify prototype components and data types",
														"Ensure all data types in the components are defined in the program",
														null,
														null),
												new GhidraMcpError.ErrorSuggestion(
														GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
														"Check component specifications",
														"Verify return type and parameter data types are valid",
														List.of(
																"Return type: 'int', 'void', 'DWORD'",
																"Parameter types: 'int', 'char*', 'LPVOID'"),
														null)))
										.build();
								throw new GhidraMcpException(error);
							}

							return Map.of(
									"message", "Function prototype updated successfully for " + functionToUpdate.getName(),
									"builtPrototype", prototypeStr,
									"functionName", functionToUpdate.getName());
						} catch (Exception e) {
							if (e instanceof GhidraMcpException) {
								throw e; // Re-throw structured errors
							}
							// Handle prototype parsing errors
							GhidraMcpError error = GhidraMcpError.validation()
									.errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
									.message("Failed to parse constructed function prototype: " + e.getMessage())
									.context(new GhidraMcpError.ErrorContext(
											annotation.mcpName(),
											"prototype construction and parsing",
											Map.of("builtPrototype", prototypeStr),
											Map.of("parseError", e.getMessage()),
											Map.of("prototypeSyntax", false)))
									.suggestions(List.of(
											new GhidraMcpError.ErrorSuggestion(
													GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
													"Check component data types",
													"Ensure all specified data types are valid and available",
													null,
													null)))
									.build();
							throw new GhidraMcpException(error);
						}
					});
		});
	}

	private static record UpdatePrototypeContext(Program program, Function function, String prototypeString) {
	}

	// Helper method to resolve function and build prototype string
	private UpdatePrototypeContext resolveFunction(Program program, Optional<Long> funcSymbolIdOpt,
			Optional<String> funcAddressOpt, Optional<String> funcNameOpt, String returnTypeName,
			Optional<String> callingConventionOpt, Optional<String> newFunctionNameOpt,
			Optional<List<Map<String, Object>>> parametersOpt, boolean noReturn, PluginTool tool) {
		GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
		FunctionManager funcMan = program.getFunctionManager();
		SymbolTable symbolTable = program.getSymbolTable();
		Function function = null;

		// Try to find function by symbol ID first
		if (funcSymbolIdOpt.isPresent()) {
			long symId = funcSymbolIdOpt.get();
			Symbol symbol = symbolTable.getSymbol(symId);
			if (symbol != null && symbol.getSymbolType() == SymbolType.FUNCTION) {
				function = funcMan.getFunctionAt(symbol.getAddress());
			}
		}

		// Try to find function by address if not found by symbol ID
		if (function == null && funcAddressOpt.isPresent()) {
			String addressString = funcAddressOpt.get();
			try {
				Address entryPointAddress = program.getAddressFactory().getAddress(addressString);
				if (entryPointAddress != null) {
					function = funcMan.getFunctionAt(entryPointAddress);
				} else {
					// Only throw error if this is the only identifier provided
					if (funcNameOpt.isEmpty() && funcSymbolIdOpt.isEmpty()) {
						GhidraMcpError error = GhidraMcpError.validation()
								.errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
								.message("Invalid address format")
								.context(new GhidraMcpError.ErrorContext(
										annotation.mcpName(),
										"address parsing",
										Map.of(ARG_ADDRESS, addressString),
										Map.of(ARG_ADDRESS, addressString),
										Map.of("expectedFormat", "hexadecimal address", "providedValue", addressString)))
								.suggestions(List.of(
										new GhidraMcpError.ErrorSuggestion(
												GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
												"Use valid hexadecimal address format",
												"Provide address as hexadecimal value",
												List.of("0x401000", "401000", "0x00401000"),
												null)))
								.build();
						throw new GhidraMcpException(error);
					}
				}
			} catch (Exception e) {
				if (e instanceof GhidraMcpException) {
					throw e; // Re-throw structured error
				}
				// Only throw error if this is the only identifier provided
				if (funcNameOpt.isEmpty() && funcSymbolIdOpt.isEmpty()) {
					GhidraMcpError error = GhidraMcpError.validation()
							.errorCode(GhidraMcpError.ErrorCode.ADDRESS_PARSE_FAILED)
							.message("Failed to parse address: " + e.getMessage())
							.context(new GhidraMcpError.ErrorContext(
									annotation.mcpName(),
									"address parsing",
									Map.of(ARG_ADDRESS, addressString),
									Map.of(ARG_ADDRESS, addressString),
									Map.of("parseError", e.getMessage(), "providedValue", addressString)))
							.suggestions(List.of(
									new GhidraMcpError.ErrorSuggestion(
											GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
											"Use valid address format for the current program",
											"Ensure address exists in the program's address space",
											List.of("0x401000", "401000"),
											null)))
							.build();
					throw new GhidraMcpException(error);
				}
			}
		}

		// Try to find function by name if not found by other methods
		if (function == null && funcNameOpt.isPresent()) {
			String functionName = funcNameOpt.get();
			function = StreamSupport.stream(funcMan.getFunctions(true).spliterator(), false)
					.filter(f -> f.getName(true).equals(functionName))
					.findFirst()
					.orElse(null);
		}

		// If still not found, create structured error
		if (function == null) {
			Map<String, Object> searchCriteria = Map.of(
					ARG_FUNCTION_SYMBOL_ID, funcSymbolIdOpt.map(Object::toString).orElse("not provided"),
					ARG_ADDRESS, funcAddressOpt.orElse("not provided"),
					ARG_FUNCTION_NAME, funcNameOpt.orElse("not provided"));

			GhidraMcpError error = GhidraMcpError.resourceNotFound()
					.errorCode(GhidraMcpError.ErrorCode.FUNCTION_NOT_FOUND)
					.message("Function not found using any of the provided identifiers")
					.context(new GhidraMcpError.ErrorContext(
							annotation.mcpName(),
							"function lookup",
							Map.of(ARG_RETURN_TYPE, returnTypeName),
							searchCriteria,
							Map.of("searchAttempted", true, "functionFound", false)))
					.suggestions(List.of(
							new GhidraMcpError.ErrorSuggestion(
									GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
									"Verify the function exists with provided identifiers",
									"Use function listing tools to verify function existence",
									null,
									List.of(getRelatedToolMcpName(com.themixednuts.tools.functions.GhidraListFunctionNamesTool.class))),
							new GhidraMcpError.ErrorSuggestion(
									GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
									"Double-check identifier values",
									"Ensure symbol ID, address, or name are correct and current",
									null,
									null)))
					.build();
			throw new GhidraMcpException(error);
		}

		// Build the prototype string from components
		String prototypeString = buildPrototypeString(program, tool, returnTypeName, callingConventionOpt,
				newFunctionNameOpt.orElse(function.getName()), parametersOpt, noReturn);

		return new UpdatePrototypeContext(program, function, prototypeString);
	}

	// Helper method to build the prototype string from components
	private String buildPrototypeString(Program program, PluginTool tool, String returnTypeName,
			Optional<String> callingConventionOpt, String functionName, Optional<List<Map<String, Object>>> parametersOpt,
			boolean noReturn) {
		GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
		StringBuilder prototype = new StringBuilder();

		// Parse and get base name for return type
		try {
			DataType returnType = DataTypeUtils.parseDataTypeString(program, returnTypeName, tool);
			String returnTypeBaseName = returnType.getName();

			// If noReturn is true, we still use the specified return type but mark function
			// appropriately
			// The noReturn flag will be handled during function signature application
			prototype.append(returnTypeBaseName);
		} catch (InvalidDataTypeException | CancelledException e) {
			GhidraMcpError error = GhidraMcpError.dataTypeParsing()
					.errorCode(GhidraMcpError.ErrorCode.INVALID_TYPE_PATH)
					.message("Invalid return type: " + e.getMessage())
					.context(new GhidraMcpError.ErrorContext(
							annotation.mcpName(),
							"return type parsing",
							Map.of(ARG_RETURN_TYPE, returnTypeName),
							Map.of(ARG_RETURN_TYPE, returnTypeName),
							Map.of("parseError", e.getMessage())))
					.suggestions(List.of(
							new GhidraMcpError.ErrorSuggestion(
									GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
									"Check return type specification",
									"Ensure the return type is valid and available in the program",
									List.of("int", "void", "DWORD", "char*"),
									null)))
					.build();
			throw new GhidraMcpException(error);
		}

		// Add calling convention if provided
		callingConventionOpt.ifPresent(cc -> prototype.append(" ").append(cc));

		// Add function name
		prototype.append(" ").append(functionName).append("(");

		// Add parameters
		if (parametersOpt.isPresent() && !parametersOpt.get().isEmpty()) {
			List<String> paramStrings = parametersOpt.get().stream()
					.map(paramMap -> {
						String paramName = (String) paramMap.get(ARG_PARAM_NAME);
						String paramDataType = (String) paramMap.get(ARG_PARAM_DATA_TYPE);

						if (paramName == null || paramDataType == null) {
							GhidraMcpError error = GhidraMcpError.validation()
									.errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
									.message("Parameter must have both '" + ARG_PARAM_NAME + "' and '" + ARG_PARAM_DATA_TYPE + "' fields")
									.context(new GhidraMcpError.ErrorContext(
											annotation.mcpName(),
											"parameter validation",
											Map.of("parameter", paramMap),
											Map.of("hasName", paramName != null, "hasDataType", paramDataType != null),
											Map.of("parameterValid", false)))
									.suggestions(List.of(
											new GhidraMcpError.ErrorSuggestion(
													GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
													"Provide complete parameter objects",
													"Each parameter must have '" + ARG_PARAM_NAME + "' and '" + ARG_PARAM_DATA_TYPE + "' fields",
													List.of("{\"" + ARG_PARAM_NAME + "\": \"param1\", \"" + ARG_PARAM_DATA_TYPE + "\": \"int\"}"),
													null)))
									.build();
							throw new GhidraMcpException(error);
						}

						// Handle variadic parameters
						if ("...".equals(paramDataType)) {
							return "...";
						}

						// Parse parameter data type and get base name
						try {
							DataType paramType = DataTypeUtils.parseDataTypeString(program, paramDataType, tool);
							String paramTypeBaseName = paramType.getName();
							return paramTypeBaseName + " " + paramName;
						} catch (InvalidDataTypeException | CancelledException e) {
							GhidraMcpError error = GhidraMcpError.dataTypeParsing()
									.errorCode(GhidraMcpError.ErrorCode.INVALID_TYPE_PATH)
									.message("Invalid parameter data type '" + paramDataType + "': " + e.getMessage())
									.context(new GhidraMcpError.ErrorContext(
											annotation.mcpName(),
											"parameter data type parsing",
											Map.of("parameterName", paramName, "parameterDataType", paramDataType),
											Map.of("parameterDataType", paramDataType),
											Map.of("parseError", e.getMessage())))
									.suggestions(List.of(
											new GhidraMcpError.ErrorSuggestion(
													GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
													"Check parameter data type specification",
													"Ensure the parameter type is valid and available in the program",
													List.of("int", "char*", "LPVOID", "DWORD"),
													null)))
									.build();
							throw new GhidraMcpException(error);
						}
					})
					.collect(Collectors.toList());

			prototype.append(String.join(", ", paramStrings));
		}

		prototype.append(")");

		return prototype.toString();
	}
}
