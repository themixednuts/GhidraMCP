package com.themixednuts.tools.decompiler;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import com.themixednuts.utils.GhidraMcpTaskMonitor;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;
import reactor.util.function.Tuples;

import com.themixednuts.tools.ToolCategory;
import com.themixednuts.tools.functions.GhidraListFunctionNamesTool;
import com.themixednuts.tools.memory.GhidraGetAssemblyAtAddressTool;
import com.themixednuts.tools.projectmanagement.GhidraTriggerAutoAnalysisTool;

@GhidraMcpTool(name = "Decompile Function", category = ToolCategory.DECOMPILER, description = "Decompiles a function given its name or address and returns the C code representation.", mcpName = "decompile_function", mcpDescription = """
		<use_case>
		Decompile assembly code to readable C-like pseudocode using Ghidra's advanced decompiler engine. Essential for understanding function logic and reverse engineering program behavior.
		</use_case>

		<important_notes>
		- Requires either function name OR function address (not both)
		- Uses sophisticated analysis to reconstruct high-level code structures
		- Quality depends on function prototype accuracy and data type definitions
		- Complex functions may require significant processing time (180s timeout)
		</important_notes>

		<example>
		Decompile main function:
		{
		  "fileName": "program.exe",
		  "functionName": "main"
		}

		Decompile by address:
		{
		  "fileName": "malware.dll",
		  "functionAddress": "0x401000"
		}
		</example>

		<workflow>
		1. Ensure function boundaries are correctly defined
		2. Update function prototype and variable types for better output
		3. Use decompile_function to generate C pseudocode
		4. Review output quality and refine data types if needed
		</workflow>
		""")
public class GhidraDecompileFunctionTool implements IGhidraMcpSpecification {

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file."));
		schemaRoot.property(ARG_FUNCTION_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the function to decompile (provide name or address)."));
		schemaRoot.property(ARG_FUNCTION_ADDRESS,
				JsonSchemaBuilder.string(mapper)
						.description("The address of the function to decompile (provide name or address)."));

		schemaRoot.requiredProperty(ARG_FILE_NAME);

		return schemaRoot.build();
	}

	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		DecompInterface decomp = new DecompInterface();

		return getProgram(args, tool).map(program -> {
			String functionName = getOptionalStringArgument(args, ARG_FUNCTION_NAME).orElse(null);
			String functionAddressStr = getOptionalStringArgument(args, ARG_FUNCTION_ADDRESS).orElse(null);
			final String toolMcpName = getMcpName();

			Function targetFunction;

			// Validate that exactly one identifier is provided
			boolean hasName = functionName != null && !functionName.isEmpty();
			boolean hasAddress = functionAddressStr != null && !functionAddressStr.isEmpty();

			if (hasName && hasAddress) {
				GhidraMcpError error = GhidraMcpError.validation()
						.errorCode(GhidraMcpError.ErrorCode.CONFLICTING_ARGUMENTS)
						.message("Cannot provide both function name and address")
						.context(new GhidraMcpError.ErrorContext(
								toolMcpName,
								"function identifier validation",
								args,
								Map.of(
										ARG_FUNCTION_NAME, functionName,
										ARG_FUNCTION_ADDRESS, functionAddressStr),
								Map.of("conflictingArguments", List.of(ARG_FUNCTION_NAME, ARG_FUNCTION_ADDRESS))))
						.suggestions(List.of(
								new GhidraMcpError.ErrorSuggestion(
										GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
										"Provide only one identifier",
										"Include either function name OR address, not both",
										List.of(
												"\"" + ARG_FUNCTION_NAME + "\": \"main\"",
												"\"" + ARG_FUNCTION_ADDRESS + "\": \"0x401000\""),
										null)))
						.build();
				throw new GhidraMcpException(error);
			}

			if (!hasName && !hasAddress) {
				GhidraMcpError error = GhidraMcpError.validation()
						.errorCode(GhidraMcpError.ErrorCode.MISSING_REQUIRED_ARGUMENT)
						.message("Either function name or address must be provided")
						.context(new GhidraMcpError.ErrorContext(
								toolMcpName,
								"function identifier validation",
								args,
								Map.of(
										ARG_FUNCTION_NAME, "not provided",
										ARG_FUNCTION_ADDRESS, "not provided"),
								Map.of("identifiersProvided", 0, "minimumRequired", 1)))
						.suggestions(List.of(
								new GhidraMcpError.ErrorSuggestion(
										GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
										"Provide a function identifier",
										"Include either function name or address",
										List.of(
												"\"" + ARG_FUNCTION_NAME + "\": \"main\"",
												"\"" + ARG_FUNCTION_ADDRESS + "\": \"0x401000\""),
										null)))
						.build();
				throw new GhidraMcpException(error);
			}

			if (hasName) {
				targetFunction = StreamSupport
						.stream(program.getFunctionManager().getFunctions(true).spliterator(), false)
						.filter(f -> f.getName().equals(functionName))
						.findFirst()
						.orElse(null);
				if (targetFunction == null) {
					List<String> availableFunctions = StreamSupport
							.stream(program.getFunctionManager().getFunctions(true).spliterator(), false)
							.map(f -> f.getName())
							.sorted()
							.limit(50)
							.collect(Collectors.toList());

					GhidraMcpError error = GhidraMcpError.resourceNotFound()
							.errorCode(GhidraMcpError.ErrorCode.FUNCTION_NOT_FOUND)
							.message("Function not found: " + functionName)
							.context(new GhidraMcpError.ErrorContext(
									toolMcpName,
									"function lookup by name",
									args,
									Map.of(ARG_FUNCTION_NAME, functionName),
									Map.of(
											"programName", program.getDomainFile().getName(),
											"totalFunctions", program.getFunctionManager().getFunctionCount())))
							.suggestions(List.of(
									new GhidraMcpError.ErrorSuggestion(
											GhidraMcpError.ErrorSuggestion.SuggestionType.SIMILAR_VALUES,
											"Check available functions",
											"Use list_function_names to see all available functions",
											availableFunctions.subList(0, Math.min(10, availableFunctions.size())),
											List.of(getMcpName(GhidraListFunctionNamesTool.class)))))
							.relatedResources(availableFunctions)
							.build();
					throw new GhidraMcpException(error);
				}
			} else {
				Address address;
				try {
					address = program.getAddressFactory().getAddress(functionAddressStr);
				} catch (Exception e) {
					GhidraMcpError error = GhidraMcpError.execution()
							.errorCode(GhidraMcpError.ErrorCode.ADDRESS_PARSE_FAILED)
							.message("Invalid address format: " + functionAddressStr)
							.context(new GhidraMcpError.ErrorContext(
									toolMcpName,
									"address parsing",
									args,
									Map.of(ARG_FUNCTION_ADDRESS, functionAddressStr),
									Map.of("parseError", e.getMessage())))
							.suggestions(List.of(
									new GhidraMcpError.ErrorSuggestion(
											GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
											"Use valid address format",
											"Provide address in hexadecimal format",
											List.of("0x401000", "0x00401000", "401000"),
											null)))
							.build();
					throw new GhidraMcpException(error);
				}

				if (address == null) {
					GhidraMcpError error = GhidraMcpError.execution()
							.errorCode(GhidraMcpError.ErrorCode.ADDRESS_PARSE_FAILED)
							.message("Invalid address format: " + functionAddressStr)
							.context(new GhidraMcpError.ErrorContext(
									toolMcpName,
									"address parsing",
									args,
									Map.of(ARG_FUNCTION_ADDRESS, functionAddressStr),
									Map.of("addressResult", "null")))
							.suggestions(List.of(
									new GhidraMcpError.ErrorSuggestion(
											GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
											"Use valid address format",
											"Provide address in hexadecimal format",
											List.of("0x401000", "0x00401000", "401000"),
											null)))
							.build();
					throw new GhidraMcpException(error);
				}

				targetFunction = program.getFunctionManager().getFunctionContaining(address);
				if (targetFunction == null) {
					GhidraMcpError error = GhidraMcpError.resourceNotFound()
							.errorCode(GhidraMcpError.ErrorCode.FUNCTION_NOT_FOUND)
							.message("No function found at address: " + functionAddressStr)
							.context(new GhidraMcpError.ErrorContext(
									toolMcpName,
									"function lookup by address",
									args,
									Map.of(ARG_FUNCTION_ADDRESS, functionAddressStr),
									Map.of(
											"parsedAddress", address.toString(),
											"programName", program.getDomainFile().getName())))
							.suggestions(List.of(
									new GhidraMcpError.ErrorSuggestion(
											GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
											"Verify address is within a function",
											"Use get_assembly_at_address to check if location contains code",
											List.of(),
											List.of(getMcpName(GhidraGetAssemblyAtAddressTool.class),
													getMcpName(GhidraListFunctionNamesTool.class)))))
							.build();
					throw new GhidraMcpException(error);
				}
			}

			return Tuples.of(program, targetFunction);

		}).flatMap(programAndFunctionTuple -> {
			ghidra.program.model.listing.Program program = programAndFunctionTuple.getT1();
			Function targetFunction = programAndFunctionTuple.getT2();

			return Mono.fromCallable(() -> {
				decomp.openProgram(program);
				GhidraMcpTaskMonitor monitor = new GhidraMcpTaskMonitor(ex, this.getClass().getSimpleName());
				DecompileResults result = decomp.decompileFunction(targetFunction, 180, monitor);

				if (result != null && result.decompileCompleted() && result.getDecompiledFunction() != null) {
					String decompiledCode = result.getDecompiledFunction().getC();
					return Map.of("decompiledCode",
							decompiledCode != null ? decompiledCode : "// Decompilation produced null output.");
				} else {
					String errorMsg = result != null ? result.getErrorMessage() : "Unknown decompiler error";
					String toolMcpName = getMcpName();

					GhidraMcpError error = GhidraMcpError.execution()
							.errorCode(GhidraMcpError.ErrorCode.DECOMPILATION_FAILED)
							.message("Decompilation failed for function: " + targetFunction.getName())
							.context(new GhidraMcpError.ErrorContext(
									toolMcpName,
									"function decompilation",
									Map.of(
											"functionName", targetFunction.getName(),
											"functionAddress", targetFunction.getEntryPoint().toString()),
									Map.of("decompilerError", errorMsg),
									Map.of(
											"completedSuccessfully", result != null && result.decompileCompleted(),
											"hasDecompiledFunction", result != null && result.getDecompiledFunction() != null)))
							.suggestions(List.of(
									new GhidraMcpError.ErrorSuggestion(
											GhidraMcpError.ErrorSuggestion.SuggestionType.ALTERNATIVE_APPROACH,
											"Try alternative approaches",
											"Consider function analysis or different timeout values",
											List.of(),
											List.of(getMcpName(GhidraTriggerAutoAnalysisTool.class),
													getMcpName(GhidraGetPcodeForFunctionTool.class),
													getMcpName(GhidraGetAssemblyAtAddressTool.class)))))
							.build();
					throw new GhidraMcpException(error);
				}
			});
		}).doFinally(signalType -> {
			if (decomp != null) {
				decomp.dispose();
			}
		});
	}

}
