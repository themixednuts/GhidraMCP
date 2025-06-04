package com.themixednuts.tools.decompiler;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.models.PcodeOpInfo;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.tools.ToolCategory;
import com.themixednuts.tools.functions.GhidraGetFunctionContainingLocationTool;
import com.themixednuts.tools.functions.GhidraListFunctionNamesTool;
import com.themixednuts.tools.memory.GhidraGetAssemblyAtAddressTool;
import com.themixednuts.tools.projectmanagement.GhidraTriggerAutoAnalysisTool;
import com.themixednuts.utils.GhidraMcpTaskMonitor;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOpAST;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

import java.util.Iterator;
import java.util.Spliterator;
import java.util.Spliterators;

@GhidraMcpTool(name = "Get PCode for Function", category = ToolCategory.DECOMPILER, description = "Retrieves the PCode representation for a function.", mcpName = "get_pcode_for_function", mcpDescription = "Get the complete PCode intermediate representation for a function using decompiler analysis. Provides high-level, architecture-independent operations for the entire function.")
public class GhidraGetPcodeForFunctionTool implements IGhidraMcpSpecification {

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file."));
		schemaRoot.property(ARG_FUNCTION_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the function. Either this or address must be provided."));
		schemaRoot.property(ARG_ADDRESS,
				JsonSchemaBuilder.string(mapper)
						.description(
								"Optional entry point address of the function (e.g., '0x1004010'). Preferred over name if provided.")
						.pattern("^(0x)?[0-9a-fA-F]+$"));

		schemaRoot.requiredProperty(ARG_FILE_NAME);
		return schemaRoot.build();
	}

	private static record FunctionResolutionContext(Program program, Function function) {
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		DecompInterface decomp = new DecompInterface();

		return getProgram(args, tool).map(program -> {
			// --- Synchronous Setup: Resolve Function ---
			String functionName = getOptionalStringArgument(args, ARG_FUNCTION_NAME).orElse(null);
			String addressStr = getOptionalStringArgument(args, ARG_ADDRESS).orElse(null);
			final String toolMcpName = getMcpName();

			Function targetFunction = null;

			boolean hasName = functionName != null && !functionName.isBlank();
			boolean hasAddress = addressStr != null && !addressStr.isBlank();

			if (!hasName && !hasAddress) {
				GhidraMcpError error = GhidraMcpError.validation()
						.errorCode(GhidraMcpError.ErrorCode.MISSING_REQUIRED_ARGUMENT)
						.message("Either function name or address must be provided")
						.context(new GhidraMcpError.ErrorContext(
								toolMcpName,
								"function identifier validation",
								Map.of(
										ARG_FUNCTION_NAME, functionName != null ? functionName : "not provided",
										ARG_ADDRESS, addressStr != null ? addressStr : "not provided"),
								Map.of(),
								Map.of("identifiersProvided", 0, "minimumRequired", 1)))
						.suggestions(List.of(
								new GhidraMcpError.ErrorSuggestion(
										GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
										"Provide a function identifier",
										"Include either function name or address",
										List.of(
												"\"" + ARG_FUNCTION_NAME + "\": \"main\"",
												"\"" + ARG_ADDRESS + "\": \"0x401000\""),
										null)))
						.build();
				throw new GhidraMcpException(error);
			}

			if (hasAddress) {
				Address entryPointAddress;
				try {
					entryPointAddress = program.getAddressFactory().getAddress(addressStr);
				} catch (Exception e) {
					GhidraMcpError error = GhidraMcpError.execution()
							.errorCode(GhidraMcpError.ErrorCode.ADDRESS_PARSE_FAILED)
							.message("Invalid address format: " + addressStr)
							.context(new GhidraMcpError.ErrorContext(
									toolMcpName,
									"address parsing",
									Map.of(ARG_ADDRESS, addressStr),
									Map.of(),
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

				targetFunction = program.getFunctionManager().getFunctionAt(entryPointAddress);
				if (targetFunction == null) {
					GhidraMcpError error = GhidraMcpError.resourceNotFound()
							.errorCode(GhidraMcpError.ErrorCode.FUNCTION_NOT_FOUND)
							.message("Function not found at address: " + addressStr)
							.context(new GhidraMcpError.ErrorContext(
									toolMcpName,
									"function lookup by address",
									Map.of(ARG_ADDRESS, addressStr),
									Map.of("parsedAddress", entryPointAddress.toString()),
									Map.of("programName", program.getDomainFile().getName())))
							.suggestions(List.of(
									new GhidraMcpError.ErrorSuggestion(
											GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
											"Verify address is a function entry point",
											"Use get_function_containing_location to find function at any address within",
											List.of(),
											List.of(getMcpName(GhidraGetFunctionContainingLocationTool.class),
													getMcpName(GhidraListFunctionNamesTool.class)))))
							.build();
					throw new GhidraMcpException(error);
				}
			} else if (hasName) {
				targetFunction = StreamSupport
						.stream(program.getFunctionManager().getFunctions(true).spliterator(), false)
						.filter(f -> f.getName(true).equals(functionName))
						.findFirst()
						.orElse(null);

				if (targetFunction == null) {
					List<String> availableFunctions = StreamSupport
							.stream(program.getFunctionManager().getFunctions(true).spliterator(), false)
							.map(f -> f.getName(true))
							.sorted()
							.limit(50)
							.collect(Collectors.toList());

					GhidraMcpError error = GhidraMcpError.resourceNotFound()
							.errorCode(GhidraMcpError.ErrorCode.FUNCTION_NOT_FOUND)
							.message("Function not found with name: " + functionName)
							.context(new GhidraMcpError.ErrorContext(
									toolMcpName,
									"function lookup by name",
									Map.of(ARG_FUNCTION_NAME, functionName),
									Map.of(),
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
			}
			return new FunctionResolutionContext(program, targetFunction);
		})
				.flatMap(context -> Mono.fromCallable(() -> {
					// --- Blocking Decompilation & PCode Extraction ---
					Program program = context.program();
					Function targetFunction = context.function();

					decomp.openProgram(program);
					GhidraMcpTaskMonitor monitor = new GhidraMcpTaskMonitor(ex, this.getClass().getSimpleName());
					DecompileResults results = decomp.decompileFunction(targetFunction, 30, monitor);

					if (results == null || !results.decompileCompleted()) {
						String errorMsg = results != null ? results.getErrorMessage() : "Unknown decompiler error";
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
												"completedSuccessfully", results != null && results.decompileCompleted())))
								.suggestions(List.of(
										new GhidraMcpError.ErrorSuggestion(
												GhidraMcpError.ErrorSuggestion.SuggestionType.ALTERNATIVE_APPROACH,
												"Try alternative approaches",
												"Consider function analysis or simpler operations",
												List.of(),
												List.of(getMcpName(GhidraTriggerAutoAnalysisTool.class),
														getMcpName(GhidraDecompileFunctionTool.class),
														getMcpName(GhidraGetAssemblyAtAddressTool.class)))))
								.build();
						throw new GhidraMcpException(error);
					}

					HighFunction highFunction = results.getHighFunction();
					if (highFunction == null) {
						String toolMcpName = getMcpName();

						GhidraMcpError error = GhidraMcpError.execution()
								.errorCode(GhidraMcpError.ErrorCode.DECOMPILATION_FAILED)
								.message("Decompilation failed: No high function available for " + targetFunction.getName())
								.context(new GhidraMcpError.ErrorContext(
										toolMcpName,
										"high function extraction",
										Map.of(
												"functionName", targetFunction.getName(),
												"functionAddress", targetFunction.getEntryPoint().toString()),
										Map.of(),
										Map.of(
												"decompileCompleted", true,
												"highFunctionAvailable", false)))
								.suggestions(List.of(
										new GhidraMcpError.ErrorSuggestion(
												GhidraMcpError.ErrorSuggestion.SuggestionType.ALTERNATIVE_APPROACH,
												"Try different analysis approach",
												"Function may need different analysis or may be too simple/complex",
												List.of(),
												List.of(getMcpName(GhidraTriggerAutoAnalysisTool.class),
														getMcpName(GhidraGetPcodeAtAddressTool.class)))))
								.build();
						throw new GhidraMcpException(error);
					}

					Iterator<PcodeOpAST> pcodeIterator = highFunction.getPcodeOps();
					Spliterator<PcodeOpAST> pcodeSpliterator = Spliterators.spliteratorUnknownSize(pcodeIterator, 0);
					List<PcodeOpInfo> pcodeList = StreamSupport.stream(pcodeSpliterator, false)
							.map(pcodeOp -> PcodeOpInfo.fromPcodeOpAST(pcodeOp, highFunction))
							.collect(Collectors.toList());

					return pcodeList;
				}))
				.doFinally(signalType -> {
					if (decomp != null) {
						decomp.dispose();
					}
				});
	}
}