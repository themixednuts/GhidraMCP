package com.themixednuts.tools.functions;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.FunctionInfo;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.tools.ToolCategory;
import com.themixednuts.utils.GhidraMcpTaskMonitor;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Create Function", mcpName = "create_function", category = ToolCategory.FUNCTIONS, description = "Creates a new function at a specified entry point address.", mcpDescription = """
		<use_case>
		Create a new function at a specific entry point address in a Ghidra program. Use this when you've identified code that should be treated as a function.
		</use_case>

		<important_notes>
		- Address must contain executable code and be properly disassembled
		- Cannot create function at address that already belongs to another function
		- Ghidra automatically determines function boundaries using control flow analysis
		- Custom name is optional; Ghidra assigns default name if not provided
		</important_notes>

		<example>
		Create a function at a specific address:
		{
		  "fileName": "program.exe",
		  "address": "0x401000",
		  "functionName": "decrypt_data"
		}
		</example>
		""")
public class GhidraCreateFunctionTool implements IGhidraMcpSpecification {

	private static record CreateFunctionContext(Program program, Address functionAddress, Optional<String> functionName) {
	}

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file."));
		schemaRoot.property(ARG_ADDRESS,
				JsonSchemaBuilder.string(mapper)
						.description("The entry point address for the new function.")
						.pattern("^(0x)?[0-9a-fA-F]+$"));
		schemaRoot.property(ARG_FUNCTION_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("Optional custom name for the new function. Default name assigned if omitted."));

		schemaRoot.requiredProperty(ARG_FILE_NAME);
		schemaRoot.requiredProperty(ARG_ADDRESS);

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);

		return getProgram(args, tool).map(program -> {
			String addressString = getRequiredStringArgument(args, ARG_ADDRESS);
			Optional<String> nameOpt = getOptionalStringArgument(args, ARG_FUNCTION_NAME);

			Address functionAddress;

			// Handle address parsing with structured error
			try {
				functionAddress = program.getAddressFactory().getAddress(addressString);
				if (functionAddress == null) {
					GhidraMcpError error = GhidraMcpError.validation()
							.errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
							.message("Invalid address format")
							.context(new GhidraMcpError.ErrorContext(
									annotation.mcpName(),
									"address parsing",
									args,
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
			} catch (Exception e) {
				if (e instanceof GhidraMcpException) {
					throw e; // Re-throw our structured error
				}
				// Handle other address parsing exceptions
				GhidraMcpError error = GhidraMcpError.validation()
						.errorCode(GhidraMcpError.ErrorCode.ADDRESS_PARSE_FAILED)
						.message("Failed to parse address: " + e.getMessage())
						.context(new GhidraMcpError.ErrorContext(
								annotation.mcpName(),
								"address parsing",
								args,
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

			// Check if function already exists at address
			if (program.getFunctionManager().getFunctionAt(functionAddress) != null) {
				GhidraMcpError error = GhidraMcpError.validation()
						.errorCode(GhidraMcpError.ErrorCode.CONFLICTING_ARGUMENTS)
						.message("Function already exists at the specified address")
						.context(new GhidraMcpError.ErrorContext(
								annotation.mcpName(),
								"function existence check",
								args,
								Map.of(ARG_ADDRESS, addressString),
								Map.of("functionExists", true, "addressValid", true)))
						.suggestions(List.of(
								new GhidraMcpError.ErrorSuggestion(
										GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
										"Verify the address is not already a function entry point",
										"Use function query tools to check existing functions",
										null,
										null),
								new GhidraMcpError.ErrorSuggestion(
										GhidraMcpError.ErrorSuggestion.SuggestionType.ALTERNATIVE_APPROACH,
										"Choose a different address or modify existing function",
										"Select an address that is not already the entry point of an existing function",
										null,
										null)))
						.build();
				throw new GhidraMcpException(error);
			}

			return new CreateFunctionContext(program, functionAddress, nameOpt);

		}).flatMap(context -> {
			Program program = context.program();
			Address funcAddr = context.functionAddress();
			Optional<String> funcNameOpt = context.functionName();
			String transactionName = "MCP - Create Function at " + funcAddr;

			return executeInTransaction(program, transactionName, () -> {
				CreateFunctionCmd cmd = new CreateFunctionCmd(
						funcNameOpt.orElse(null),
						funcAddr,
						new AddressSet(funcAddr),
						SourceType.USER_DEFINED);

				GhidraMcpTaskMonitor monitor = new GhidraMcpTaskMonitor(ex, this.getClass().getSimpleName());
				if (!cmd.applyTo(program, monitor)) {
					String cmdStatus = cmd.getStatusMsg() != null ? cmd.getStatusMsg() : "Unknown error";
					GhidraMcpError error = GhidraMcpError.execution()
							.errorCode(GhidraMcpError.ErrorCode.TRANSACTION_FAILED)
							.message("Failed to create function: " + cmdStatus)
							.context(new GhidraMcpError.ErrorContext(
									annotation.mcpName(),
									"function creation command",
									Map.of(ARG_ADDRESS, funcAddr.toString(), ARG_FUNCTION_NAME, funcNameOpt.orElse("default")),
									Map.of("commandStatus", cmdStatus),
									Map.of("commandSuccess", false, "addressValid", true)))
							.suggestions(List.of(
									new GhidraMcpError.ErrorSuggestion(
											GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
											"Ensure address contains executable code",
											"Verify the target address has been properly disassembled",
											null,
											null),
									new GhidraMcpError.ErrorSuggestion(
											GhidraMcpError.ErrorSuggestion.SuggestionType.ALTERNATIVE_APPROACH,
											"Try a different address or run analysis first",
											"Complete disassembly and analysis at the target location",
											null,
											null)))
							.build();
					throw new GhidraMcpException(error);
				}

				Function createdFunction = cmd.getFunction();
				if (createdFunction == null) {
					GhidraMcpError error = GhidraMcpError.execution()
							.errorCode(GhidraMcpError.ErrorCode.UNEXPECTED_ERROR)
							.message("Function creation command succeeded but returned no function object")
							.context(new GhidraMcpError.ErrorContext(
									annotation.mcpName(),
									"function creation result",
									Map.of(ARG_ADDRESS, funcAddr.toString()),
									Map.of("commandSuccess", true, "functionReturned", false),
									Map.of("internalError", true)))
							.suggestions(List.of(
									new GhidraMcpError.ErrorSuggestion(
											GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
											"Verify function was actually created",
											"Check if function exists at the specified address after creation",
											null,
											null)))
							.build();
					throw new GhidraMcpException(error);
				}

				return new FunctionInfo(createdFunction);
			});
		});
	}
}