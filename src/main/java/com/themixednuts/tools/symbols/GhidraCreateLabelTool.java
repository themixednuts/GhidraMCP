package com.themixednuts.tools.symbols;

import java.util.List;
import java.util.Map;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.tools.ToolCategory;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.app.cmd.label.AddLabelCmd;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.util.exception.InvalidInputException;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Create Label", category = ToolCategory.SYMBOLS, description = "Adds a label at a specified address.", mcpName = "create_label", mcpDescription = """
		<use_case>
		Create a new label at a specific address in a Ghidra program. Use this to mark important locations like function entry points, data structures, or string references.
		</use_case>

		<important_notes>
		- Label names must be valid identifiers (letters, digits, underscore)
		- Cannot start with a digit
		- Creates USER_DEFINED label with highest priority
		- Replaces any existing default labels at the address
		</important_notes>

		<example>
		Create a label for a function entry point:
		{
		  "fileName": "program.exe",
		  "address": "0x401000",
		  "name": "decrypt_routine"
		}
		</example>
		""")
public class GhidraCreateLabelTool implements IGhidraMcpSpecification {

	// Define nested record for context
	private static record CreateLabelContext(
			Program program,
			Address address,
			String labelName) {
	}

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file."));
		schemaRoot.property(ARG_ADDRESS,
				JsonSchemaBuilder.string(mapper)
						.description("The address where the label should be added (e.g., '0x1004010').")
						.pattern("^(0x)?[0-9a-fA-F]+$"));
		schemaRoot.property(ARG_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name for the new label."));

		schemaRoot.requiredProperty(ARG_FILE_NAME)
				.requiredProperty(ARG_ADDRESS)
				.requiredProperty(ARG_NAME);

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool)
				.map(program -> {
					// --- Setup Phase (Synchronous) ---
					String addressStr = getRequiredStringArgument(args, ARG_ADDRESS);
					String labelName = getRequiredStringArgument(args, ARG_NAME);
					final String toolMcpName = getMcpName();
					Address targetAddress;

					// Validate label name format
					try {
						SymbolUtilities.validateName(labelName);
					} catch (InvalidInputException e) {
						GhidraMcpError error = GhidraMcpError.validation()
								.errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
								.message("Invalid label name: " + e.getMessage())
								.context(new GhidraMcpError.ErrorContext(
										toolMcpName,
										"label name validation",
										args,
										Map.of(ARG_NAME, labelName),
										Map.of("validationError", e.getMessage())))
								.suggestions(List.of(
										new GhidraMcpError.ErrorSuggestion(
												GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
												"Use valid label name format",
												"Label names must be valid identifiers",
												List.of(
														"my_label",
														"Label_123",
														"importantFunction"),
												null)))
								.build();
						throw new GhidraMcpException(error);
					}

					// Parse address
					try {
						targetAddress = program.getAddressFactory().getAddress(addressStr);
					} catch (Exception e) {
						GhidraMcpError error = GhidraMcpError.execution()
								.errorCode(GhidraMcpError.ErrorCode.ADDRESS_PARSE_FAILED)
								.message("Invalid address format: " + addressStr)
								.context(new GhidraMcpError.ErrorContext(
										toolMcpName,
										"address parsing",
										args,
										Map.of(ARG_ADDRESS, addressStr),
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

					if (targetAddress == null) {
						GhidraMcpError error = GhidraMcpError.execution()
								.errorCode(GhidraMcpError.ErrorCode.ADDRESS_PARSE_FAILED)
								.message("Invalid address format: " + addressStr)
								.context(new GhidraMcpError.ErrorContext(
										toolMcpName,
										"address parsing",
										args,
										Map.of(ARG_ADDRESS, addressStr),
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

					// Pass program and validated inputs to transaction
					return new CreateLabelContext(program, targetAddress, labelName);

				})
				.flatMap(context -> {
					// Use context record fields
					return executeInTransaction(context.program(),
							"MCP - Add Label " + context.labelName() + " at " + context.address(), () -> {
								// Use AddLabelCmd
								AddLabelCmd cmd = new AddLabelCmd(context.address(), context.labelName(), SourceType.USER_DEFINED);
								if (cmd.applyTo(context.program())) {
									return "Successfully created label '" + context.labelName() + "' at " + context.address().toString();
								} else {
									String toolMcpName = getMcpName();
									GhidraMcpError error = GhidraMcpError.execution()
											.errorCode(GhidraMcpError.ErrorCode.UNEXPECTED_ERROR)
											.message("Failed to create label: " + cmd.getStatusMsg())
											.context(new GhidraMcpError.ErrorContext(
													toolMcpName,
													"label creation",
													Map.of(
															ARG_ADDRESS, context.address().toString(),
															ARG_NAME, context.labelName()),
													null,
													Map.of("commandStatus", cmd.getStatusMsg())))
											.suggestions(List.of(
													new GhidraMcpError.ErrorSuggestion(
															GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
															"Check if label name conflicts with existing symbols",
															"Verify label name is unique at the address",
															null,
															List.of("get_symbol_at_address", "list_all_symbols"))))
											.build();
									throw new GhidraMcpException(error);
								}
							});
				});
	}
}