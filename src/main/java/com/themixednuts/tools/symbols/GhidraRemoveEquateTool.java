package com.themixednuts.tools.symbols;

import java.util.List;
import java.util.Map;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.tools.ToolCategory;
import com.themixednuts.tools.memory.GhidraGetAssemblyAtAddressTool;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.app.cmd.equate.ClearEquateCmd;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFormatException;
import ghidra.program.model.listing.Instruction;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;
import ghidra.util.Msg;

@GhidraMcpTool(name = "Clear Specific Equate from Operand", description = "Clears a specific equate by name from an instruction operand.", category = ToolCategory.SYMBOLS, mcpName = "clear_equate_from_operand", mcpDescription = "Remove a named equate from an instruction operand.")
public class GhidraRemoveEquateTool implements IGhidraMcpSpecification {

	public static final String ARG_INSTRUCTION_ADDRESS = "instructionAddress";
	public static final String ARG_OPERAND_INDEX = "operandIndex";
	public static final String ARG_EQUATE_NAME = "equateName";

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();

		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper).description("The name of the program file."))
				.property(ARG_INSTRUCTION_ADDRESS,
						JsonSchemaBuilder.string(mapper)
								.description("The address of the instruction (e.g., \"ram:00401000\")."))
				.property(ARG_OPERAND_INDEX,
						JsonSchemaBuilder.integer(mapper).description("The zero-based index of the operand."))
				.property(ARG_EQUATE_NAME,
						JsonSchemaBuilder.string(mapper).description("The name of the equate to clear."));

		schemaRoot.requiredProperty(ARG_FILE_NAME);
		schemaRoot.requiredProperty(ARG_INSTRUCTION_ADDRESS);
		schemaRoot.requiredProperty(ARG_OPERAND_INDEX);
		schemaRoot.requiredProperty(ARG_EQUATE_NAME);

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool)
				.flatMap(program -> {
					try {
						String addressStr = getRequiredStringArgument(args, ARG_INSTRUCTION_ADDRESS);
						int operandIndex = getRequiredIntArgument(args, ARG_OPERAND_INDEX);
						String equateName = getRequiredStringArgument(args, ARG_EQUATE_NAME);
						final String toolMcpName = getMcpName();

						Address instructionAddress;
						try {
							instructionAddress = program.getAddressFactory().getDefaultAddressSpace().getAddress(addressStr);
						} catch (Exception e) {
							throw new GhidraMcpException(GhidraMcpError.execution()
									.errorCode(GhidraMcpError.ErrorCode.ADDRESS_PARSE_FAILED)
									.message("Invalid instruction address format: " + addressStr)
									.context(new GhidraMcpError.ErrorContext(
											toolMcpName,
											"address parsing",
											args,
											Map.of(ARG_INSTRUCTION_ADDRESS, addressStr),
											Map.of("parseException", e.getMessage())))
									.suggestions(List.of(
											new GhidraMcpError.ErrorSuggestion(
													GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
													"Use valid address format",
													"Provide address in hexadecimal format",
													List.of("0x401000", "ram:00401000", "401000"),
													null)))
									.build());
						}

						if (instructionAddress == null) {
							throw new GhidraMcpException(GhidraMcpError.execution()
									.errorCode(GhidraMcpError.ErrorCode.ADDRESS_PARSE_FAILED)
									.message("Failed to parse instruction address: " + addressStr)
									.context(new GhidraMcpError.ErrorContext(
											toolMcpName,
											"address parsing",
											args,
											Map.of(ARG_INSTRUCTION_ADDRESS, addressStr),
											Map.of("addressResult", "null")))
									.suggestions(List.of(
											new GhidraMcpError.ErrorSuggestion(
													GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
													"Use valid address format",
													"Provide address in hexadecimal format",
													List.of("0x401000", "ram:00401000", "401000"),
													null)))
									.build());
						}

						Instruction instruction = program.getListing().getInstructionAt(instructionAddress);
						if (instruction == null) {
							throw new GhidraMcpException(GhidraMcpError.resourceNotFound()
									.errorCode(GhidraMcpError.ErrorCode.ADDRESS_NOT_FOUND)
									.message("No instruction found at address: " + instructionAddress)
									.context(new GhidraMcpError.ErrorContext(
											toolMcpName,
											"instruction lookup",
											args,
											Map.of(ARG_INSTRUCTION_ADDRESS, addressStr,
													"parsedAddress", instructionAddress.toString()),
											Map.of("instructionExists", false)))
									.suggestions(List.of(
											new GhidraMcpError.ErrorSuggestion(
													GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
													"Verify instruction exists at address",
													"Check that the address contains a valid instruction",
													null,
													List.of(getMcpName(GhidraGetAssemblyAtAddressTool.class)))))
									.build());
						}

						if (operandIndex < 0 || operandIndex >= instruction.getNumOperands()) {
							throw new GhidraMcpException(GhidraMcpError.validation()
									.errorCode(GhidraMcpError.ErrorCode.ARGUMENT_OUT_OF_RANGE)
									.message(String.format("Invalid operand index %d for instruction at %s. Number of operands: %d.",
											operandIndex, instructionAddress, instruction.getNumOperands()))
									.context(new GhidraMcpError.ErrorContext(
											toolMcpName,
											"operand index validation",
											args,
											Map.of(ARG_OPERAND_INDEX, operandIndex,
													ARG_INSTRUCTION_ADDRESS, addressStr),
											Map.of("requestedIndex", operandIndex,
													"maxValidIndex", instruction.getNumOperands() - 1,
													"totalOperands", instruction.getNumOperands())))
									.suggestions(List.of(
											new GhidraMcpError.ErrorSuggestion(
													GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
													"Use valid operand index",
													"Operand index must be between 0 and " + (instruction.getNumOperands() - 1),
													List.of("\"operandIndex\": 0", "\"operandIndex\": 1"),
													null)))
									.build());
						}

						Msg.info(this, "Attempting to clear equate '" + equateName + "' from operand " + operandIndex + " at "
								+ instructionAddress);

						ClearEquateCmd clearEquateCmd = new ClearEquateCmd(equateName, instructionAddress, operandIndex);

						if (!tool.execute(clearEquateCmd, program)) {
							throw new GhidraMcpException(GhidraMcpError.execution()
									.errorCode(GhidraMcpError.ErrorCode.UNEXPECTED_ERROR)
									.message(
											"Failed to clear equate '" + equateName + "' from operand: " + clearEquateCmd.getStatusMsg())
									.context(new GhidraMcpError.ErrorContext(
											toolMcpName,
											"equate removal",
											args,
											Map.of(ARG_EQUATE_NAME, equateName,
													ARG_OPERAND_INDEX, operandIndex,
													ARG_INSTRUCTION_ADDRESS, addressStr),
											Map.of("command", "ClearEquateCmd",
													"statusMessage", clearEquateCmd.getStatusMsg())))
									.suggestions(List.of(
											new GhidraMcpError.ErrorSuggestion(
													GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
													"Verify equate exists on operand",
													"Check that the specified equate is applied to the operand",
													null,
													null)))
									.build());
						}

						return Mono.just(String.format("Equate '%s' cleared from operand %d at address %s.",
								equateName, operandIndex, instructionAddress.toString()));

					} catch (GhidraMcpException e) {
						return Mono.error(e);
					} catch (Exception e) {
						throw new GhidraMcpException(GhidraMcpError.execution()
								.errorCode(GhidraMcpError.ErrorCode.UNEXPECTED_ERROR)
								.message("Unexpected error clearing equate: " + e.getMessage())
								.context(new GhidraMcpError.ErrorContext(
										getMcpName(),
										"equate removal",
										args,
										Map.of("operation", "clear_equate"),
										Map.of("exceptionType", e.getClass().getSimpleName(),
												"exceptionMessage", e.getMessage())))
								.suggestions(List.of(
										new GhidraMcpError.ErrorSuggestion(
												GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
												"Verify instruction and operand details",
												"Check address, operand index, and equate name",
												null,
												null)))
								.build());
					}
				});
	}
}