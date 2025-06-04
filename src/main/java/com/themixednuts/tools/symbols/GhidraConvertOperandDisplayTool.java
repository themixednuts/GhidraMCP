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

import ghidra.app.cmd.equate.SetEquateCmd;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.scalar.Scalar;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Convert Operand Display", description = "Converts the display format of an instruction operand between hex, decimal, binary, octal, and character formats.", category = ToolCategory.SYMBOLS, mcpName = "convert_operand_display", mcpDescription = "Convert an instruction operand's display format to hex, decimal, binary, octal, or character representation.")
public class GhidraConvertOperandDisplayTool implements IGhidraMcpSpecification {

	public static final String ARG_INSTRUCTION_ADDRESS = "instructionAddress";
	public static final String ARG_OPERAND_INDEX = "operandIndex";
	public static final String ARG_CONVERSION_TYPE = "conversionType";

	// Define the conversion types enum for validation
	public enum ConversionType {
		HEX, DECIMAL, BINARY, OCTAL, CHAR
	}

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
				.property(ARG_CONVERSION_TYPE,
						JsonSchemaBuilder.string(mapper)
								.description("The desired display format for the operand.")
								.enumValues(ConversionType.class));

		schemaRoot.requiredProperty(ARG_FILE_NAME);
		schemaRoot.requiredProperty(ARG_INSTRUCTION_ADDRESS);
		schemaRoot.requiredProperty(ARG_OPERAND_INDEX);
		schemaRoot.requiredProperty(ARG_CONVERSION_TYPE);

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool)
				.flatMap(program -> {
					try {
						String addressStr = getRequiredStringArgument(args, ARG_INSTRUCTION_ADDRESS);
						int operandIndex = getRequiredIntArgument(args, ARG_OPERAND_INDEX);
						String conversionTypeStr = getRequiredStringArgument(args, ARG_CONVERSION_TYPE);
						final String toolMcpName = getMcpName();

						ConversionType conversionType;
						try {
							conversionType = ConversionType.valueOf(conversionTypeStr.toUpperCase());
						} catch (Exception e) {
							throw new GhidraMcpException(
									GhidraMcpError.validation()
											.errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
											.message("Invalid conversion type: " + conversionTypeStr)
											.context(new GhidraMcpError.ErrorContext(
													toolMcpName,
													"conversion type validation",
													args,
													Map.of(ARG_CONVERSION_TYPE, conversionTypeStr),
													Map.of("validTypes", List.of("HEX", "DECIMAL", "BINARY", "OCTAL", "CHAR"))))
											.suggestions(List.of(
													new GhidraMcpError.ErrorSuggestion(
															GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
															"Use valid conversion type",
															"Conversion type must be one of the supported formats",
															List.of("HEX", "DECIMAL", "BINARY", "OCTAL", "CHAR"),
															null)))
											.build());
						}

						Address instructionAddress;
						try {
							instructionAddress = program.getAddressFactory().getDefaultAddressSpace().getAddress(addressStr);
						} catch (Exception e) {
							throw new GhidraMcpException(
									GhidraMcpError.execution()
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
							throw new GhidraMcpException(
									GhidraMcpError.execution()
											.errorCode(GhidraMcpError.ErrorCode.ADDRESS_PARSE_FAILED)
											.message("Address " + addressStr + " parsed to null")
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
							throw new GhidraMcpException(
									GhidraMcpError.resourceNotFound()
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
															List.of(
																	getMcpName(GhidraGetAssemblyAtAddressTool.class)))))
											.build());
						}

						if (operandIndex < 0 || operandIndex >= instruction.getNumOperands()) {
							throw new GhidraMcpException(
									GhidraMcpError.validation()
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

						Scalar operandScalar = instruction.getScalar(operandIndex);
						if (operandScalar == null) {
							throw new GhidraMcpException(
									GhidraMcpError.validation()
											.errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
											.message("Operand at index " + operandIndex + " is not a scalar value and cannot be converted")
											.context(new GhidraMcpError.ErrorContext(
													toolMcpName,
													"operand scalar validation",
													args,
													Map.of(ARG_OPERAND_INDEX, operandIndex,
															ARG_INSTRUCTION_ADDRESS, addressStr),
													Map.of("operandType", "non-scalar",
															"instructionText", instruction.toString())))
											.suggestions(List.of(
													new GhidraMcpError.ErrorSuggestion(
															GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
															"Select scalar operand",
															"Choose an operand index that contains a numeric value",
															null,
															null)))
											.build());
						}

						// Generate equate name based on conversion type
						long scalarValue = operandScalar.getValue();
						String equateName = switch (conversionType) {
							case HEX -> "0x" + Long.toHexString(scalarValue).toUpperCase();
							case DECIMAL -> Long.toString(scalarValue);
							case BINARY -> "0b" + Long.toBinaryString(scalarValue);
							case OCTAL -> "0" + Long.toOctalString(scalarValue);
							case CHAR -> {
								if (scalarValue >= 32 && scalarValue <= 126) {
									yield "'" + (char) scalarValue + "'";
								} else {
									yield "0x" + Long.toHexString(scalarValue).toUpperCase();
								}
							}
						};

						SetEquateCmd setEquateCmd = new SetEquateCmd(equateName, instructionAddress, operandIndex, scalarValue);

						if (!tool.execute(setEquateCmd, program)) {
							throw new GhidraMcpException(
									GhidraMcpError.execution()
											.errorCode(GhidraMcpError.ErrorCode.UNEXPECTED_ERROR)
											.message("Failed to convert operand display format: " + setEquateCmd.getStatusMsg())
											.context(new GhidraMcpError.ErrorContext(
													toolMcpName,
													"operand format conversion",
													args,
													Map.of(ARG_CONVERSION_TYPE, conversionTypeStr,
															ARG_OPERAND_INDEX, operandIndex,
															ARG_INSTRUCTION_ADDRESS, addressStr),
													Map.of("command", "SetEquateCmd",
															"statusMessage", setEquateCmd.getStatusMsg(),
															"equateName", equateName,
															"scalarValue", scalarValue)))
											.suggestions(List.of(
													new GhidraMcpError.ErrorSuggestion(
															GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
															"Verify operand conversion compatibility",
															"Check that the operand value can be displayed in the requested format",
															null,
															null)))
											.build());
						}

						return Mono.just(String.format("Operand %d at address %s converted to %s format (equate: %s).",
								operandIndex, instructionAddress.toString(), conversionType.name(), equateName));

					} catch (GhidraMcpException e) {
						return Mono.error(e);
					} catch (Exception e) {
						throw new GhidraMcpException(
								GhidraMcpError.execution()
										.errorCode(GhidraMcpError.ErrorCode.UNEXPECTED_ERROR)
										.message("Unexpected error converting operand display: " + e.getMessage())
										.context(new GhidraMcpError.ErrorContext(
												getMcpName(),
												"operand format conversion",
												args,
												Map.of("operation", "convert_operand_display"),
												Map.of("exceptionType", e.getClass().getSimpleName(),
														"exceptionMessage", e.getMessage())))
										.suggestions(List.of(
												new GhidraMcpError.ErrorSuggestion(
														GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
														"Verify instruction and operand details",
														"Check address, operand index, and conversion format",
														null,
														null)))
										.build());
					}
				});
	}
}