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

import ghidra.app.cmd.equate.SetEquateCmd;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFormatException;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Equate;
import ghidra.program.model.symbol.EquateTable;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;
import ghidra.util.Msg;

@GhidraMcpTool(name = "Apply Equate", description = "Creates an equate if it doesn't exist, and applies it to an instruction operand.", category = ToolCategory.SYMBOLS, mcpName = "apply_equate", mcpDescription = "Apply a named equate value to an instruction operand. Creates the equate if it doesn't exist.")
public class GhidraApplyEquateTool implements IGhidraMcpSpecification {

	public static final String ARG_INSTRUCTION_ADDRESS = "instructionAddress";
	public static final String ARG_OPERAND_INDEX = "operandIndex";
	public static final String ARG_EQUATE_NAME = "equateName";
	public static final String ARG_EQUATE_VALUE = "equateValue";

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
						JsonSchemaBuilder.string(mapper).description("The name of the equate to apply or create."))
				.property(ARG_EQUATE_VALUE,
						JsonSchemaBuilder.integer(mapper).format(com.themixednuts.utils.jsonschema.IntegerFormatType.INT64)
								.description("The value of the equate (e.g., 10, 0xA). Used if the equate needs to be created."));

		schemaRoot.requiredProperty(ARG_FILE_NAME);
		schemaRoot.requiredProperty(ARG_INSTRUCTION_ADDRESS);
		schemaRoot.requiredProperty(ARG_OPERAND_INDEX);
		schemaRoot.requiredProperty(ARG_EQUATE_NAME);
		schemaRoot.requiredProperty(ARG_EQUATE_VALUE);

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool)
				.flatMap(program -> {
					String addressStr = getRequiredStringArgument(args, ARG_INSTRUCTION_ADDRESS);
					int operandIndex = getRequiredIntArgument(args, ARG_OPERAND_INDEX);
					String equateName = getRequiredStringArgument(args, ARG_EQUATE_NAME);
					long equateValueForCreation = getRequiredLongArgument(args, ARG_EQUATE_VALUE);

					Address instructionAddress;
					try {
						instructionAddress = program.getAddressFactory().getDefaultAddressSpace().getAddress(addressStr);
					} catch (AddressFormatException e) {
						return Mono.error(new IllegalArgumentException("Invalid instruction address format: " + addressStr, e));
					}
					if (instructionAddress == null) {
						return Mono.error(new IllegalArgumentException("Failed to parse instruction address: " + addressStr));
					}

					Instruction instruction = program.getListing().getInstructionAt(instructionAddress);
					if (instruction == null) {
						return Mono.error(new IllegalArgumentException("No instruction found at address: " + instructionAddress));
					}
					if (operandIndex < 0 || operandIndex >= instruction.getNumOperands()) {
						return Mono.error(new IllegalArgumentException(
								String.format("Invalid operand index %d for instruction at %s. Number of operands: %d.",
										operandIndex, instructionAddress, instruction.getNumOperands())));
					}
					Scalar operandScalar = instruction.getScalar(operandIndex);
					if (operandScalar == null) {
						return Mono
								.error(new IllegalStateException("Operand at " + instructionAddress + " opIndex " + operandIndex +
										" is not a scalar. Equates can only be applied to scalar operands."));
					}
					long actualOperandValue = operandScalar.getSignedValue();

					EquateTable equateTable = program.getEquateTable();
					String transactionName = "Apply Equate: " + equateName;

					return executeInTransaction(program, transactionName, () -> {
						Equate finalEquate = equateTable.getEquate(equateName);
						if (finalEquate == null) {
							Msg.info(this, "Equate '" + equateName + "' not found. Creating with value: " + equateValueForCreation);
							finalEquate = equateTable.createEquate(equateName, equateValueForCreation);
							if (finalEquate == null) {
								throw new RuntimeException("Failed to create equate '" + equateName + "' in equate table.");
							}
							Msg.info(this, "Equate '" + equateName + "' created successfully.");
						} else {
							Msg.info(this, "Equate '" + equateName + "' already exists.");
						}

						Msg.info(this, "Attempting to apply equate '" + equateName + "' to operand " + operandIndex + " at "
								+ instructionAddress + " with operand value " + actualOperandValue);

						SetEquateCmd setEquateCmd = new SetEquateCmd(equateName, instructionAddress, operandIndex,
								actualOperandValue);
						if (!tool.execute(setEquateCmd, program)) {
							throw new RuntimeException(
									"Failed to apply equate '" + equateName + "' to operand: " + setEquateCmd.getStatusMsg());
						}

						return String.format(
								"Equate '%s' (value %d for creation, applied to operand with value %d) at operand %d at %s.",
								equateName, equateValueForCreation, actualOperandValue, operandIndex, instructionAddress.toString());
					});
				});
	}
}