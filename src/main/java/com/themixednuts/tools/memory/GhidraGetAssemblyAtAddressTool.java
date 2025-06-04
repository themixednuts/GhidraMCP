package com.themixednuts.tools.memory;

import java.util.Map;
import java.util.List;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.tools.ToolCategory;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Get Assembly at Address", category = ToolCategory.MEMORY, description = "Retrieves the assembly instruction at a specific address.", mcpName = "get_assembly_at_address", mcpDescription = "Get the assembly instruction located at a specified memory address. Returns the complete instruction string with mnemonic and operands formatted for the target architecture.")
public class GhidraGetAssemblyAtAddressTool implements IGhidraMcpSpecification {

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file."));
		schemaRoot.property(ARG_ADDRESS,
				JsonSchemaBuilder.string(mapper)
						.description("The address of the instruction to retrieve (e.g., '0x1004010').")
						.pattern("^(0x)?[0-9a-fA-F]+$"));

		schemaRoot.requiredProperty(ARG_FILE_NAME)
				.requiredProperty(ARG_ADDRESS);

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);

		return getProgram(args, tool).map(program -> {
			String addressStr = getRequiredStringArgument(args, ARG_ADDRESS);

			// Parse and validate address
			Address address;
			try {
				address = program.getAddressFactory().getAddress(addressStr);
			} catch (Exception e) {
				GhidraMcpError error = GhidraMcpError.validation()
						.errorCode(GhidraMcpError.ErrorCode.ADDRESS_PARSE_FAILED)
						.message("Failed to parse address: " + e.getMessage())
						.context(new GhidraMcpError.ErrorContext(
								annotation.mcpName(),
								"address parsing",
								Map.of(ARG_ADDRESS, addressStr),
								Map.of(ARG_ADDRESS, addressStr),
								Map.of("parseError", e.getMessage(), "providedValue", addressStr)))
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

			if (address == null) {
				GhidraMcpError error = GhidraMcpError.validation()
						.errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
						.message("Invalid address format")
						.context(new GhidraMcpError.ErrorContext(
								annotation.mcpName(),
								"address validation",
								Map.of(ARG_ADDRESS, addressStr),
								Map.of(ARG_ADDRESS, addressStr),
								Map.of("expectedFormat", "hexadecimal address", "providedValue", addressStr)))
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

			// Get instruction at address
			Instruction instruction = program.getListing().getInstructionAt(address);
			if (instruction == null) {
				GhidraMcpError error = GhidraMcpError.resourceNotFound()
						.errorCode(GhidraMcpError.ErrorCode.ADDRESS_NOT_FOUND)
						.message("No instruction found at address: " + addressStr)
						.context(new GhidraMcpError.ErrorContext(
								annotation.mcpName(),
								"instruction lookup",
								Map.of(ARG_ADDRESS, addressStr),
								Map.of(ARG_ADDRESS, addressStr, "addressResolved", address.toString()),
								Map.of("instructionFound", false, "addressValid", true)))
						.suggestions(List.of(
								new GhidraMcpError.ErrorSuggestion(
										GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
										"Verify the address contains an instruction",
										"Ensure the address points to a disassembled instruction",
										List.of("Check if address is at instruction boundary", "Verify disassembly is complete"),
										null),
								new GhidraMcpError.ErrorSuggestion(
										GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
										"Try a different address",
										"Use an address that contains a valid instruction",
										null,
										null)))
						.build();
				throw new GhidraMcpException(error);
			}

			return instruction.toString();
		});
	}
}