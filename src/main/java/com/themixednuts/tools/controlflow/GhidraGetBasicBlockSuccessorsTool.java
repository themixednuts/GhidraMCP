package com.themixednuts.tools.controlflow;

import java.util.List;
import java.util.Map;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.models.BasicBlockInfo;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.tools.ToolCategory;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;
import com.themixednuts.utils.GhidraMcpTaskMonitor;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockModel;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.block.SimpleBlockModel;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Get Basic Block Successors", category = ToolCategory.CONTROL_FLOW, description = "Retrieves information about the successor basic blocks of the block containing the specified address.", mcpName = "get_basic_block_successors", mcpDescription = "Get all successor basic blocks that the block containing a specified address can flow into. Essential for forward control flow analysis.")
public class GhidraGetBasicBlockSuccessorsTool implements IGhidraMcpSpecification {

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
		schemaRoot.property(ARG_ADDRESS,
				JsonSchemaBuilder.string(mapper)
						.description("An address within the source basic block (e.g., '0x1004010').")
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

			CodeBlockModel blockModel = new SimpleBlockModel(program);
			TaskMonitor monitor = new GhidraMcpTaskMonitor(ex, "Get Successors");
			CodeBlock block;
			CodeBlockReferenceIterator succIter;

			try {
				block = blockModel.getFirstCodeBlockContaining(address, monitor);
				if (block == null) {
					GhidraMcpError error = GhidraMcpError.resourceNotFound()
							.errorCode(GhidraMcpError.ErrorCode.ADDRESS_NOT_FOUND)
							.message("No basic block found containing address: " + addressStr)
							.context(new GhidraMcpError.ErrorContext(
									annotation.mcpName(),
									"basic block lookup",
									Map.of(ARG_ADDRESS, addressStr),
									Map.of(ARG_ADDRESS, addressStr, "addressResolved", address.toString()),
									Map.of("blockFound", false, "addressValid", true)))
							.suggestions(List.of(
									new GhidraMcpError.ErrorSuggestion(
											GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
											"Verify the address contains code",
											"Ensure the address is within a defined code block",
											List.of("Check if address contains valid instructions", "Verify program analysis is complete"),
											List.of(getRelatedToolMcpName(GhidraGetBasicBlockAtAddressTool.class))),
									new GhidraMcpError.ErrorSuggestion(
											GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
											"Try a different address",
											"Use an address that is known to contain code",
											null,
											null)))
							.build();
					throw new GhidraMcpException(error);
				}
				succIter = block.getDestinations(monitor);
			} catch (CancelledException e) {
				GhidraMcpError error = GhidraMcpError.execution()
						.errorCode(GhidraMcpError.ErrorCode.ANALYSIS_FAILED)
						.message("Operation cancelled while getting basic block successors: " + e.getMessage())
						.context(new GhidraMcpError.ErrorContext(
								annotation.mcpName(),
								"successor analysis",
								Map.of(ARG_ADDRESS, addressStr),
								Map.of("cancellationReason", e.getMessage()),
								Map.of("operationCancelled", true)))
						.suggestions(List.of(
								new GhidraMcpError.ErrorSuggestion(
										GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
										"Retry the operation",
										"The operation was cancelled, try again",
										null,
										null)))
						.build();
				throw new GhidraMcpException(error);
			}

			List<BasicBlockInfo> successors = new java.util.ArrayList<>();
			try {
				while (succIter.hasNext()) {
					CodeBlockReference ref = succIter.next();
					successors.add(new BasicBlockInfo(ref.getDestinationBlock()));
				}
			} catch (CancelledException e) {
				GhidraMcpError error = GhidraMcpError.execution()
						.errorCode(GhidraMcpError.ErrorCode.ANALYSIS_FAILED)
						.message("Operation cancelled during successor iteration: " + e.getMessage())
						.context(new GhidraMcpError.ErrorContext(
								annotation.mcpName(),
								"successor enumeration",
								Map.of(ARG_ADDRESS, addressStr),
								Map.of("cancellationReason", e.getMessage(), "successorsFound", successors.size()),
								Map.of("operationCancelled", true, "partialResults", true)))
						.suggestions(List.of(
								new GhidraMcpError.ErrorSuggestion(
										GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
										"Retry the operation",
										"The operation was cancelled during processing, try again",
										null,
										null)))
						.build();
				throw new GhidraMcpException(error);
			}
			return successors;
		});
	}
}