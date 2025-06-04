package com.themixednuts.tools.memory;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.models.ReferenceInfo;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.tools.ToolCategory;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Get XRefs To Address", category = ToolCategory.MEMORY, description = "Retrieves all cross-references (XRefs) to a specific address.", mcpName = "get_xrefs_to_address", mcpDescription = "Get all incoming cross-references to a specified memory address. Returns function calls, jumps, and data references that target the location.")
public class GhidraGetXRefsToAddressTool implements IGhidraMcpSpecification {

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file."));
		schemaRoot.property(ARG_ADDRESS,
				JsonSchemaBuilder.string(mapper)
						.description("The target address to find incoming cross-references to (e.g., '0x1004010').")
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

			// Get references to the address
			ReferenceIterator refIterator = program.getReferenceManager().getReferencesTo(address);
			List<ReferenceInfo> references = new ArrayList<>();

			try {
				while (refIterator.hasNext()) {
					Reference ref = refIterator.next();
					references.add(new ReferenceInfo(ref));
				}
			} catch (Exception e) {
				GhidraMcpError error = GhidraMcpError.execution()
						.errorCode(GhidraMcpError.ErrorCode.ANALYSIS_FAILED)
						.message("Error analyzing cross-references: " + e.getMessage())
						.context(new GhidraMcpError.ErrorContext(
								annotation.mcpName(),
								"reference analysis",
								Map.of(ARG_ADDRESS, addressStr),
								Map.of("analysisError", e.getMessage()),
								Map.of("referencesFound", references.size())))
						.suggestions(List.of(
								new GhidraMcpError.ErrorSuggestion(
										GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
										"Verify program analysis is complete",
										"Ensure the program has been fully analyzed",
										List.of("Run auto-analysis", "Check analysis completion status"),
										null),
								new GhidraMcpError.ErrorSuggestion(
										GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
										"Try a different address",
										"Use an address in a well-analyzed region",
										null,
										null)))
						.build();
				throw new GhidraMcpException(error);
			}

			return references;
		});
	}
}
