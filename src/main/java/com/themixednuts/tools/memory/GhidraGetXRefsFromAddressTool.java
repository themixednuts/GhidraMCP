package com.themixednuts.tools.memory;

import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.models.ReferenceInfo;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.tools.ToolCategory;

import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.framework.plugintool.PluginTool;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Get XRefs From Address", category = ToolCategory.MEMORY, description = "Retrieves cross-references originating from a specific address.", mcpName = "get_xrefs_from_address", mcpDescription = "Get a list of addresses that are referenced by the instruction or data at the given address.")
public class GhidraGetXRefsFromAddressTool implements IGhidraMcpSpecification {

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(ARG_FILE_NAME, JsonSchemaBuilder.string(mapper).description("The name of the program file."));
		schemaRoot.property(ARG_ADDRESS, JsonSchemaBuilder.string(mapper)
				.description("The source address to find references from (e.g., '0x1004010').")
				.pattern("^(0x)?[0-9a-fA-F]+$"));

		schemaRoot.requiredProperty(ARG_FILE_NAME)
				.requiredProperty(ARG_ADDRESS);

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).map(program -> {
			String addressStr = getRequiredStringArgument(args, ARG_ADDRESS);
			Address address = program.getAddressFactory().getAddress(addressStr);
			if (address == null) {
				throw new IllegalArgumentException("Invalid address format: " + addressStr);
			}

			ReferenceManager refManager = program.getReferenceManager();
			Reference[] refsFrom = refManager.getReferencesFrom(address);

			List<ReferenceInfo> references = Arrays.stream(refsFrom)
					.map(ReferenceInfo::new)
					.sorted(Comparator.comparing(ReferenceInfo::getToAddress))
					.collect(Collectors.toList());

			return references;
		});
	}

}
