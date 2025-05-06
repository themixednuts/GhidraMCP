package com.themixednuts.tools.projectmanagement;

import java.util.Map;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.tools.ToolCategory;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.app.services.GoToService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Go To Address", category = ToolCategory.PROJECT_MANAGEMENT, description = "Navigates Ghidra views to the specified address.", mcpName = "go_to_address", mcpDescription = "Navigate the UI views (Listing, Decompiler) to a specific address.")
public class GhidraGoToAddressTool implements IGhidraMcpSpecification {

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file (required to resolve address and target UI)."));
		schemaRoot.property(ARG_ADDRESS,
				JsonSchemaBuilder.string(mapper)
						.description("The address to navigate to (e.g., '0x1004010').")
						.pattern("^(0x)?[0-9a-fA-F]+$"));

		schemaRoot.requiredProperty(ARG_FILE_NAME)
				.requiredProperty(ARG_ADDRESS);

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool)
				.map(program -> {
					String addressStr = getRequiredStringArgument(args, ARG_ADDRESS);
					Address targetAddress = program.getAddressFactory().getAddress(addressStr);

					if (targetAddress == null) {
						throw new IllegalArgumentException("Invalid address format: " + addressStr);
					}

					GoToService goToService = tool.getService(GoToService.class);
					if (goToService == null) {
						throw new IllegalStateException("GoToService is not available in the current tool context.");
					}

					boolean success = goToService.goTo(targetAddress, program);

					if (success) {
						return "Successfully navigated to " + addressStr;
					} else {
						throw new RuntimeException("GoToService failed to navigate to " + addressStr
								+ ". View might not be active or address invalid for current context.");
					}
				});
	}
}