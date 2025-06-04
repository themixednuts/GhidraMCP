package com.themixednuts.tools.projectmanagement;

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

import ghidra.app.services.GoToService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Go To Address", category = ToolCategory.PROJECT_MANAGEMENT, description = "Navigates Ghidra views to the specified address.", mcpName = "go_to_address", mcpDescription = """
		Navigate the UI views (Listing, Decompiler) to a specific address.
		""")
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
						GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
						GhidraMcpError error = GhidraMcpError.validation()
								.errorCode(GhidraMcpError.ErrorCode.ADDRESS_PARSE_FAILED)
								.message("Invalid address format or address not found in program: " + addressStr)
								.context(new GhidraMcpError.ErrorContext(
										annotation.mcpName(),
										"Address Parsing/Validation",
										args,
										Map.of(ARG_ADDRESS, addressStr),
										Map.of("detail",
												"The provided string could not be parsed into a valid memory address or the address does not exist in the program's address space.")))
								.suggestions(List.of(
										new GhidraMcpError.ErrorSuggestion(
												GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
												"Verify address string",
												"Ensure the address string is correctly formatted (e.g., '0x1004010', 'ram:00401000') and exists within the program.",
												List.of("\"address\": \"0x00401000\""),
												null)))
								.build();
						throw new GhidraMcpException(error);
					}

					GoToService goToService = tool.getService(GoToService.class);
					if (goToService == null) {
						GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
						GhidraMcpError error = GhidraMcpError.internal()
								.errorCode(GhidraMcpError.ErrorCode.CONFIGURATION_ERROR)
								.message("GoToService is not available in the current Ghidra tool context.")
								.context(new GhidraMcpError.ErrorContext(
										annotation.mcpName(),
										"Service Initialization",
										args,
										Map.of("missingService", "GoToService"),
										Map.of("detail",
												"The required Ghidra service for navigation could not be retrieved. This might indicate an issue with the Ghidra environment or tool setup.")))
								.build();
						throw new GhidraMcpException(error);
					}

					boolean success = goToService.goTo(targetAddress, program);

					if (success) {
						return "Successfully navigated to " + addressStr;
					} else {
						GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
						GhidraMcpError error = GhidraMcpError.execution()
								.errorCode(GhidraMcpError.ErrorCode.UNEXPECTED_ERROR)
								.message("Failed to navigate to address: " + addressStr)
								.context(new GhidraMcpError.ErrorContext(
										annotation.mcpName(),
										"Navigation Execution",
										args,
										Map.of(ARG_ADDRESS, addressStr),
										Map.of("detail",
												"The GoToService reported a failure. This can occur if the target view (e.g., Listing, Decompiler) is not open, not focused, or if the address, while parseable, is not considered navigable by the service in the current program state.")))
								.suggestions(List.of(
										new GhidraMcpError.ErrorSuggestion(
												GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
												"Verify Program State and Views",
												"Ensure the program is active, the address is valid, and the relevant Ghidra views (Listing, Decompiler) are open and focused.",
												null,
												null)))
								.build();
						throw new GhidraMcpException(error);
					}
				});
	}
}