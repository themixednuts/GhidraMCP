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

import ghidra.app.services.CodeViewerService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.util.ProgramLocation;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Get Current Address", category = ToolCategory.MEMORY, description = "Retrieves the current cursor address in Ghidra.", mcpName = "get_current_address", mcpDescription = "Get the current cursor address from the active Ghidra session. Returns the address where the user's cursor is currently positioned in the program view.")
public class GhidraGetCurrentAddressTool implements IGhidraMcpSpecification {

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file."));

		schemaRoot.requiredProperty(ARG_FILE_NAME);

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);

		return getProgram(args, tool).map(program -> {
			// Get CodeViewerService to access current location
			CodeViewerService codeViewerService = tool.getService(CodeViewerService.class);
			if (codeViewerService == null) {
				GhidraMcpError error = GhidraMcpError.execution()
						.errorCode(GhidraMcpError.ErrorCode.ANALYSIS_FAILED)
						.message("CodeViewerService not available")
						.context(new GhidraMcpError.ErrorContext(
								annotation.mcpName(),
								"service access",
								Map.of(ARG_FILE_NAME, getRequiredStringArgument(args, ARG_FILE_NAME)),
								Map.of("serviceRequested", "CodeViewerService"),
								Map.of("serviceAvailable", false)))
						.suggestions(List.of(
								new GhidraMcpError.ErrorSuggestion(
										GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
										"Ensure Ghidra CodeBrowser is active",
										"Make sure the CodeBrowser plugin is loaded and active",
										List.of("Open the CodeBrowser tool", "Verify plugin is enabled"),
										null)))
						.build();
				throw new GhidraMcpException(error);
			}

			// Get current location from the code viewer service
			ProgramLocation currentLocation = codeViewerService.getCurrentLocation();

			if (currentLocation == null) {
				GhidraMcpError error = GhidraMcpError.resourceNotFound()
						.errorCode(GhidraMcpError.ErrorCode.ADDRESS_NOT_FOUND)
						.message("No current address position is set")
						.context(new GhidraMcpError.ErrorContext(
								annotation.mcpName(),
								"current address lookup",
								Map.of(ARG_FILE_NAME, getRequiredStringArgument(args, ARG_FILE_NAME)),
								Map.of("currentLocation", "null"),
								Map.of("locationAvailable", false)))
						.suggestions(List.of(
								new GhidraMcpError.ErrorSuggestion(
										GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
										"Set a current address in Ghidra",
										"Click on a location in the program view to set current address",
										List.of("Navigate to a function or data location", "Click in the listing view"),
										null),
								new GhidraMcpError.ErrorSuggestion(
										GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
										"Use a specific address instead",
										"Consider using address-specific tools with explicit addresses",
										null,
										null)))
						.build();
				throw new GhidraMcpException(error);
			}

			// Verify the location belongs to the current program
			if (!program.equals(currentLocation.getProgram())) {
				GhidraMcpError error = GhidraMcpError.validation()
						.errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
						.message("Current location does not match requested program")
						.context(new GhidraMcpError.ErrorContext(
								annotation.mcpName(),
								"program context validation",
								Map.of(ARG_FILE_NAME, getRequiredStringArgument(args, ARG_FILE_NAME)),
								Map.of("requestedProgram", program.getName(),
										"currentProgram",
										currentLocation.getProgram() != null ? currentLocation.getProgram().getName() : "null"),
								Map.of("programMismatch", true)))
						.suggestions(List.of(
								new GhidraMcpError.ErrorSuggestion(
										GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
										"Ensure the correct program is active",
										"Switch to the requested program in Ghidra",
										List.of("Open the correct program file", "Set focus on the target program"),
										null)))
						.build();
				throw new GhidraMcpException(error);
			}

			// Get the current address
			ghidra.program.model.address.Address currentAddress = currentLocation.getAddress();
			if (currentAddress == null) {
				GhidraMcpError error = GhidraMcpError.resourceNotFound()
						.errorCode(GhidraMcpError.ErrorCode.ADDRESS_NOT_FOUND)
						.message("Current location has no valid address")
						.context(new GhidraMcpError.ErrorContext(
								annotation.mcpName(),
								"address extraction",
								Map.of(ARG_FILE_NAME, getRequiredStringArgument(args, ARG_FILE_NAME)),
								Map.of("locationClass", currentLocation.getClass().getSimpleName()),
								Map.of("addressValid", false)))
						.suggestions(List.of(
								new GhidraMcpError.ErrorSuggestion(
										GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
										"Navigate to a valid address location",
										"Click on a specific address in the program listing",
										List.of("Click on an instruction or data item", "Use Go To Address dialog"),
										null)))
						.build();
				throw new GhidraMcpException(error);
			}

			// Return current address information
			return Map.of(
					"currentAddress", currentAddress.toString(),
					"programName", program.getName(),
					"locationType", currentLocation.getClass().getSimpleName());
		});
	}
}