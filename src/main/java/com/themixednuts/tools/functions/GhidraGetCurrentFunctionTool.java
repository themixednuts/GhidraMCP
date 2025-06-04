package com.themixednuts.tools.functions;

import java.util.List;
import java.util.Map;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.FunctionInfo;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.tools.ToolCategory;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.app.nav.Navigatable;
import ghidra.app.services.GoToService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Get Current Function", category = ToolCategory.FUNCTIONS, description = "Gets details about the function containing the current cursor location.", mcpName = "get_current_function", mcpDescription = "Get details of the function containing the current cursor location in Ghidra. Automatically detects the cursor position and returns complete function information if positioned within a function.")
public class GhidraGetCurrentFunctionTool implements IGhidraMcpSpecification {

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);

		return Mono.fromCallable(() -> {
			// Check for GoToService availability
			GoToService goToService = tool.getService(GoToService.class);
			if (goToService == null) {
				GhidraMcpError error = GhidraMcpError.permissionState()
						.errorCode(GhidraMcpError.ErrorCode.INVALID_PROGRAM_STATE)
						.message("GoToService not available in current Ghidra session")
						.context(new GhidraMcpError.ErrorContext(
								annotation.mcpName(),
								"Ghidra service availability",
								args,
								Map.of("requiredService", "GoToService"),
								Map.of("serviceAvailable", false, "sessionActive", true)))
						.suggestions(List.of(
								new GhidraMcpError.ErrorSuggestion(
										GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
										"Ensure Ghidra session is properly initialized",
										"Verify that Ghidra is running with all required services",
										null,
										null)))
						.build();
				throw new GhidraMcpException(error);
			}

			// Check for default navigatable
			Navigatable navigatable = goToService.getDefaultNavigatable();
			if (navigatable == null) {
				GhidraMcpError error = GhidraMcpError.permissionState()
						.errorCode(GhidraMcpError.ErrorCode.INVALID_PROGRAM_STATE)
						.message("Default navigatable not available")
						.context(new GhidraMcpError.ErrorContext(
								annotation.mcpName(),
								"Ghidra navigation context",
								args,
								Map.of("requiredComponent", "DefaultNavigatable"),
								Map.of("navigatableAvailable", false, "serviceActive", true)))
						.suggestions(List.of(
								new GhidraMcpError.ErrorSuggestion(
										GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
										"Ensure a program is open in Ghidra",
										"Open a program in the main Ghidra listing window",
										null,
										null)))
						.build();
				throw new GhidraMcpException(error);
			}

			// Check for current location
			ProgramLocation location = navigatable.getLocation();
			if (location == null) {
				GhidraMcpError error = GhidraMcpError.permissionState()
						.errorCode(GhidraMcpError.ErrorCode.INVALID_PROGRAM_STATE)
						.message("Current cursor location not available")
						.context(new GhidraMcpError.ErrorContext(
								annotation.mcpName(),
								"cursor location",
								args,
								Map.of("requiredContext", "ProgramLocation"),
								Map.of("locationAvailable", false, "navigatableActive", true)))
						.suggestions(List.of(
								new GhidraMcpError.ErrorSuggestion(
										GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
										"Position cursor in the Ghidra listing",
										"Click on an address in the main Ghidra listing window to set cursor location",
										null,
										null)))
						.build();
				throw new GhidraMcpException(error);
			}

			// Check for program context
			Program program = location.getProgram();
			if (program == null) {
				GhidraMcpError error = GhidraMcpError.permissionState()
						.errorCode(GhidraMcpError.ErrorCode.PROGRAM_NOT_OPEN)
						.message("No program context available from current location")
						.context(new GhidraMcpError.ErrorContext(
								annotation.mcpName(),
								"program context",
								args,
								Map.of("locationAddress", location.getAddress() != null ? location.getAddress().toString() : "unknown"),
								Map.of("programAvailable", false, "locationValid", true)))
						.suggestions(List.of(
								new GhidraMcpError.ErrorSuggestion(
										GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
										"Ensure a program is properly loaded",
										"Open and analyze a program in Ghidra before using this tool",
										null,
										null)))
						.build();
				throw new GhidraMcpException(error);
			}

			// Look for function at current location
			FunctionManager functionManager = program.getFunctionManager();
			Function function = functionManager.getFunctionContaining(location.getAddress());

			if (function == null) {
				GhidraMcpError error = GhidraMcpError.resourceNotFound()
						.errorCode(GhidraMcpError.ErrorCode.FUNCTION_NOT_FOUND)
						.message("No function found at current cursor location")
						.context(new GhidraMcpError.ErrorContext(
								annotation.mcpName(),
								"function at address: " + location.getAddress(),
								args,
								Map.of("currentAddress", location.getAddress().toString()),
								Map.of("functionExists", false, "addressValid", true)))
						.suggestions(List.of(
								new GhidraMcpError.ErrorSuggestion(
										GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
										"Position cursor within a function",
										"Navigate to an address that is within a function's body",
										null,
										null),
								new GhidraMcpError.ErrorSuggestion(
										GhidraMcpError.ErrorSuggestion.SuggestionType.ALTERNATIVE_APPROACH,
										"Create a function at this location",
										"Use function creation tools if this should be a function entry point",
										null,
										null)))
						.build();
				throw new GhidraMcpException(error);
			}

			return new FunctionInfo(function);
		});
	}
}