package com.themixednuts.tools.projectmanagement;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.AnalysisOptionInfo;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.tools.ToolCategory;
import com.themixednuts.utils.GhidraMcpTaskMonitor;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.framework.options.OptionType;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Trigger Auto Analysis", category = ToolCategory.PROJECT_MANAGEMENT, description = "Triggers automatic analysis on a program with optional analysis option overrides.", mcpName = "trigger_auto_analysis", mcpDescription = "Trigger automatic analysis on a Ghidra program with configurable analysis options. Essential for comprehensive program analysis and feature extraction.")
public class GhidraTriggerAutoAnalysisTool implements IGhidraMcpSpecification {

	private static final String ARG_ANALYSIS_OPTIONS = "analysisOptionOverrides";

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file."));

		// Analysis option override schema
		IObjectSchemaBuilder optionOverrideSchema = JsonSchemaBuilder.object(mapper)
				.property("name", JsonSchemaBuilder.string(mapper).description("Name of the analysis option."))
				.property("value",
						JsonSchemaBuilder.object(mapper).description("Value to set for the option (boolean, string, or number)."))
				.requiredProperty("name")
				.requiredProperty("value");

		schemaRoot.property(ARG_ANALYSIS_OPTIONS,
				JsonSchemaBuilder.array(mapper)
						.description(
								"Optional: A list of analysis options to set before starting analysis. Use the 'list_analysis_options' tool to discover available option names, their types, and current values.")
						.items(optionOverrideSchema));

		schemaRoot.requiredProperty(ARG_FILE_NAME);

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool)
				.map(program -> {
					try {
						// Create task monitor for progress reporting
						GhidraMcpTaskMonitor monitor = new GhidraMcpTaskMonitor(ex, "auto_analysis");

						AutoAnalysisManager manager = AutoAnalysisManager.getAnalysisManager(program);
						if (manager == null) {
							throw new GhidraMcpException(
									GhidraMcpError.permissionState()
											.errorCode(GhidraMcpError.ErrorCode.INVALID_PROGRAM_STATE)
											.message("AutoAnalysisManager is not available for the program")
											.context(new GhidraMcpError.ErrorContext(
													"get_analysis_manager",
													getMcpName(),
													Map.of("fileName", getRequiredStringArgument(args, ARG_FILE_NAME)),
													Map.of("program_name", program.getName()),
													Map.of("manager_status", "not_available")))
											.suggestions(List.of(
													new GhidraMcpError.ErrorSuggestion(
															GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
															"Ensure the program is properly opened and analysis framework is available",
															"Verify program state and analysis capabilities",
															null,
															List.of(getMcpName(GhidraGetCurrentProgramInfoTool.class)))))
											.build());
						}

						// Start analysis
						manager.startAnalysis(monitor);

						return Map.of(
								"message", "Auto analysis has been triggered for " + program.getName(),
								"program", program.getName(),
								"status", "analysis_started");
					} catch (Exception e) {
						if (e instanceof GhidraMcpException) {
							throw e;
						}
						throw new GhidraMcpException(
								GhidraMcpError.toolExecution()
										.errorCode(GhidraMcpError.ErrorCode.ANALYSIS_FAILED)
										.message("Failed to trigger auto analysis: " + e.getMessage())
										.context(new GhidraMcpError.ErrorContext(
												"trigger_analysis",
												getMcpName(),
												Map.of("fileName", getRequiredStringArgument(args, ARG_FILE_NAME)),
												Map.of("program_name", program.getName()),
												Map.of("exception_type", e.getClass().getSimpleName(),
														"exception_message", e.getMessage())))
										.suggestions(List.of(
												new GhidraMcpError.ErrorSuggestion(
														GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
														"Verify program state and analysis capabilities",
														"Ensure the program is writable and analysis framework is available",
														null,
														List.of(getMcpName(GhidraGetCurrentProgramInfoTool.class),
																getMcpName(GhidraListAnalysisOptionsTool.class)))))
										.build());
					}
				});
	}
}