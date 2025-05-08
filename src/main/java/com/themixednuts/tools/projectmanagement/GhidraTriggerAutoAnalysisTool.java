package com.themixednuts.tools.projectmanagement;

import java.util.Map;
import java.util.List;
import java.util.concurrent.Callable;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.tools.ToolCategory;
import com.themixednuts.utils.GhidraMcpTaskMonitor; // Import the custom monitor
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IArraySchemaBuilder;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.framework.plugintool.PluginTool;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;
import ghidra.framework.options.Options;
import ghidra.framework.options.OptionType;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

@GhidraMcpTool(name = "Trigger Auto-Analysis", category = ToolCategory.PROJECT_MANAGEMENT, description = "Triggers standard Ghidra auto-analysis (respecting options).", mcpName = "trigger_auto_analysis", mcpDescription = "Triggers the standard Ghidra auto-analysis process (respecting current analysis options). Analysis runs in the background.")
public class GhidraTriggerAutoAnalysisTool implements IGhidraMcpSpecification {

	public static final String ARG_ANALYSIS_OPTION_OVERRIDES = "analysisOptionOverrides";

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file."));
		schemaRoot.requiredProperty(ARG_FILE_NAME);

		// Define schema for an individual option override
		IObjectSchemaBuilder optionOverrideSchema = JsonSchemaBuilder.object(mapper)
				.property(ARG_NAME, JsonSchemaBuilder.string(mapper).description("Name of the analysis option."))
				.property(ARG_VALUE, JsonSchemaBuilder.object(mapper)
						.description("Value to set for the option (boolean, string, or number)."))
				.requiredProperty(ARG_NAME)
				.requiredProperty(ARG_VALUE);

		// Define schema for the array of option overrides
		IArraySchemaBuilder optionsArraySchema = JsonSchemaBuilder.array(mapper)
				.description(
						"Optional: A list of analysis options to set before starting analysis. Use the 'list_analysis_options' tool to discover available option names, their types, and current values.")
				.items(optionOverrideSchema);

		schemaRoot.property(ARG_ANALYSIS_OPTION_OVERRIDES, optionsArraySchema);

		return schemaRoot.build();
	}

	@Override
	@SuppressWarnings("unchecked") // Suppress unchecked warnings for the method due to dynamic enum handling
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool)
				.flatMap(program -> {
					List<Map<String, Object>> overrides = getOptionalListArgument(args, ARG_ANALYSIS_OPTION_OVERRIDES)
							.orElse(null);

					Mono<Void> optionsAppliedMono = Mono.empty(); // Default to no-op if no overrides

					if (overrides != null && !overrides.isEmpty()) {
						Callable<Void> optionSettingWork = () -> { // Callable returns Void (null)
							Options analysisOptions = program.getOptions(Program.ANALYSIS_PROPERTIES);
							for (Map<String, Object> override : overrides) {
								Object optionNameObj = override.get(ARG_NAME);
								Object optionValue = override.get(ARG_VALUE);
								if (!(optionNameObj instanceof String)) {
									Msg.warn(this, "Skipping invalid option override: name is not a string. Provided Name Object: '"
											+ optionNameObj + "', Provided Value: " + optionValue);
									continue;
								}
								String optionName = (String) optionNameObj;
								if (optionName.isBlank()) {
									Msg.warn(this, "Skipping invalid option override: name is blank. Provided Value: " + optionValue);
									continue;
								}
								if (optionValue == null) {
									Msg.warn(this, "Skipping invalid option override for '" + optionName + "': value is null.");
									continue;
								}
								OptionType type = analysisOptions.getType(optionName);
								if (type == null) {
									Msg.warn(this, "Skipping override for unknown Ghidra option: '" + optionName + "'");
									continue;
								}
								try {
									switch (type) {
										case BOOLEAN_TYPE:
											if (optionValue instanceof Boolean) {
												analysisOptions.setBoolean(optionName, (Boolean) optionValue);
											} else {
												Msg.warn(this, "Type mismatch for boolean option: '" + optionName + "', value: " + optionValue
														+ ". Expected Boolean.");
											}
											break;
										case INT_TYPE:
											if (optionValue instanceof Number) {
												analysisOptions.setInt(optionName, ((Number) optionValue).intValue());
											} else {
												Msg.warn(this, "Type mismatch for int option: '" + optionName + "', value: " + optionValue
														+ ". Expected Number.");
											}
											break;
										case LONG_TYPE:
											if (optionValue instanceof Number) {
												analysisOptions.setLong(optionName, ((Number) optionValue).longValue());
											} else {
												Msg.warn(this, "Type mismatch for long option: '" + optionName + "', value: " + optionValue
														+ ". Expected Number.");
											}
											break;
										case DOUBLE_TYPE:
											if (optionValue instanceof Number) {
												analysisOptions.setDouble(optionName, ((Number) optionValue).doubleValue());
											} else {
												Msg.warn(this, "Type mismatch for double option: '" + optionName + "', value: " + optionValue
														+ ". Expected Number.");
											}
											break;
										case STRING_TYPE:
											if (optionValue instanceof String) {
												analysisOptions.setString(optionName, (String) optionValue);
											} else {
												Msg.warn(this, "Type mismatch for string option: '" + optionName + "', value: " + optionValue
														+ ". Expected String. Attempting toString().");
												analysisOptions.setString(optionName, optionValue.toString());
											}
											break;
										case FILE_TYPE:
											if (optionValue instanceof String) {
												analysisOptions.setFile(optionName, new java.io.File((String) optionValue));
											} else {
												Msg.warn(this, "Type mismatch for file option: '" + optionName + "', value: " + optionValue
														+ ". Expected String path.");
											}
											break;
										case ENUM_TYPE:
											if (!(optionValue instanceof String)) {
												Msg.warn(this,
														"Type mismatch for enum option (expected String representing enum name): '" + optionName
																+ "', value: " + optionValue);
												break;
											}
											Enum<?> currentEnum = analysisOptions.getEnum(optionName, null);
											if (currentEnum == null) {
												Msg.warn(this, "Could not determine enum type for option: '" + optionName + "'.");
												break;
											}
											try {
												@SuppressWarnings("rawtypes")
												Class<? extends Enum> enumClass = currentEnum.getDeclaringClass().asSubclass(Enum.class);
												Enum<?>[] constants = enumClass.getEnumConstants();
												boolean found = false;
												for (Enum<?> ec : constants) {
													if (ec.name().equals(optionValue.toString())) {
														analysisOptions.setEnum(optionName, enumClass.cast(ec));
														found = true;
														break;
													}
												}
												if (!found) {
													Msg.warn(this,
															"Enum value '" + optionValue + "' not found for option: '" + optionName + "'.");
												}
											} catch (Exception e) {
												Msg.error(this, "Error setting enum option '" + optionName + "'", e);
											}
											break;
										default:
											Msg.warn(this, "Unsupported option type '" + type + "' for override on option '" + optionName
													+ "'. Value not set.");
											break;
									}
								} catch (Exception e) {
									Msg.error(this, "Failed to set analysis option '" + optionName + "' to '" + optionValue + "'", e);
								}
							} // End of for loop for overrides
							return null; // Callable<Void> returns null
						};

						optionsAppliedMono = executeInTransaction(program, "Set Analysis Option Overrides", optionSettingWork)
								.then(); // Convert to Mono<Void>
					}

					return optionsAppliedMono.then(Mono.fromCallable(() -> {
						// Use the original 'program' instance here
						AutoAnalysisManager analysisManager = AutoAnalysisManager.getAnalysisManager(program);
						if (analysisManager.isAnalyzing()) {
							throw new IllegalStateException("Analysis is already running for program: " + program.getName());
						}
						GhidraMcpTaskMonitor monitor = new GhidraMcpTaskMonitor(ex, this.getClass().getSimpleName());
						analysisManager.startAnalysis(monitor);
						return "Auto-analysis started for program: " + program.getName();
					}));
				});
	}
}