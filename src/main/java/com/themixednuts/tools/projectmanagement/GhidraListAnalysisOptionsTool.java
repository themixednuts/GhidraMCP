package com.themixednuts.tools.projectmanagement;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.AnalysisOptionInfo;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.tools.ToolCategory;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.framework.options.OptionType;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "List Analysis Options", category = ToolCategory.PROJECT_MANAGEMENT, description = "Lists available analysis options and their current values for the program.", mcpName = "list_analysis_options", mcpDescription = "List available analysis options for a Ghidra program with their current values and types. Essential for configuring automated analysis settings.")
public class GhidraListAnalysisOptionsTool implements IGhidraMcpSpecification {

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file to get analysis options for."));

		schemaRoot.requiredProperty(ARG_FILE_NAME);

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool)
				.map(program -> {
					try {
						return getAllAnalysisOptions(program);
					} catch (Exception e) {
						throw new GhidraMcpException(
								GhidraMcpError.execution()
										.errorCode(GhidraMcpError.ErrorCode.UNEXPECTED_ERROR)
										.message("Failed to retrieve analysis options: " + e.getMessage())
										.context(new GhidraMcpError.ErrorContext(
												"get_analysis_options",
												getMcpName(),
												Map.of("fileName", getRequiredStringArgument(args, ARG_FILE_NAME)),
												Map.of("operation", "get_analysis_options"),
												Map.of("exception_type", e.getClass().getSimpleName(),
														"exception_message", e.getMessage())))
										.suggestions(List.of(
												new GhidraMcpError.ErrorSuggestion(
														GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
														"Ensure the program is properly opened and analysis framework is available",
														"Verify program state and analysis capabilities",
														null,
														List.of(getMcpName(GhidraGetCurrentProgramInfoTool.class)))))
										.build());
					}
				});
	}

	private List<AnalysisOptionInfo> getAllAnalysisOptions(Program program) {
		Options analysisOptions = program.getOptions(Program.ANALYSIS_PROPERTIES);
		List<String> optionNames = analysisOptions.getOptionNames();
		List<AnalysisOptionInfo> results = new ArrayList<>();

		for (String optionName : optionNames) {
			String description = analysisOptions.getDescription(optionName);
			OptionType type = analysisOptions.getType(optionName);
			Object value = analysisOptions.getObject(optionName, null);
			String valueStr = (value != null) ? value.toString() : "null";

			results.add(new AnalysisOptionInfo(optionName, description, type.toString(), valueStr));
		}

		results.sort(Comparator.comparing(AnalysisOptionInfo::getName));
		return results;
	}
}