package com.themixednuts.tools.projectmanagement;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.models.AnalysisOptionInfo;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.tools.ToolCategory;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.framework.options.Options;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;
import ghidra.framework.options.OptionType;

@GhidraMcpTool(name = "List Analysis Options", category = ToolCategory.PROJECT_MANAGEMENT, description = "Lists the available auto-analysis options and their current enabled status for a program.", mcpName = "list_analysis_options", mcpDescription = "Retrieves a list of all available auto-analysis options and their current enabled/disabled status for the specified program.")
public class GhidraListAnalysisOptionsTool implements IGhidraMcpSpecification {

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(ARG_FILE_NAME, // Constant from IGhidraMcpSpecification
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file to get analysis options for."));
		schemaRoot.requiredProperty(ARG_FILE_NAME);
		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool)
				.map(program -> {
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
				});
	}
}