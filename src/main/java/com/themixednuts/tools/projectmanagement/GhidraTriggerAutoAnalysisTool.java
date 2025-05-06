package com.themixednuts.tools.projectmanagement;

import java.util.Map;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.tools.ToolCategory;
import com.themixednuts.utils.GhidraMcpTaskMonitor; // Import the custom monitor
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.framework.plugintool.PluginTool;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Trigger Auto-Analysis", category = ToolCategory.PROJECT_MANAGEMENT, description = "Triggers standard Ghidra auto-analysis (respecting options).", mcpName = "trigger_auto_analysis", mcpDescription = "Triggers the standard Ghidra auto-analysis process (respecting current analysis options). Analysis runs in the background.")
public class GhidraTriggerAutoAnalysisTool implements IGhidraMcpSpecification {

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
		return getProgram(args, tool)
				.flatMap(program -> {
					AutoAnalysisManager analysisManager = AutoAnalysisManager.getAnalysisManager(program);
					if (analysisManager.isAnalyzing()) {
						// Optionally return an error or info message if analysis is already running
						return Mono
								.error(new IllegalStateException("Analysis is already running for program: " + program.getName()));
					}

					// Use the custom Task Monitor that reports progress via MCP
					GhidraMcpTaskMonitor monitor = new GhidraMcpTaskMonitor(ex, this.getClass().getSimpleName());

					// StartAnalysis runs in the background, so we return success immediately.
					// The monitor will send progress updates.
					analysisManager.startAnalysis(monitor);

					return Mono.just("Auto-analysis started for program: " + program.getName());
				});
	}
}