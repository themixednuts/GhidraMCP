package com.themixednuts.tools.projectmanagement;

import java.util.List;
import java.util.Map;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.models.ProgramInfo;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.tools.ToolCategory;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.framework.plugintool.PluginTool;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Get Current Program Info", category = ToolCategory.PROJECT_MANAGEMENT, description = "Gets the current program information.", mcpName = "get_current_program_info", mcpDescription = "Get detailed information about the current Ghidra program including name, architecture, memory layout, and analysis status.")
public class GhidraGetCurrentProgramInfoTool implements IGhidraMcpSpecification {

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file (used for context)."));

		schemaRoot.requiredProperty(ARG_FILE_NAME);

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool)
				.map(program -> new ProgramInfo(program))
				.onErrorMap(throwable -> {
					// Convert any remaining uncaught errors to structured errors
					if (throwable instanceof GhidraMcpException) {
						return throwable;
					}
					return new GhidraMcpException(
							GhidraMcpError.execution()
									.errorCode(GhidraMcpError.ErrorCode.UNEXPECTED_ERROR)
									.message("Failed to retrieve program information: " + throwable.getMessage())
									.context(new GhidraMcpError.ErrorContext(
											"get_program_info",
											getMcpName(),
											Map.of("fileName", getRequiredStringArgument(args, ARG_FILE_NAME)),
											Map.of("operation", "get_program_info"),
											Map.of("exception_type", throwable.getClass().getSimpleName(),
													"exception_message", throwable.getMessage())))
									.suggestions(List.of(
											new GhidraMcpError.ErrorSuggestion(
													GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
													"Ensure the program is properly opened and accessible",
													"Verify program state and try reopening if necessary",
													null,
													List.of(getMcpName(GhidraListOpenFilesTool.class)))))
									.build());
				});
	}
}