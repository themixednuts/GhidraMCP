package com.themixednuts.tools.functions;

import java.util.Map;
import java.util.Optional;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.utils.GhidraMcpTaskMonitor;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;
import com.themixednuts.tools.ToolCategory;

import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.services.DataTypeQueryService;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.LoggingLevel;
import io.modelcontextprotocol.spec.McpSchema.LoggingMessageNotification;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Update Function Prototype", category = ToolCategory.FUNCTIONS, description = "Updates the prototype (signature) of an existing function.", mcpName = "update_function_prototype", mcpDescription = "Modifies the return type, parameters, calling convention, or varargs status of an existing function.")
public class GhidraUpdateFunctionPrototypeTool implements IGhidraMcpSpecification {

	@Override
	public AsyncToolSpecification specification(PluginTool tool) {
		GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
		if (annotation == null) {
			Msg.error(this, "Missing @GhidraMcpTool annotation on " + this.getClass().getSimpleName());
			return null;
		}

		JsonSchema schemaObject = schema();
		Optional<String> schemaStringOpt = parseSchema(schemaObject);
		if (schemaStringOpt.isEmpty()) {
			Msg.error(this, "Failed to serialize schema for tool '" + annotation.mcpName() + "'. Tool will be disabled.");
			return null;
		}
		String schemaJson = schemaStringOpt.get();

		return new AsyncToolSpecification(
				new Tool(annotation.mcpName(), annotation.mcpDescription(), schemaJson),
				(ex, args) -> execute(ex, args, tool));
	}

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file."));
		schemaRoot.property(ARG_FUNCTION_ADDRESS,
				JsonSchemaBuilder.string(mapper)
						.description("The address of the function entry point (e.g., '0x1004010')."));
		schemaRoot.property("prototype",
				JsonSchemaBuilder.string(mapper)
						.description("The new function prototype string (e.g., 'void FUN_00401000(int param1, char *param2)')."));

		schemaRoot.requiredProperty(ARG_FILE_NAME)
				.requiredProperty(ARG_FUNCTION_ADDRESS)
				.requiredProperty("prototype");

		return schemaRoot.build();
	}

	@Override
	public Mono<CallToolResult> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).flatMap(program -> {
			String addressString = getRequiredStringArgument(args, ARG_FUNCTION_ADDRESS);
			String newPrototypeString = getRequiredStringArgument(args, "prototype");

			Address functionAddress = program.getAddressFactory().getAddress(addressString);
			if (functionAddress == null) {
				return createErrorResult("Invalid function address format: " + addressString);
			}

			Function targetFunction = program.getFunctionManager().getFunctionAt(functionAddress);
			if (targetFunction == null) {
				return createErrorResult("Error: Function not found at address '" + addressString + "'.");
			}

			ex.loggingNotification(LoggingMessageNotification.builder()
					.level(LoggingLevel.INFO)
					.logger(this.getClass().getSimpleName())
					.data("Attempting to update prototype for " + targetFunction.getName() + " at " + addressString
							+ " with signature: " + newPrototypeString)
					.build());

			return executeInTransaction(program,
					"MCP - Update Function Prototype: " + targetFunction.getName(),
					() -> {
						DataTypeManager dtm = program.getDataTypeManager();
						DataTypeQueryService service = tool.getService(DataTypeQueryService.class);
						if (service == null) {
							return createErrorResult("DataTypeQueryService not available.");
						}
						FunctionSignatureParser parser = new FunctionSignatureParser(dtm, service);

						FunctionDefinitionDataType parsedSignature = parser.parse(targetFunction.getSignature(),
								newPrototypeString);

						ApplyFunctionSignatureCmd cmd = new ApplyFunctionSignatureCmd(
								functionAddress,
								parsedSignature,
								SourceType.USER_DEFINED);

						GhidraMcpTaskMonitor mcpMonitor = new GhidraMcpTaskMonitor(ex, this.getClass().getSimpleName());

						if (!cmd.applyTo(program, mcpMonitor)) {
							String errorMsg = "Failed to apply signature: " + cmd.getStatusMsg();
							return createErrorResult(errorMsg);
						}

						return createSuccessResult("Function prototype updated successfully for " + targetFunction.getName());
					});

		}).onErrorResume(e -> createErrorResult(e));
	}

}
