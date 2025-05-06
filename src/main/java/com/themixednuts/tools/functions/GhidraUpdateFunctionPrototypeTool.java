package com.themixednuts.tools.functions;

import java.util.Map;

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
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import io.modelcontextprotocol.spec.McpSchema.LoggingLevel;
import io.modelcontextprotocol.spec.McpSchema.LoggingMessageNotification;
import reactor.core.publisher.Mono;
import reactor.util.function.Tuples;

@GhidraMcpTool(name = "Update Function Prototype", category = ToolCategory.FUNCTIONS, description = "Updates the prototype (signature) of an existing function.", mcpName = "update_function_prototype", mcpDescription = "Modifies the return type, parameters, calling convention, or varargs status of an existing function.")
public class GhidraUpdateFunctionPrototypeTool implements IGhidraMcpSpecification {

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
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).flatMap(program -> {
			return Mono.fromCallable(() -> {
				String addressString = getRequiredStringArgument(args, ARG_FUNCTION_ADDRESS);
				String newPrototypeString = getRequiredStringArgument(args, "prototype");

				Address functionAddress = program.getAddressFactory().getAddress(addressString);
				if (functionAddress == null) {
					throw new IllegalArgumentException("Invalid address format: " + addressString);
				}

				Function targetFunction = program.getFunctionManager().getFunctionAt(functionAddress);
				if (targetFunction == null) {
					throw new IllegalArgumentException("Function not found: " + addressString);
				}

				return Tuples.of(targetFunction, newPrototypeString);
			})
					.flatMap(tuple -> {
						Function functionToUpdate = tuple.getT1();
						String prototypeStr = tuple.getT2();

						ex.loggingNotification(LoggingMessageNotification.builder()
								.level(LoggingLevel.INFO)
								.logger(this.getClass().getSimpleName())
								.data("Attempting to update prototype for " + functionToUpdate.getName() + " at "
										+ functionToUpdate.getEntryPoint()
										+ " with signature: " + prototypeStr)
								.build());

						return executeInTransaction(program,
								"MCP - Update Function Prototype: " + functionToUpdate.getName(),
								() -> {
									DataTypeManager dtm = program.getDataTypeManager();
									DataTypeQueryService service = tool.getService(DataTypeQueryService.class);
									if (service == null) {
										throw new IllegalStateException("DataTypeQueryService not available.");
									}
									FunctionSignatureParser parser = new FunctionSignatureParser(dtm, service);
									FunctionDefinitionDataType parsedSignature = parser.parse(functionToUpdate.getSignature(),
											prototypeStr);
									ApplyFunctionSignatureCmd cmd = new ApplyFunctionSignatureCmd(functionToUpdate.getEntryPoint(),
											parsedSignature, SourceType.USER_DEFINED);
									GhidraMcpTaskMonitor mcpMonitor = new GhidraMcpTaskMonitor(ex, this.getClass().getSimpleName());
									if (!cmd.applyTo(program, mcpMonitor)) {
										throw new RuntimeException("Failed to apply signature: " + cmd.getStatusMsg());
									}
									return "Function prototype updated successfully for " + functionToUpdate.getName();
								});
					});
		});
	}

}
