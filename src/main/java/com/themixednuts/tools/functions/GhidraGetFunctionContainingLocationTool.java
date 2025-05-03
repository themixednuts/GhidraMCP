package com.themixednuts.tools.functions;

import java.util.Map;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.utils.GhidraFunctionsToolInfo;
import com.themixednuts.utils.JsonSchemaBuilder;
import com.themixednuts.utils.JsonSchemaBuilder.IObjectSchemaBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import reactor.core.publisher.Mono;
import ghidra.framework.plugintool.PluginTool;

@GhidraMcpTool(key = "Get Function Containing Location", category = "Functions", description = "Finds the function that contains a given memory address.", mcpName = "get_function_containing_location", mcpDescription = "Returns details about the function that includes the specified memory address within its body.")
public class GhidraGetFunctionContainingLocationTool implements IGhidraMcpSpecification {

	@Override
	public AsyncToolSpecification specification(PluginTool tool) {
		GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
		if (annotation == null) {
			Msg.error(this, "Missing @GhidraMcpTool annotation on " + this.getClass().getSimpleName());
			return null;
		}

		String schema = parseSchema(schema()).orElse(null);
		if (schema == null) {
			return null;
		}

		return new AsyncToolSpecification(
				new Tool(annotation.mcpName(), annotation.mcpDescription(), schema),
				(ex, args) -> execute(ex, args, tool));
	}

	@Override
	public ObjectNode schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property("fileName",
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file."));
		schemaRoot.property("address",
				JsonSchemaBuilder.string(mapper)
						.description("The memory address to check (e.g., '0x1004050')."));

		schemaRoot.requiredProperty("fileName")
				.requiredProperty("address");

		return schemaRoot.build();
	}

	@Override
	public Mono<CallToolResult> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).flatMap(program -> {
			String addressStr = getRequiredStringArgument(args, "address");

			Address addr = program.getAddressFactory().getAddress(addressStr);
			if (addr == null) {
				return createErrorResult("Invalid address format (could not parse address): " + addressStr);
			}

			Function func = program.getFunctionManager().getFunctionContaining(addr);
			if (func == null) {
				return createErrorResult("No function found containing address: " + addressStr);
			}

			GhidraFunctionsToolInfo functionInfo = new GhidraFunctionsToolInfo(func);
			return createSuccessResult(functionInfo);

		}).onErrorResume(e -> {
			return createErrorResult(e);
		});
	}
}
