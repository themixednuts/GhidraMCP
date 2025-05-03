package com.themixednuts.tools.functions;

import java.util.Map;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.utils.JsonSchemaBuilder;
import com.themixednuts.utils.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import reactor.core.publisher.Mono;
import ghidra.framework.plugintool.PluginTool;

@GhidraMcpTool(key = "Rename Function By Address", category = "Functions", description = "Renames a function identified by its address.", mcpName = "rename_function_by_address", mcpDescription = "Finds a function by its entry point address and renames it.")
public class GhidraRenameFunctionByAddressTool implements IGhidraMcpSpecification {

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
						.description("The entry point address of the function to rename (e.g., '0x1004010')."));
		schemaRoot.property("newName",
				JsonSchemaBuilder.string(mapper)
						.description("The new name for the function."));

		schemaRoot.requiredProperty("fileName")
				.requiredProperty("address")
				.requiredProperty("newName");

		return schemaRoot.build();
	}

	@Override
	public Mono<CallToolResult> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).flatMap(program -> {
			String addressStr = getRequiredStringArgument(args, "address");
			String newName = getRequiredStringArgument(args, "newName");

			Address addr = program.getAddressFactory().getAddress(addressStr);
			if (addr == null) {
				return createErrorResult("Invalid address format (could not parse address): " + addressStr);
			}

			Function function = program.getFunctionManager().getFunctionAt(addr);
			if (function == null) {
				return createErrorResult("Error: No function found at address " + addressStr);
			}

			return executeInTransaction(program, "Rename Function: " + newName, () -> {
				function.setName(newName, SourceType.USER_DEFINED);
				return createSuccessResult("Function renamed successfully to " + newName);
			});
		}).onErrorResume(e -> {
			return createErrorResult(e);
		});
	}

}
