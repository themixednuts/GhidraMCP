package com.themixednuts.tools.symbols;

import java.util.Map;
import java.util.Optional;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;

import reactor.core.publisher.Mono;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.symbol.SymbolTable;
import com.themixednuts.tools.ToolCategory;

@GhidraMcpTool(key = "Rename Data at Address", category = ToolCategory.SYMBOLS, description = "Enable the MCP tool to rename data at a specific address.", mcpName = "rename_data_at_address", mcpDescription = "Assign or change the symbolic label (name) for the data item located at the specified memory address.")
public class GhidraRenameDataAtAddressTool implements IGhidraMcpSpecification {

	public GhidraRenameDataAtAddressTool() {
	}

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
			Msg.error(this, "Failed to generate schema for tool '" + annotation.mcpName() + "'. Tool will be disabled.");
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
		schemaRoot.property(ARG_ADDRESS,
				JsonSchemaBuilder.string(mapper)
						.description("The address of the data or label to rename (e.g., '0x1004010').")
						.pattern("^(0x)?[0-9a-fA-F]+$"));
		schemaRoot.property(ARG_NEW_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The new name for the data or label."));

		schemaRoot.requiredProperty(ARG_FILE_NAME)
				.requiredProperty(ARG_ADDRESS)
				.requiredProperty(ARG_NEW_NAME);

		return schemaRoot.build();
	}

	@Override
	public Mono<CallToolResult> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).flatMap(program -> {
			String addressStr = getRequiredStringArgument(args, ARG_ADDRESS);
			Address addr = program.getAddressFactory().getAddress(addressStr);
			if (addr == null) {
				return createErrorResult("Invalid address provided: " + addressStr);
			}
			Data data = program.getListing().getDefinedDataAt(addr);
			if (data == null) {
				return createErrorResult("Data not found at address: " + addressStr);
			}
			String newName = getRequiredStringArgument(args, ARG_NEW_NAME);
			SymbolTable symbolTable = program.getSymbolTable();

			return executeInTransaction(program, "MCP - Rename data at " + addressStr,
					() -> {
						symbolTable.createLabel(addr, newName, SourceType.USER_DEFINED);
						return createSuccessResult(
								"Data at " + addressStr + " renamed successfully to '" + newName + "'.");
					});

		}).onErrorResume(e -> createErrorResult(e));
	}

}
