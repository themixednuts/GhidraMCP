package com.themixednuts.tools.datatypes;

import java.util.Map;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;
import com.themixednuts.tools.ToolCategory;

import ghidra.app.cmd.data.CreateDataCmd;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Update Data Type at Address", category = ToolCategory.DATATYPES, description = "Applies a named data type to a given memory address.", mcpName = "update_data_type_at_address", mcpDescription = "Applies a named data type to a given memory address.")
public class GhidraUpdateDataTypeAtAddressTool implements IGhidraMcpSpecification {

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file."));
		schemaRoot.property(ARG_ADDRESS,
				JsonSchemaBuilder.string(mapper)
						.description("The address where the data type should be applied (e.g., '0x1004010').")
						.pattern("^(0x)?[0-9a-fA-F]+$"));
		schemaRoot.property(ARG_DATA_TYPE_PATH,
				JsonSchemaBuilder.string(mapper)
						.description("The full path of the data type to apply (e.g., /MyStruct, /integer, /dword)."));

		schemaRoot.requiredProperty(ARG_FILE_NAME)
				.requiredProperty(ARG_ADDRESS)
				.requiredProperty(ARG_DATA_TYPE_PATH);

		return schemaRoot.build();
	}

	// Nested record for type-safe context passing
	private static record UpdateDataAtAddressContext(
			Program program,
			Address addr,
			DataType dt) {
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).map(program -> {
			String addressStr = getRequiredStringArgument(args, ARG_ADDRESS);
			String dataTypePath = getRequiredStringArgument(args, ARG_DATA_TYPE_PATH);

			Address addr = program.getAddressFactory().getAddress(addressStr);

			DataType dt = program.getDataTypeManager().getDataType(dataTypePath);
			if (dt == null) {
				throw new IllegalArgumentException("Data type not found: " + dataTypePath);
			}

			// Return type-safe context
			return new UpdateDataAtAddressContext(program, addr, dt);

		}).flatMap(context -> {
			return executeInTransaction(context.program(),
					"MCP - Apply Data Type: " + context.dt().getPathName() + " to " + context.addr().toString(),
					() -> {
						// Use CreateDataCmd
						CreateDataCmd cmd = new CreateDataCmd(context.addr(), context.dt());
						if (cmd.applyTo(context.program())) {
							return "Data type '" + context.dt().getPathName() + "' applied successfully at address "
									+ context.addr().toString();
						} else {
							// Throw exception with status message from command
							throw new RuntimeException("Failed to apply data type: " + cmd.getStatusMsg());
						}
					});
		});
	}
}