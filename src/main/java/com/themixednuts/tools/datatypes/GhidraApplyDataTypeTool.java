package com.themixednuts.tools.datatypes;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.utils.JsonSchemaBuilder;
import com.themixednuts.utils.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import reactor.core.publisher.Mono;
import ghidra.framework.plugintool.PluginTool;

import java.util.Map;

@GhidraMcpTool(key = "Apply Data Type", category = "Data Types", description = "Enable the MCP tool to apply a specific data type at a given address.", mcpName = "apply_data_type_at_address", mcpDescription = "Applies the specified data type to the code unit at the given address.")
public class GhidraApplyDataTypeTool implements IGhidraMcpSpecification {

	@Override
	public AsyncToolSpecification specification(PluginTool tool) {
		GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
		if (annotation == null) {
			Msg.error(this, "Missing @GhidraMcpTool annotation on " + this.getClass().getSimpleName());
			return null;
		}

		String schema = parseSchema(schema()).orElse(null);
		if (schema == null) {
			Msg.error(this, "Failed to generate schema for tool '" + annotation.mcpName() + "'. Tool will be disabled.");
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
						.description("The file name of the Ghidra tool window to target"));

		schemaRoot.property("address",
				JsonSchemaBuilder.string(mapper)
						.description("The address where the data type should be applied (e.g., 0x100400)"));

		schemaRoot.property("dataTypeName",
				JsonSchemaBuilder.string(mapper)
						.description("The name of the data type to apply (e.g., \"dword\", \"MyStruct\")"));

		schemaRoot.requiredProperty("fileName")
				.requiredProperty("address")
				.requiredProperty("dataTypeName");

		return schemaRoot.build();
	}

	@Override
	public Mono<CallToolResult> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).flatMap(program -> {
			// Setup: Parse args, resolve address, find data type
			// Argument parsing errors caught by onErrorResume
			String addressString = getRequiredStringArgument(args, "address");
			String dataTypeNameString = getRequiredStringArgument(args, "dataTypeName");

			final Address address = program.getAddressFactory().getAddress(addressString); // Final for lambda
			if (address == null) {
				return createErrorResult("Invalid address format: " + addressString);
			}

			DataTypeManager dtm = program.getDataTypeManager();
			final DataType dataType = dtm.getDataType(dataTypeNameString); // Final for lambda
			if (dataType == null) {
				return createErrorResult("Data type not found: " + dataTypeNameString);
			}

			// --- Execute modification in transaction ---
			final String finalAddressString = addressString; // Capture for messages
			final String finalDataTypeNameString = dataTypeNameString; // Capture for messages

			return executeInTransaction(program, "MCP - Apply Data Type", () -> {
				// Inner Callable logic (just the modification):
				try {
					program.getListing().createData(address, dataType);
					// Return success
					return createSuccessResult(
							"Data type '" + finalDataTypeNameString + "' applied successfully at " + finalAddressString);
				}
				// Catch specific exception for better error message
				catch (CodeUnitInsertionException e) {
					// Log is handled by createErrorResult
					return createErrorResult(
							"Failed to apply data type at " + finalAddressString + " (conflict?): " + e.getMessage());
				}
				// Let executeInTransaction handle other exceptions
			}); // End of Callable for executeInTransaction

		}).onErrorResume(e -> {
			// Catch errors from getProgram, setup (incl. arg parsing), or transaction
			// execution
			// Logging handled by createErrorResult
			return createErrorResult(e);
		});
	}
}