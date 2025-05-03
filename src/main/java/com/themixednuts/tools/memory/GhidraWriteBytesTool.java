package com.themixednuts.tools.memory;

import java.util.HexFormat;
import java.util.Map;
import java.util.Optional;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.tools.ToolCategory;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import reactor.core.publisher.Mono;

@GhidraMcpTool(key = "Write Memory Bytes", category = ToolCategory.MEMORY, description = "Writes (patches) a sequence of bytes to a specified memory address.", mcpName = "write_memory_bytes", mcpDescription = "Writes a sequence of bytes (provided as a hex string) to a given memory address.")
public class GhidraWriteBytesTool implements IGhidraMcpSpecification {

	private static final String ARG_BYTES_HEX = "bytesHex";

	@Override
	public AsyncToolSpecification specification(PluginTool tool) {
		GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
		if (annotation == null) {
			Msg.error(this, "Missing @GhidraMcpTool annotation on " + this.getClass().getSimpleName());
			return null;
		}
		Optional<String> schemaStringOpt = parseSchema(schema());
		if (schemaStringOpt.isEmpty()) {
			Msg.error(this, "Failed to generate schema for tool '" + annotation.mcpName() + "'. Tool will be disabled.");
			return null;
		}
		return new AsyncToolSpecification(
				new Tool(annotation.mcpName(), annotation.mcpDescription(), schemaStringOpt.get()),
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
						.description("The address to write the bytes to (e.g., '0x1004010').")
						.pattern("^(0x)?[0-9a-fA-F]+$"));
		schemaRoot.property(ARG_BYTES_HEX,
				JsonSchemaBuilder.string(mapper)
						.description("Hex string representation of bytes to write (e.g., 'C390').")
						.pattern("^[0-9a-fA-F]*$")); // Allow empty, handled in execute

		schemaRoot.requiredProperty(ARG_FILE_NAME)
				.requiredProperty(ARG_ADDRESS)
				.requiredProperty(ARG_BYTES_HEX);

		return schemaRoot.build();
	}

	@Override
	public Mono<CallToolResult> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool)
				.flatMap(program -> {
					// --- Setup Phase ---
					String addressStr = getRequiredStringArgument(args, ARG_ADDRESS);
					String bytesHexString = getRequiredStringArgument(args, ARG_BYTES_HEX);

					Address targetAddress = program.getAddressFactory().getAddress(addressStr);
					if (targetAddress == null) {
						return createErrorResult("Invalid address string (resolved to null): " + addressStr);
					}

					// Parse hex string into byte array
					byte[] bytesToWrite;
					// Ensure even length for hex string
					if (bytesHexString.length() % 2 != 0) {
						return createErrorResult("Invalid hex string: Must have an even number of characters.");
					}
					bytesToWrite = HexFormat.of().parseHex(bytesHexString);

					if (bytesToWrite.length == 0) {
						return createErrorResult("No bytes provided (hex string was empty or invalid).");
					}

					final byte[] finalBytesToWrite = bytesToWrite; // Final for lambda
					final Address finalTargetAddress = targetAddress;
					final String finalAddressStr = addressStr; // For messages

					// --- Modification Phase ---
					return executeInTransaction(program, "Write Bytes at " + finalAddressStr, () -> {
						Memory memory = program.getMemory();
						memory.setBytes(finalTargetAddress, finalBytesToWrite);
						return createSuccessResult(
								"Successfully wrote " + finalBytesToWrite.length + " bytes to " + finalAddressStr);
					});
				})
				.onErrorResume(e -> createErrorResult(e)); // Handles AddressFormatException, etc.
	}
}