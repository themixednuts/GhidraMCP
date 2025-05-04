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
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Read Memory Bytes", category = ToolCategory.MEMORY, description = "Reads a sequence of bytes from a specified memory address.", mcpName = "read_memory_bytes", mcpDescription = "Reads a specified number of bytes from a given memory address.")
public class GhidraReadBytesTool implements IGhidraMcpSpecification {

	@Override
	public AsyncToolSpecification specification(PluginTool tool) {
		GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
		if (annotation == null) {
			Msg.error(this, "Missing @GhidraMcpTool annotation on " + this.getClass().getSimpleName());
			return null;
		}
		Optional<String> schemaStringOpt = parseSchema(schema());
		if (schemaStringOpt.isEmpty()) {
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
						.description("The starting address to read from (e.g., '0x1004010').")
						.pattern("^(0x)?[0-9a-fA-F]+$"));
		schemaRoot.property(ARG_LENGTH,
				JsonSchemaBuilder.integer(mapper)
						.description("The number of bytes to read.")
						.minimum(1));

		schemaRoot.requiredProperty(ARG_FILE_NAME)
				.requiredProperty(ARG_ADDRESS)
				.requiredProperty(ARG_LENGTH);

		return schemaRoot.build();
	}

	@Override
	public Mono<CallToolResult> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool)
				.flatMap(program -> {
					// --- Setup Phase ---
					String addressStr = getRequiredStringArgument(args, ARG_ADDRESS);
					Integer lengthInt = getRequiredIntArgument(args, ARG_LENGTH);
					int length = lengthInt.intValue(); // Should be positive due to schema minimum(1)

					Address startAddress = program.getAddressFactory().getAddress(addressStr);
					if (startAddress == null) {
						return createErrorResult("Invalid address string (resolved to null): " + addressStr);
					}

					// This is read-only, no transaction needed.
					// Memory access exceptions are caught by onErrorResume.
					Memory memory = program.getMemory();
					byte[] bytesRead = new byte[length];
					int actualLengthRead;
					try {
						actualLengthRead = memory.getBytes(startAddress, bytesRead);
					} catch (MemoryAccessException e) {
						return createErrorResult(
								"Memory access error reading " + length + " bytes at " + addressStr + ": " + e.getMessage());
					}

					// Convert bytes to hex string
					String hexString = HexFormat.of().formatHex(bytesRead, 0, actualLengthRead);

					// Create result map (or a dedicated model object later)
					Map<String, Object> result = Map.of(
							"address", startAddress.toString(),
							"requestedLength", length,
							"actualLengthRead", actualLengthRead,
							"bytesHex", hexString);
					return createSuccessResult(result);
				})
				.onErrorResume(e -> createErrorResult(e)); // Handles AddressFormatException, IllegalArgumentException, etc.
	}
}