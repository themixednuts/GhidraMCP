package com.themixednuts.tools.memory;

import java.util.HexFormat;
import java.util.Map;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.tools.ToolCategory;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;
import reactor.util.function.Tuples;

@GhidraMcpTool(name = "Write Memory Bytes", category = ToolCategory.MEMORY, description = "Writes a sequence of bytes to a specific memory address.", mcpName = "write_memory_bytes", mcpDescription = "Write a hexadecimal string of bytes to a given memory address.")
public class GhidraWriteMemoryBytesTool implements IGhidraMcpSpecification {

	public static final String ARG_BYTES_HEX = "bytesHex";

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(ARG_FILE_NAME, JsonSchemaBuilder.string(mapper).description("The name of the program file."));
		schemaRoot.property(ARG_ADDRESS, JsonSchemaBuilder.string(mapper)
				.description("The starting memory address to write to (e.g., '0x1004010').")
				.pattern("^(0x)?[0-9a-fA-F]+$"));
		schemaRoot.property(ARG_BYTES_HEX, JsonSchemaBuilder.string(mapper)
				.description("The byte sequence as a hexadecimal string (e.g., '4889e5').")
				.pattern("^[0-9a-fA-F]+$"));

		schemaRoot.requiredProperty(ARG_FILE_NAME)
				.requiredProperty(ARG_ADDRESS)
				.requiredProperty(ARG_BYTES_HEX);

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool)
				.map(program -> { // .map for synchronous setup
					String addressStr = getRequiredStringArgument(args, ARG_ADDRESS);
					String bytesHex = getRequiredStringArgument(args, ARG_BYTES_HEX);

					Address address = program.getAddressFactory().getAddress(addressStr);
					if (address == null) { // Check remains, though getAddress usually throws
						throw new IllegalArgumentException("Invalid address format: " + addressStr);
					}

					byte[] bytesToWrite;
					try {
						bytesToWrite = HexFormat.of().parseHex(bytesHex);
					} catch (IllegalArgumentException e) {
						throw new IllegalArgumentException("Invalid hex string format for bytes: " + bytesHex, e);
					}
					// Return context tuple
					return Tuples.of(program, address, bytesToWrite);
				})
				.flatMap(context -> { // flatMap for transaction
					Program program = context.getT1();
					Address address = context.getT2();
					byte[] bytesToWrite = context.getT3();
					String addressStr = address.toString(); // Get string rep here

					return executeInTransaction(program, "Write Memory Bytes to " + addressStr, () -> {
						Memory memory = program.getMemory();
						try {
							memory.setBytes(address, bytesToWrite);
							return "Successfully wrote " + bytesToWrite.length + " bytes to " + addressStr;
						} catch (MemoryAccessException e) {
							throw new RuntimeException("Memory access error writing to " + addressStr + ": " + e.getMessage(), e);
						}
					});
				});
	}
}