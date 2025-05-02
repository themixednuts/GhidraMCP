package com.themixednuts.tools.functions;

import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;

import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.framework.model.Project;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.ProgramBasedDataTypeManager;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.Swing;
import ghidra.util.task.ConsoleTaskMonitor;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import reactor.core.publisher.Mono;

@GhidraMcpTool(key = "Update Function Prototype", category = "Functions", description = "Enable the MCP tool to update the prototype of a function.", mcpName = "update_function_prototype", mcpDescription = "Modify the function signature (prototype) of a function located at a specific address using a C-style declaration string.")
public class GhidraUpdateFunctionPrototypeTool implements IGhidraMcpSpecification {
	public GhidraUpdateFunctionPrototypeTool() {
	}

	@Override
	public AsyncToolSpecification specification(Project project) {
		GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
		if (annotation == null) {
			Msg.error(this, "Missing @GhidraMcpTool annotation on " + this.getClass().getSimpleName());
			return null;
		}

		Optional<String> schemaJson = schema();
		if (schemaJson.isEmpty()) {
			Msg.error(this, "Failed to generate schema for tool '" + annotation.mcpName() + "'. Tool will be disabled.");
			return null; // Signal failure
		}

		return new AsyncToolSpecification(
				new Tool(annotation.mcpName(), annotation.mcpDescription(), schemaJson.get()),
				(ex, args) -> {
					return getProgram(args, project).flatMap(program -> {
						String functionAddressStr = getRequiredStringArgument(args, "functionAddress");
						String prototype = getRequiredStringArgument(args, "prototype");

						Address functionAddress = program.getAddressFactory().getAddress(functionAddressStr);
						Function function = program.getFunctionManager().getFunctionAt(functionAddress);
						if (function == null) {
							return Mono.just(new CallToolResult("Function not found", true));
						}

						AtomicReference<CallToolResult> result = new AtomicReference<>();
						Swing.runNow(() -> {

							int txId = -1;
							boolean success = false;

							try {
								txId = program.startTransaction("Update Function Prototype");
								ProgramBasedDataTypeManager dtm = program.getDataTypeManager();
								FunctionSignatureParser parser = new FunctionSignatureParser(dtm, null);

								FunctionDefinitionDataType sig = parser.parse(null, prototype);
								if (sig == null) {
									throw new Exception("Failed to parse function prototype");
								}

								ApplyFunctionSignatureCmd cmd = new ApplyFunctionSignatureCmd(functionAddress, sig,
										SourceType.USER_DEFINED);
								success = cmd.applyTo(program, new ConsoleTaskMonitor());
							} catch (Exception e) {
								Msg.error(this, "Error updating function prototype", e);
								result.set(new CallToolResult("Error updating function prototype", true));
							} finally {
								program.endTransaction(txId, success);
							}

						});

						return Mono.just(new CallToolResult("Function prototype updated", false));
					});
				});
	}

	@Override
	public Optional<String> schema() {
		try {
			ObjectNode schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
			schemaRoot.putObject("properties");
			ObjectNode fileNameProp = schemaRoot.putObject("fileName");
			fileNameProp.put("type", "string");
			fileNameProp.put("description", "The file name of the Ghidra tool window to target");
			ObjectNode functionAddressProp = schemaRoot.putObject("functionAddress");
			functionAddressProp.put("type", "string");
			functionAddressProp.put("description", "The address of the function to update the prototype of");
			ObjectNode prototypeProp = schemaRoot.putObject("prototype");
			prototypeProp.put("type", "string");
			prototypeProp.put("description", "The new prototype of the function");
			schemaRoot.putArray("required").add("fileName").add("functionAddress").add("prototype");
			return Optional.of(IGhidraMcpSpecification.mapper.writeValueAsString(schemaRoot));
		} catch (JsonProcessingException e) {
			Msg.error(this, "Error creating schema for update_function_prototype tool", e);
			return Optional.empty();
		}
	}

}
