package com.themixednuts.tools.decompiler;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.models.PcodeOpInfo;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.tools.ToolCategory;
import com.themixednuts.utils.GhidraMcpTaskMonitor;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOpAST;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

import java.util.Iterator;
import java.util.Spliterator;
import java.util.Spliterators;

@GhidraMcpTool(name = "Get PCode for Function", category = ToolCategory.DECOMPILER, description = "Retrieves the PCode representation for a function.", mcpName = "get_pcode_for_function", mcpDescription = "Get the PCode intermediate representation for a function.")
public class GhidraGetPcodeForFunctionTool implements IGhidraMcpSpecification {

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file."));
		schemaRoot.property(ARG_FUNCTION_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the function. Either this or address must be provided."));
		schemaRoot.property(ARG_ADDRESS,
				JsonSchemaBuilder.string(mapper)
						.description(
								"Optional entry point address of the function (e.g., '0x1004010'). Preferred over name if provided.")
						.pattern("^(0x)?[0-9a-fA-F]+$"));

		schemaRoot.requiredProperty(ARG_FILE_NAME);
		return schemaRoot.build();
	}

	private static record FunctionResolutionContext(Program program, Function function) {
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		DecompInterface decomp = new DecompInterface();

		return getProgram(args, tool).map(program -> {
			// --- Synchronous Setup: Resolve Function ---
			String functionName = getOptionalStringArgument(args, ARG_FUNCTION_NAME).orElse(null);
			String addressStr = getOptionalStringArgument(args, ARG_ADDRESS).orElse(null);

			Function targetFunction = null;

			if (addressStr != null && !addressStr.isBlank()) {
				Address entryPointAddress = program.getAddressFactory().getAddress(addressStr);
				targetFunction = program.getFunctionManager().getFunctionAt(entryPointAddress);
				if (targetFunction == null) {
					throw new IllegalArgumentException("Function not found at address: " + addressStr);
				}
			} else if (functionName != null && !functionName.isBlank()) {
				targetFunction = StreamSupport
						.stream(program.getFunctionManager().getFunctions(true).spliterator(), false)
						.filter(f -> f.getName(true).equals(functionName))
						.findFirst()
						.orElseThrow(() -> new IllegalArgumentException("Function not found with name: " + functionName));
			} else {
				throw new IllegalArgumentException("Either function name or address must be provided.");
			}
			return new FunctionResolutionContext(program, targetFunction);
		})
				.flatMap(context -> Mono.fromCallable(() -> {
					// --- Blocking Decompilation & PCode Extraction ---
					Program program = context.program();
					Function targetFunction = context.function();

					decomp.openProgram(program);
					GhidraMcpTaskMonitor monitor = new GhidraMcpTaskMonitor(ex, this.getClass().getSimpleName());
					DecompileResults results = decomp.decompileFunction(targetFunction, 30, monitor);

					if (results == null || !results.decompileCompleted()) {
						String errorMsg = results != null ? results.getErrorMessage() : "Unknown decompiler error";
						throw new RuntimeException("Decompilation failed: " + errorMsg);
					}

					HighFunction highFunction = results.getHighFunction();
					if (highFunction == null) {
						throw new RuntimeException("Decompilation failed (no high function available).");
					}

					Iterator<PcodeOpAST> pcodeIterator = highFunction.getPcodeOps();
					Spliterator<PcodeOpAST> pcodeSpliterator = Spliterators.spliteratorUnknownSize(pcodeIterator, 0);
					List<PcodeOpInfo> pcodeList = StreamSupport.stream(pcodeSpliterator, false)
							.map(pcodeOp -> PcodeOpInfo.fromPcodeOpAST(pcodeOp, highFunction))
							.collect(Collectors.toList());

					return pcodeList;
				}))
				.doFinally(signalType -> {
					if (decomp != null) {
						decomp.dispose();
					}
				});
	}
}