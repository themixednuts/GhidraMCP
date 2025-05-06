package com.themixednuts.tools.functions;

import java.util.Map;
import java.util.Optional;
import java.util.stream.StreamSupport;
import java.util.Arrays;

import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;
import com.themixednuts.tools.ToolCategory;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import io.modelcontextprotocol.server.McpAsyncServerExchange;

import reactor.core.publisher.Mono;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.Parameter;

@GhidraMcpTool(name = "Update Symbol in Function", category = ToolCategory.FUNCTIONS, description = "Renames a symbol (variable or parameter) within a specific function.", mcpName = "update_symbol_in_function", mcpDescription = "Renames a local variable or parameter within a function.")
public class GhidraRenameSymbolInFunctionTool implements IGhidraMcpSpecification {

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file."));
		schemaRoot.property(ARG_FUNCTION_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the function containing the symbol."));
		schemaRoot.property(ARG_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The current name of the local variable or parameter to rename."));
		schemaRoot.property(ARG_NEW_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The desired new name for the symbol."));

		schemaRoot.requiredProperty(ARG_FILE_NAME)
				.requiredProperty(ARG_FUNCTION_NAME)
				.requiredProperty(ARG_NAME)
				.requiredProperty(ARG_NEW_NAME);

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).flatMap(program -> {
			return Mono.fromCallable(() -> {
				String functionName = getRequiredStringArgument(args, ARG_FUNCTION_NAME);
				String currentName = getRequiredStringArgument(args, ARG_NAME);
				String newName = getRequiredStringArgument(args, ARG_NEW_NAME);

				Function function = StreamSupport.stream(program.getFunctionManager().getFunctions(true).spliterator(), false)
						.filter(f -> f.getName().equals(functionName))
						.findFirst()
						.orElse(null);

				if (function == null) {
					throw new IllegalArgumentException("Function not found: " + functionName);
				}

				Symbol symbolToRename = null;
				Optional<Parameter> paramOpt = Arrays.stream(function.getParameters())
						.filter(p -> p.getName().equals(currentName))
						.findFirst();

				if (paramOpt.isPresent()) {
					symbolToRename = paramOpt.get().getSymbol();
				} else {
					Optional<Variable> varOpt = Arrays.stream(function.getLocalVariables())
							.filter(v -> v.getName().equals(currentName))
							.findFirst();
					if (varOpt.isPresent()) {
						symbolToRename = varOpt.get().getSymbol();
					} else {
						throw new IllegalArgumentException("Symbol not found: " + currentName);
					}
				}

				return Map.entry(symbolToRename, newName);
			})
					.flatMap(entry -> {
						Symbol symbol = entry.getKey();
						String nameToSet = entry.getValue();
						String originalName = symbol.getName();
						return executeInTransaction(program, "MCP - Rename Symbol " + originalName, () -> {
							symbol.setName(nameToSet, SourceType.USER_DEFINED);
							return "Successfully renamed symbol '" + originalName + "' to '" + nameToSet + "'";
						});
					});
		});
	}
}
