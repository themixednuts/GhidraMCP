package com.themixednuts.tools.functions;

import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Spliterator;
import java.util.Spliterators;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;
import com.themixednuts.utils.PaginatedResult;
import com.themixednuts.tools.ToolCategory;
import com.themixednuts.models.FunctionVariableInfo;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;
import ghidra.program.model.listing.FunctionManager;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.util.task.ConsoleTaskMonitor;

@GhidraMcpTool(name = "List Function Variables", category = ToolCategory.FUNCTIONS, description = "Lists variables (listing and decompiler-generated) within a function, providing detailed information.", mcpName = "list_function_variables", mcpDescription = "Returns a paginated list of all variables (parameters, locals, register, etc.) defined or used within a specified function, with detailed attributes, including those identified by the decompiler.")
public class GhidraListFunctionVariablesTool implements IGhidraMcpSpecification {

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file."));
		schemaRoot.property(ARG_FUNCTION_SYMBOL_ID,
				JsonSchemaBuilder.integer(mapper)
						.description("Optional: Symbol ID of the function. Preferred identifier."))
				.property(ARG_FUNCTION_ADDRESS,
						JsonSchemaBuilder.string(mapper)
								.description(
										"Optional: Entry point address of the function (e.g., '0x1004010'). Used if Symbol ID is not provided or not found.")
								.pattern("^(0x)?[0-9a-fA-F]+$"))
				.property(ARG_FUNCTION_NAME,
						JsonSchemaBuilder.string(mapper)
								.description(
										"Optional: Name of the function. Used if Symbol ID and Address are not provided or not found."));

		schemaRoot.requiredProperty(ARG_FILE_NAME);
		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).flatMap(program -> {
			Optional<Long> funcSymbolIdOpt = getOptionalLongArgument(args, ARG_FUNCTION_SYMBOL_ID);
			Optional<String> funcAddressOpt = getOptionalStringArgument(args, ARG_FUNCTION_ADDRESS);
			Optional<String> funcNameOpt = getOptionalStringArgument(args, ARG_FUNCTION_NAME);
			Optional<String> cursorOpt = getOptionalStringArgument(args, ARG_CURSOR);

			if (funcSymbolIdOpt.isEmpty() && funcAddressOpt.isEmpty() && funcNameOpt.isEmpty()) {
				return Mono.error(new IllegalArgumentException(
						"At least one function identifier (functionSymbolId, functionAddress, or functionName) must be provided."));
			}

			Function function = resolveFunction(program, funcSymbolIdOpt, funcAddressOpt, funcNameOpt);

			if (function == null) {
				return Mono.error(new IllegalStateException("Could not identify function from the provided arguments."));
			}

			final Function finalFunction = function;
			final Program finalProgram = program;

			return Mono.fromCallable(() -> {
				Stream<FunctionVariableInfo> listingVarStream = Arrays.stream(finalFunction.getAllVariables())
						.map(FunctionVariableInfo::new);

				Stream<FunctionVariableInfo> decompilerVarStream = Stream.empty();
				DecompInterface decomplib = new DecompInterface();
				try {
					decomplib.setOptions(new DecompileOptions());
					decomplib.openProgram(finalProgram);
					DecompileResults results = decomplib.decompileFunction(finalFunction,
							decomplib.getOptions().getDefaultTimeout(), new ConsoleTaskMonitor());
					HighFunction hf = results.getHighFunction();

					if (hf != null) {
						LocalSymbolMap localSymbolMap = hf.getLocalSymbolMap();
						if (localSymbolMap != null) {
							java.util.Iterator<HighSymbol> highSymbolIterator = localSymbolMap.getSymbols();
							decompilerVarStream = StreamSupport.stream(
									Spliterators.spliteratorUnknownSize(highSymbolIterator, Spliterator.ORDERED), false)
									.map(HighSymbol::getHighVariable)
									.filter(java.util.Objects::nonNull)
									.map(hv -> new FunctionVariableInfo(hv, finalProgram));
						}
					} else {
						ghidra.util.Msg.warn(this,
								"Decompilation did not yield a HighFunction for function: " + finalFunction.getName());
					}
				} catch (Exception e) {
					ghidra.util.Msg.error(this,
							"Error during decompilation for ListFunctionVariables: " + e.getMessage(), e);
				} finally {
					if (decomplib != null) {
						decomplib.dispose();
					}
				}

				List<FunctionVariableInfo> variablesToList = Stream.concat(listingVarStream, decompilerVarStream)
						.sorted(Comparator.comparing(FunctionVariableInfo::getStorage)
								.thenComparing(FunctionVariableInfo::getEffectiveName))
						.collect(Collectors.toList());

				final String finalCursorStr = cursorOpt.orElse(null);

				List<FunctionVariableInfo> paginatedVariables = variablesToList.stream()
						.dropWhile(varInfo -> {
							if (finalCursorStr == null)
								return false;

							String[] parts = finalCursorStr.split(":", 2);
							String cursorStorage = parts[0];
							String cursorName = parts.length > 1 ? parts[1] : "";

							int storageCompare = varInfo.getStorage().compareTo(cursorStorage);
							if (storageCompare < 0)
								return true;
							if (storageCompare == 0) {
								return varInfo.getEffectiveName().compareTo(cursorName) <= 0;
							}
							return false;
						})
						.limit(DEFAULT_PAGE_LIMIT + 1)
						.collect(Collectors.toList());

				boolean hasMore = paginatedVariables.size() > DEFAULT_PAGE_LIMIT;
				List<FunctionVariableInfo> resultsForPage = paginatedVariables.subList(0,
						Math.min(paginatedVariables.size(), DEFAULT_PAGE_LIMIT));
				String nextCursor = null;
				if (hasMore && !resultsForPage.isEmpty()) {
					FunctionVariableInfo lastItem = resultsForPage.get(resultsForPage.size() - 1);
					nextCursor = lastItem.getStorage() + ":" + lastItem.getEffectiveName();
				}

				return new PaginatedResult<>(resultsForPage, nextCursor);
			}).subscribeOn(reactor.core.scheduler.Schedulers.boundedElastic());
		});
	}

	private Function resolveFunction(Program program, Optional<Long> funcSymbolIdOpt, Optional<String> funcAddressOpt,
			Optional<String> funcNameOpt) {
		FunctionManager funcMan = program.getFunctionManager();
		Function function = null;

		if (funcSymbolIdOpt.isPresent()) {
			long symbolID = funcSymbolIdOpt.get();
			ghidra.program.model.symbol.Symbol symbol = program.getSymbolTable().getSymbol(symbolID);
			if (symbol != null && symbol.getSymbolType() == ghidra.program.model.symbol.SymbolType.FUNCTION) {
				function = funcMan.getFunctionAt(symbol.getAddress());
				if (function != null) {
					return function;
				}
			}
		}

		if (funcAddressOpt.isPresent()) {
			Address funcAddr = program.getAddressFactory().getAddress(funcAddressOpt.get());
			if (funcAddr == null) {
				ghidra.util.Msg.warn(this, "Invalid function address format or address not found: " + funcAddressOpt.get());
			}
			if (funcAddr != null) {
				function = funcMan.getFunctionAt(funcAddr);
				if (function != null) {
					return function;
				}
			}
		}

		if (funcNameOpt.isPresent()) {
			String functionName = funcNameOpt.get();
			List<Function> foundFunctionsByName = StreamSupport
					.stream(funcMan.getFunctions(true).spliterator(), false)
					.filter(f -> f.getName().equals(functionName))
					.collect(Collectors.toList());

			if (foundFunctionsByName.size() == 1) {
				return foundFunctionsByName.get(0);
			} else if (foundFunctionsByName.size() > 1) {
				throw new IllegalArgumentException(
						"Multiple functions found with name: '" + functionName +
								"'. Please use a more specific identifier like address or symbol ID.");
			}
		}

		StringBuilder errorMessage = new StringBuilder("Function not found using any of the provided identifiers: ");
		funcSymbolIdOpt.ifPresent(id -> errorMessage.append("functionSymbolId='").append(id).append("' "));
		funcAddressOpt.ifPresent(addr -> errorMessage.append("functionAddress='").append(addr).append("' "));
		funcNameOpt.ifPresent(name -> errorMessage.append("functionName='").append(name).append("' "));
		throw new IllegalArgumentException(errorMessage.toString().trim());
	}
}