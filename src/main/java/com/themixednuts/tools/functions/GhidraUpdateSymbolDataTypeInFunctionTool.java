package com.themixednuts.tools.functions;

import java.util.Arrays;
import java.util.Map;
import java.util.stream.StreamSupport;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.tools.ToolCategory;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.app.cmd.function.SetVariableDataTypeCmd;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.data.DataTypeParser;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;
import reactor.util.function.Tuples;

@GhidraMcpTool(name = "Update Symbol Data Type In Function", category = ToolCategory.FUNCTIONS, description = "Changes the data type of a local variable or parameter within a specific function.", mcpName = "update_symbol_data_type_in_function", mcpDescription = "Changes the data type of a local variable or parameter within a function.")
public class GhidraUpdateSymbolDataTypeInFunctionTool implements IGhidraMcpSpecification {

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
						.description("The name of the local variable or parameter whose data type will be changed."));
		schemaRoot.property(ARG_DATA_TYPE_PATH,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the new data type to apply (e.g., 'int', 'char*', 'MyStruct')."));

		schemaRoot.requiredProperty(ARG_FILE_NAME)
				.requiredProperty(ARG_FUNCTION_NAME)
				.requiredProperty(ARG_NAME)
				.requiredProperty(ARG_DATA_TYPE_PATH);

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool)
				.map(program -> {
					String functionName = getRequiredStringArgument(args, ARG_FUNCTION_NAME);
					String symbolName = getRequiredStringArgument(args, ARG_NAME);
					String newDataTypePath = getRequiredStringArgument(args, ARG_DATA_TYPE_PATH);

					Function function = StreamSupport.stream(program.getFunctionManager().getFunctions(true).spliterator(), false)
							.filter(f -> f.getName().equals(functionName))
							.findFirst()
							.orElseThrow(() -> new IllegalArgumentException("Function not found: " + functionName));

					Variable variableToUpdate = findVariableInFunction(function, symbolName);
					DataType newDataType = parseDataType(program, newDataTypePath);

					return Tuples.of(program, variableToUpdate, newDataType);
				})
				.flatMap(tuple -> {
					Program program = tuple.getT1();
					Variable variable = tuple.getT2();
					DataType dataType = tuple.getT3();
					String varName = variable.getName();
					String dtName = dataType.getName();

					return executeInTransaction(program, "MCP - Update Symbol Data Type: " + varName,
							() -> {
								SetVariableDataTypeCmd cmd = new SetVariableDataTypeCmd(variable, dataType, SourceType.USER_DEFINED);
								if (!cmd.applyTo(program)) {
									throw new RuntimeException("Failed to apply data type change: " + cmd.getStatusMsg());
								}
								return "Successfully updated data type for symbol '" + varName + "' to '" + dtName + "'";
							});
				});
	}

	private Variable findVariableInFunction(Function function, String symbolName) {
		return Arrays.stream(function.getParameters())
				.filter(p -> p.getName().equals(symbolName))
				.findFirst()
				.map(p -> (Variable) p)
				.orElseGet(() -> Arrays.stream(function.getLocalVariables())
						.filter(v -> v.getName().equals(symbolName))
						.findFirst()
						.orElseThrow(() -> new IllegalArgumentException(
								"Symbol '" + symbolName + "' not found in function '" + function.getName() + "'")));
	}

	private DataType parseDataType(Program program, String newDataTypePath) {
		DataTypeManager dtm = program.getDataTypeManager();
		try {
			DataTypeParser parser = new DataTypeParser(dtm, dtm, null, DataTypeParser.AllowedDataTypes.ALL);
			DataType newDataType = parser.parse(newDataTypePath);
			if (newDataType == null) {
				throw new IllegalArgumentException("Data type not found or invalid: " + newDataTypePath);
			}
			return newDataType;
		} catch (Exception e) {
			throw new IllegalArgumentException("Failed to parse data type '" + newDataTypePath + "': " + e.getMessage(), e);
		}
	}
}
