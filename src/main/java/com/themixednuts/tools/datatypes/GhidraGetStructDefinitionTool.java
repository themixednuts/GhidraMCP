package com.themixednuts.tools.datatypes;

import java.util.Map;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.models.DataTypeInfo;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;
import com.themixednuts.tools.ToolCategory;

@GhidraMcpTool(name = "Get Struct Definition", category = ToolCategory.DATATYPES, description = "Gets the definition of an existing structure.", mcpName = "get_struct_definition", mcpDescription = "Retrieves the definition (name, members, etc.) of a struct data type.")
public class GhidraGetStructDefinitionTool implements IGhidraMcpSpecification {

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(IGhidraMcpSpecification.ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file."));
		schemaRoot.property(IGhidraMcpSpecification.ARG_STRUCT_PATH,
				JsonSchemaBuilder.string(mapper)
						.description("The name or path of the struct data type (e.g., 'MyStruct', '/windows/POINTL')."));

		schemaRoot.requiredProperty(IGhidraMcpSpecification.ARG_FILE_NAME)
				.requiredProperty(IGhidraMcpSpecification.ARG_STRUCT_PATH);

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).map(program -> {
			String structPath = getRequiredStringArgument(args, IGhidraMcpSpecification.ARG_STRUCT_PATH);
			DataType dt = program.getDataTypeManager().getDataType(structPath);

			if (dt == null) {
				throw new IllegalArgumentException("Structure data type not found: " + structPath);
			}

			if (!(dt instanceof Structure)) {
				throw new IllegalArgumentException("Data type '" + structPath + "' is not a Structure. Found: "
						+ dt.getClass().getSimpleName());
			}

			DataTypeInfo structInfo = new DataTypeInfo(dt);
			return structInfo;
		});
	}
}