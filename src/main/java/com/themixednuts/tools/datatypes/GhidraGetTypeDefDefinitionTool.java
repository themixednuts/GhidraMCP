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
import ghidra.program.model.data.TypeDef;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;
import com.themixednuts.tools.ToolCategory;

@GhidraMcpTool(name = "Get TypeDef Definition", category = ToolCategory.DATATYPES, description = "Gets the definition of an existing typedef.", mcpName = "get_typedef_definition", mcpDescription = "Retrieves the definition (name, underlying type) of a typedef data type.")
public class GhidraGetTypeDefDefinitionTool implements IGhidraMcpSpecification {

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(IGhidraMcpSpecification.ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The name of the program file."));
		schemaRoot.property(IGhidraMcpSpecification.ARG_TYPEDEF_PATH,
				JsonSchemaBuilder.string(mapper)
						.description("The name or path of the typedef data type (e.g., 'MyIntTypedef', '/windows/DWORD')."));

		schemaRoot.requiredProperty(IGhidraMcpSpecification.ARG_FILE_NAME)
				.requiredProperty(IGhidraMcpSpecification.ARG_TYPEDEF_PATH);

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).map(program -> {
			String typedefPath = getRequiredStringArgument(args, IGhidraMcpSpecification.ARG_TYPEDEF_PATH);
			DataType dt = program.getDataTypeManager().getDataType(typedefPath);

			if (dt == null) {
				throw new IllegalArgumentException("TypeDef data type not found: " + typedefPath);
			}

			if (!(dt instanceof TypeDef)) {
				throw new IllegalArgumentException("Data type '" + typedefPath + "' is not a TypeDef. Found: "
						+ dt.getClass().getSimpleName());
			}

			DataTypeInfo typedefInfo = new DataTypeInfo(dt);
			return typedefInfo;
		});
	}
}