package com.themixednuts.tools.datatypes;

import java.util.Map;

import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.tools.ToolCategory;
import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.Union;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;
import com.themixednuts.models.BaseDataTypeDetails;
import com.themixednuts.models.StructureDetails;
import com.themixednuts.models.UnionDetails;
import com.themixednuts.models.EnumDetails;
import com.themixednuts.models.TypedefDetails;
import com.themixednuts.models.FunctionDefinitionDetails;
import com.themixednuts.models.OtherDataTypeDetails;

@GhidraMcpTool(name = "Get Data Type Definition", mcpName = "get_data_type_definition", category = ToolCategory.DATATYPES, description = "Retrieves the detailed definition of a specific data type given its full path.", mcpDescription = "Retrieves the detailed definition of a specific data type given its full path.")
public class GhidraGetDataTypeTool implements IGhidraMcpSpecification {

	// ARG_FILE_NAME and ARG_PATH will be used from IGhidraMcpSpecification
	// constants

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();

		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The file name of the Ghidra tool window to target."));

		schemaRoot.property(ARG_PATH,
				JsonSchemaBuilder.string(mapper)
						.description("The full path of the data type to retrieve (e.g., /MyCategory/MyStruct, /byte).")
						.pattern("^/.*"),
				true);

		schemaRoot.requiredProperty(ARG_FILE_NAME)
				.requiredProperty(ARG_PATH);

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool)
				.map(program -> {
					DataTypeManager dtm = program.getDataTypeManager();
					String dataTypePathString = getRequiredStringArgument(args, ARG_PATH);

					DataType dt = dtm.getDataType(dataTypePathString);

					if (dt == null) {
						throw new IllegalArgumentException("Data type not found at path: " + dataTypePathString);
					}

					BaseDataTypeDetails resultDetails;

					if (dt instanceof Structure) {
						resultDetails = new StructureDetails((Structure) dt);
					} else if (dt instanceof Union) {
						resultDetails = new UnionDetails((Union) dt);
					} else if (dt instanceof Enum) {
						resultDetails = new EnumDetails((Enum) dt);
					} else if (dt instanceof TypeDef) {
						resultDetails = new TypedefDetails((TypeDef) dt);
					} else if (dt instanceof FunctionDefinition) {
						resultDetails = new FunctionDefinitionDetails((FunctionDefinition) dt);
					} else {
						resultDetails = new OtherDataTypeDetails(dt);
					}

					return resultDetails;
				});
	}
}