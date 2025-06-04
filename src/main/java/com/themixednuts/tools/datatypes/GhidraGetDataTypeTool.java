package com.themixednuts.tools.datatypes;

import java.util.Map;

import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.tools.ToolCategory;
import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;
import com.themixednuts.utils.DataTypeUtils;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataType;
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
import ghidra.util.exception.CancelledException;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.data.ProgramBasedDataTypeManager;
import java.util.List;

@GhidraMcpTool(name = "Get Data Type Definition", mcpName = "get_data_type_definition", category = ToolCategory.DATATYPES, description = "Retrieves the detailed definition of a specific data type given its full path.", mcpDescription = "Get the detailed definition of a specific data type from a Ghidra program. Returns complete information including structure, members, or enum values.")
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
					GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
					ProgramBasedDataTypeManager dtm = program.getDataTypeManager();
					String dataTypePathString = getRequiredStringArgument(args, ARG_PATH);
					DataType dt;

					try {
						dt = dtm.getDataType(dataTypePathString);

						if (dt == null) {
							dt = DataTypeUtils.parseDataTypeString(program, dataTypePathString, tool);
						}
					} catch (IllegalArgumentException e) {
						GhidraMcpError error = GhidraMcpError.resourceNotFound()
								.errorCode(GhidraMcpError.ErrorCode.DATA_TYPE_NOT_FOUND)
								.message("Data type not found at path: " + dataTypePathString)
								.context(new GhidraMcpError.ErrorContext(
										annotation.mcpName(),
										"data type lookup",
										Map.of(ARG_PATH, dataTypePathString),
										Map.of("dataTypePath", dataTypePathString),
										Map.of("dataTypeExists", false)))
								.suggestions(List.of(
										new GhidraMcpError.ErrorSuggestion(
												GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
												"List available data types",
												"Check what data types exist",
												null,
												List.of(getMcpName(GhidraListDataTypesTool.class)))))
								.build();
						throw new GhidraMcpException(error);
					} catch (InvalidDataTypeException e) {
						GhidraMcpError error = GhidraMcpError.validation()
								.errorCode(GhidraMcpError.ErrorCode.INVALID_TYPE_PATH)
								.message("Invalid data type format for path: " + dataTypePathString)
								.context(new GhidraMcpError.ErrorContext(
										annotation.mcpName(),
										"data type path validation",
										Map.of(ARG_PATH, dataTypePathString),
										Map.of("dataTypePath", dataTypePathString),
										Map.of("formatError", e.getMessage())))
								.suggestions(List.of(
										new GhidraMcpError.ErrorSuggestion(
												GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
												"Check data type path format",
												"Use correct data type path format",
												List.of("'/MyCategory/MyStruct'", "'/byte'", "'/int'"),
												null)))
								.build();
						throw new GhidraMcpException(error);
					} catch (CancelledException e) {
						throw new RuntimeException("Parsing cancelled for data type path '" + dataTypePathString + "'.", e);
					} catch (RuntimeException e) {
						throw new RuntimeException(
								"Unexpected error parsing data type path '" + dataTypePathString + "': " + e.getMessage(), e);
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