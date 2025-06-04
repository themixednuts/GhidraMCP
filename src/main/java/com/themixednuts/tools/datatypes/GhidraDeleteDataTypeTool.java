package com.themixednuts.tools.datatypes;

import java.util.List;
import java.util.Map;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.utils.GhidraMcpTaskMonitor;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;
import com.themixednuts.tools.ToolCategory;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.SourceArchive;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;
import ghidra.program.model.data.ArchiveType;

@GhidraMcpTool(name = "Delete Data Type", category = ToolCategory.DATATYPES, description = "Deletes an existing data type.", mcpName = "delete_data_type", mcpDescription = "Delete a user-defined data type from a Ghidra program. Cannot delete built-in or external archive data types.")
public class GhidraDeleteDataTypeTool implements IGhidraMcpSpecification {

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();

		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The file name of the Ghidra tool window to target."),
				true);

		schemaRoot.property(ARG_PATH, JsonSchemaBuilder.string(mapper)
				.description("The full path of the data type to delete (e.g., /MyCategory/MyType)."),
				true);

		schemaRoot.requiredProperty(ARG_FILE_NAME);
		schemaRoot.requiredProperty(ARG_PATH);

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool)
				.flatMap(program -> {
					String pathString = getRequiredStringArgument(args, ARG_PATH);
					GhidraMcpTaskMonitor monitor = new GhidraMcpTaskMonitor(ex,
							this.getClass().getAnnotation(GhidraMcpTool.class).mcpName());

					String transactionName = "Delete Data Type: " + pathString;

					return executeInTransaction(program, transactionName, () -> {
						DataTypeManager dtm = program.getDataTypeManager();
						return deleteDataTypeAtPath(dtm, pathString, monitor);
					});
				});
	}

	private String deleteDataTypeAtPath(DataTypeManager dtm, String pathString, GhidraMcpTaskMonitor monitor) {
		GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);

		DataType dt = dtm.getDataType(pathString);
		if (dt == null) {
			GhidraMcpError error = GhidraMcpError.resourceNotFound()
					.errorCode(GhidraMcpError.ErrorCode.DATA_TYPE_NOT_FOUND)
					.message("Data type not found at path: " + pathString)
					.context(new GhidraMcpError.ErrorContext(
							annotation.mcpName(),
							"data type lookup",
							Map.of(ARG_PATH, pathString),
							Map.of("dataTypePath", pathString),
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
		}

		// Check if it's deletable (not built-in, etc.)
		SourceArchive sourceArchive = dt.getSourceArchive();
		SourceArchive programArchive = dtm.getLocalSourceArchive();
		if (sourceArchive != null && !sourceArchive.equals(programArchive)
				&& sourceArchive.getArchiveType() != ArchiveType.PROJECT) {
			GhidraMcpError error = GhidraMcpError.validation()
					.errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
					.message("Cannot delete built-in or external archive data type: " + pathString + " from archive "
							+ sourceArchive.getName())
					.context(new GhidraMcpError.ErrorContext(
							annotation.mcpName(),
							"data type deletion validation",
							Map.of(ARG_PATH, pathString),
							Map.of("dataTypePath", pathString, "sourceArchive", sourceArchive.getName()),
							Map.of("isBuiltIn", true, "isDeletable", false, "archiveType",
									sourceArchive.getArchiveType().toString())))
					.suggestions(List.of(
							new GhidraMcpError.ErrorSuggestion(
									GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
									"Only delete user-defined data types",
									"Built-in and external archive data types cannot be deleted",
									null,
									null)))
					.build();
			throw new GhidraMcpException(error);
		}

		boolean removed = dtm.remove(dt, monitor);
		if (removed) {
			return "Data Type '" + pathString + "' deleted successfully.";
		} else {
			throw new RuntimeException("Failed to delete Data Type '" + pathString
					+ ". It might be in use, was already deleted, or another issue occurred.");
		}
	}
}