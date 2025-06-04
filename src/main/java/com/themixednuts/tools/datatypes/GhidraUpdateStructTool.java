package com.themixednuts.tools.datatypes;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.tools.ToolCategory;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Program;
import ghidra.util.InvalidNameException;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Update Struct", category = ToolCategory.DATATYPES, description = "Updates properties of an existing Struct.", mcpName = "update_struct", mcpDescription = "Update properties of an existing structure data type including name, description, packing behavior, and alignment settings.")
public class GhidraUpdateStructTool implements IGhidraMcpSpecification {

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();

		schemaRoot.property(ARG_FILE_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("The file name of the Ghidra tool window to target."),
				true);
		schemaRoot.property(ARG_STRUCT_PATH,
				JsonSchemaBuilder.string(mapper)
						.description("The full path of the struct to update (e.g., /MyCategory/MyStruct)."),
				true);
		schemaRoot.property(ARG_NEW_NAME,
				JsonSchemaBuilder.string(mapper)
						.description("Optional new name for the struct."));
		schemaRoot.property(ARG_COMMENT,
				JsonSchemaBuilder.string(mapper)
						.description("Optional new description text. An empty string clears the description."));
		schemaRoot.property(ARG_PACKING_VALUE, JsonSchemaBuilder.integer(mapper)
				.description(
						"Optional packing behavior. -1 uses default data organization packing (setToDefaultPacking). 0 disables packing (setPackingEnabled(false)). Positive values specify explicit byte boundaries (setExplicitPackingValue).")
				.minimum(-1));
		schemaRoot.property(ARG_ALIGNMENT_VALUE, JsonSchemaBuilder.integer(mapper)
				.description(
						"Optional explicit minimum alignment. -1 uses default alignment (setToDefaultAligned). 0 uses machine alignment (setToMachineAligned). Positive values (powers of 2) specify explicit alignment (setExplicitMinimumAlignment).")
				.minimum(-1));

		schemaRoot.requiredProperty(ARG_FILE_NAME);
		schemaRoot.requiredProperty(ARG_STRUCT_PATH);

		return schemaRoot.build();
	}

	private static record StructUpdateContext(
			Program program,
			Structure oldStruct, // Keep for reference if needed, or just path
			Optional<String> newNameOpt,
			Optional<String> newDescriptionOpt,
			Optional<Integer> newPackingArgOpt, // User input
			Optional<Integer> newAlignmentArgOpt, // User input
			String originalPath,
			List<String> updatedFieldsLog) { // For logging what was changed
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).map(program -> {
			final String structPathString = getRequiredStringArgument(args, ARG_STRUCT_PATH);
			Optional<String> newNameOpt = getOptionalStringArgument(args, ARG_NEW_NAME);
			Optional<String> newDescriptionOpt = getOptionalStringArgument(args, ARG_COMMENT);
			Optional<Integer> newPackingArgOpt = getOptionalIntArgument(args, ARG_PACKING_VALUE);
			Optional<Integer> newAlignmentArgOpt = getOptionalIntArgument(args, ARG_ALIGNMENT_VALUE);

			if (newNameOpt.isEmpty() && newDescriptionOpt.isEmpty() && newPackingArgOpt.isEmpty()
					&& newAlignmentArgOpt.isEmpty()) {
				GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
				GhidraMcpError error = GhidraMcpError.validation()
						.errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
						.message("No changes specified. Provide at least newName, newDescription, packingValue, or alignmentValue")
						.context(new GhidraMcpError.ErrorContext(
								annotation.mcpName(),
								"update parameters validation",
								Map.of(ARG_STRUCT_PATH, structPathString),
								Map.of("structPath", structPathString),
								Map.of("noUpdatesProvided", true, "availableUpdateFields",
										List.of("newName", "newDescription", "packingValue", "alignmentValue"))))
						.suggestions(List.of(
								new GhidraMcpError.ErrorSuggestion(
										GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
										"Specify at least one update",
										"Provide at least one field to update",
										List.of("newName", "newDescription", "packingValue", "alignmentValue"),
										null)))
						.build();
				throw new GhidraMcpException(error);
			}

			DataType dt = program.getDataTypeManager().getDataType(structPathString);

			if (dt == null) {
				GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
				GhidraMcpError error = GhidraMcpError.resourceNotFound()
						.errorCode(GhidraMcpError.ErrorCode.DATA_TYPE_NOT_FOUND)
						.message("Struct not found at path: " + structPathString)
						.context(new GhidraMcpError.ErrorContext(
								annotation.mcpName(),
								"struct lookup",
								Map.of(ARG_STRUCT_PATH, structPathString),
								Map.of("structPath", structPathString),
								Map.of("structExists", false)))
						.suggestions(List.of(
								new GhidraMcpError.ErrorSuggestion(
										GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
										"List available data types",
										"Check what structures exist",
										null,
										List.of(getMcpName(GhidraListDataTypesTool.class)))))
						.build();
				throw new GhidraMcpException(error);
			}
			if (!(dt instanceof Structure)) {
				GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
				GhidraMcpError error = GhidraMcpError.validation()
						.errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
						.message("Data type at path is not a Struct: " + structPathString)
						.context(new GhidraMcpError.ErrorContext(
								annotation.mcpName(),
								"data type validation",
								Map.of(ARG_STRUCT_PATH, structPathString),
								Map.of("structPath", structPathString, "actualDataType", dt.getDisplayName()),
								Map.of("isStruct", false, "actualTypeName", dt.getClass().getSimpleName())))
						.suggestions(List.of(
								new GhidraMcpError.ErrorSuggestion(
										GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
										"Use a structure data type",
										"Ensure the path points to a structure, not " + dt.getClass().getSimpleName(),
										null,
										null)))
						.build();
				throw new GhidraMcpException(error);
			}
			final Structure oldStruct = (Structure) dt;
			final List<String> updatedFieldsLog = new ArrayList<>();

			newNameOpt.ifPresent(s -> updatedFieldsLog.add("name"));
			newDescriptionOpt.ifPresent(s -> updatedFieldsLog.add("description"));
			newPackingArgOpt.ifPresent(s -> updatedFieldsLog.add("packingValue"));
			newAlignmentArgOpt.ifPresent(s -> updatedFieldsLog.add("alignmentValue"));

			return new StructUpdateContext(program, oldStruct, newNameOpt, newDescriptionOpt, newPackingArgOpt,
					newAlignmentArgOpt,
					structPathString,
					updatedFieldsLog);

		}).flatMap(context -> {
			return executeInTransaction(context.program(), "MCP - Update Struct: " + context.originalPath(), () -> {
				DataTypeManager dtm = context.program().getDataTypeManager();
				// Re-fetch the structure within the transaction to ensure it's the live version
				// from the DTM
				DataType liveDt = dtm.getDataType(context.originalPath());
				if (liveDt == null || !(liveDt instanceof Structure)) {
					throw new IllegalStateException(
							"Struct disappeared or changed type before transaction: " + context.originalPath());
				}
				Structure structToUpdate = (Structure) liveDt;

				context.newNameOpt().ifPresent(newName -> {
					try {
						structToUpdate.setName(newName);
					} catch (InvalidNameException | ghidra.util.exception.DuplicateNameException e) {
						GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);
						GhidraMcpError error = GhidraMcpError.validation()
								.errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
								.message("Failed to set new name for struct: " + e.getMessage())
								.context(new GhidraMcpError.ErrorContext(
										annotation.mcpName(),
										"struct name update",
										Map.of(ARG_NEW_NAME, newName, ARG_STRUCT_PATH, context.originalPath()),
										Map.of("newName", newName, "structPath", context.originalPath()),
										Map.of("nameUpdateFailed", true, "nameError", e.getMessage())))
								.suggestions(List.of(
										new GhidraMcpError.ErrorSuggestion(
												GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
												"Use a valid unique name",
												"Struct names must be valid and not duplicate existing names",
												null,
												null)))
								.build();
						throw new GhidraMcpException(error);
					}
				});

				context.newDescriptionOpt().ifPresent(structToUpdate::setDescription);

				context.newPackingArgOpt().ifPresent(packingValue -> {
					if (packingValue == -1) {
						structToUpdate.setToDefaultPacking();
						structToUpdate.setPackingEnabled(true);
					} else if (packingValue == 0) {
						structToUpdate.setPackingEnabled(false);
					} else {
						structToUpdate.setExplicitPackingValue(packingValue);
						structToUpdate.setPackingEnabled(true);
					}
				});

				context.newAlignmentArgOpt().ifPresent(alignmentValue -> {
					if (alignmentValue == -1) {
						structToUpdate.setToDefaultAligned();
					} else if (alignmentValue == 0) {
						structToUpdate.setToMachineAligned();
					} else {
						structToUpdate.setExplicitMinimumAlignment(alignmentValue);
					}
				});

				return "Struct '" + structToUpdate.getPathName() + "' updated successfully. Modified fields: "
						+ String.join(", ", context.updatedFieldsLog());
			});
		});
	}
}