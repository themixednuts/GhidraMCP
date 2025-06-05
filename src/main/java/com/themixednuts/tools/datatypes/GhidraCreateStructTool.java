package com.themixednuts.tools.datatypes;

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
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Create Struct", mcpName = "create_struct", category = ToolCategory.DATATYPES, description = "Creates a new struct data type.", mcpDescription = """
		<use_case>
		Create a new structure data type in a Ghidra program with configurable size, packing, and alignment options. Essential for defining custom data structures for reverse engineering.
		</use_case>

		<important_notes>
		- Category path auto-created if it doesn't exist
		- Packing values: -1 (default), 0 (disabled), or specific byte boundaries (1,2,4,8,16)
		- Alignment values: -1 (default), 0 (machine-specific), or explicit minimum alignment
		- Size 0 creates growable struct (recommended)
		</important_notes>

		<example>
		Create basic struct: provide fileName and name. For advanced struct: include path "/Malware/Config", size 64, packingValue 1 for packed header.
		</example>

		<workflow>
		1. Validate struct name doesn't already exist in target category
		2. Create category path if it doesn't exist
		3. Create structure with specified size and settings
		4. Apply packing and alignment configurations
		5. Add to data type manager and set description
		</workflow>
		""")
public class GhidraCreateStructTool implements IGhidraMcpSpecification {

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();

		schemaRoot.property(ARG_FILE_NAME, JsonSchemaBuilder.string(mapper)
				.description("The file name of the Ghidra tool window to target."), true);
		schemaRoot.property(ARG_NAME, JsonSchemaBuilder.string(mapper)
				.description("Name for the new struct (e.g., MyStruct)."), true);
		schemaRoot.property(ARG_PATH, JsonSchemaBuilder.string(mapper)
				.description(
						"Optional category path for the new struct (e.g., /MyCategory). If omitted, uses default/root path."));
		schemaRoot.property(ARG_SIZE, JsonSchemaBuilder.integer(mapper)
				.description("Optional initial size for the struct (0 for default/growable)."));
		schemaRoot.property(ARG_COMMENT, JsonSchemaBuilder.string(mapper)
				.description("Optional comment for the new struct."));
		schemaRoot.property(ARG_PACKING_VALUE, JsonSchemaBuilder.integer(mapper)
				.description(
						"Optional packing behavior. -1 uses default data organization packing (setToDefaultPacking). 0 disables packing (setPackingEnabled(false)). Positive values specify explicit byte boundaries (setExplicitPackingValue).")
				.minimum(-1));
		schemaRoot.property(ARG_ALIGNMENT_VALUE, JsonSchemaBuilder.integer(mapper)
				.description(
						"Optional explicit minimum alignment. -1 uses default alignment (setToDefaultAligned). 0 uses machine alignment (setToMachineAligned). Positive values (powers of 2) specify explicit alignment (setExplicitMinimumAlignment).")
				.minimum(-1));

		schemaRoot.requiredProperty(ARG_FILE_NAME);
		schemaRoot.requiredProperty(ARG_NAME);

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool)
				.flatMap(program -> {
					String structName = getRequiredStringArgument(args, ARG_NAME);
					Optional<String> pathOpt = getOptionalStringArgument(args, ARG_PATH);
					CategoryPath categoryPath = pathOpt.map(CategoryPath::new).orElse(CategoryPath.ROOT);
					Optional<Integer> sizeOpt = getOptionalIntArgument(args, ARG_SIZE);
					Optional<String> commentOpt = getOptionalStringArgument(args, ARG_COMMENT);
					Optional<Integer> packingArgOpt = getOptionalIntArgument(args, ARG_PACKING_VALUE);
					Optional<Integer> alignmentArgOpt = getOptionalIntArgument(args, ARG_ALIGNMENT_VALUE);
					String transactionName = "Create Struct: " + structName;

					return executeInTransaction(program, transactionName, () -> {
						DataTypeManager dtm = program.getDataTypeManager();
						ensureCategoryExists(dtm, categoryPath);
						return createStructInternal(dtm, structName, categoryPath, commentOpt, sizeOpt, packingArgOpt,
								alignmentArgOpt);
					});
				});
	}

	private String createStructInternal(DataTypeManager dtm, String structName, CategoryPath categoryPath,
			Optional<String> commentOpt, Optional<Integer> sizeOpt, Optional<Integer> packingArgOpt,
			Optional<Integer> alignmentArgOpt) {
		GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);

		if (dtm.getDataType(categoryPath, structName) != null) {
			GhidraMcpError error = GhidraMcpError.validation()
					.errorCode(GhidraMcpError.ErrorCode.CONFLICTING_ARGUMENTS)
					.message("Data type already exists: " + categoryPath.getPath() + CategoryPath.DELIMITER_CHAR + structName)
					.context(new GhidraMcpError.ErrorContext(
							annotation.mcpName(),
							"struct creation",
							Map.of(ARG_NAME, structName, ARG_PATH, categoryPath.getPath()),
							Map.of("proposedStructPath", categoryPath.getPath() + CategoryPath.DELIMITER_CHAR + structName),
							Map.of("dataTypeExists", true, "categoryPath", categoryPath.getPath(), "structName", structName)))
					.suggestions(List.of(
							new GhidraMcpError.ErrorSuggestion(
									GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
									"Choose a different struct name",
									"Use a unique name for the struct",
									null,
									null),
							new GhidraMcpError.ErrorSuggestion(
									GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
									"Check existing data types",
									"List existing data types to avoid conflicts",
									null,
									List.of(getMcpName(GhidraListDataTypesTool.class)))))
					.build();
			throw new GhidraMcpException(error);
		}
		StructureDataType newStruct = new StructureDataType(categoryPath, structName,
				sizeOpt.orElse(0), dtm);

		packingArgOpt.ifPresent(packingValue -> {
			if (packingValue == -1) {
				newStruct.setToDefaultPacking();
				newStruct.setPackingEnabled(true);
			} else if (packingValue == 0) {
				newStruct.setPackingEnabled(false);
			} else {
				newStruct.setExplicitPackingValue(packingValue);
				newStruct.setPackingEnabled(true);
			}
		});

		alignmentArgOpt.ifPresent(alignmentValue -> {
			if (alignmentValue == -1) {
				newStruct.setToDefaultAligned();
			} else if (alignmentValue == 0) {
				newStruct.setToMachineAligned();
			} else {
				newStruct.setExplicitMinimumAlignment(alignmentValue);
			}
		});

		DataType newDt = dtm.addDataType(newStruct, DataTypeConflictHandler.REPLACE_HANDLER);
		if (newDt == null || !(newDt instanceof Structure)) { // Also check instance type
			throw new RuntimeException(
					"Failed to add struct '" + structName + "' to data type manager or it was not resolved as a Structure.");
		}
		commentOpt.ifPresent(comment -> newDt.setDescription(comment));

		// Constructing the success message
		StringBuilder message = new StringBuilder("Struct '" + newDt.getPathName() + "' created.");
		Structure resolvedStruct = (Structure) newDt;
		packingArgOpt.ifPresent(
				val -> message.append(" Explicit Packing set to: ").append(resolvedStruct.getExplicitPackingValue())
						.append("."));
		alignmentArgOpt.ifPresent(val -> message.append(" Explicit Alignment set to: ")
				.append(resolvedStruct.getExplicitMinimumAlignment()).append("."));

		return message.toString();
	}

	private static void ensureCategoryExists(DataTypeManager dtm, CategoryPath categoryPath) {
		if (categoryPath == null || categoryPath.equals(CategoryPath.ROOT)) {
			return;
		}
		if (dtm.getCategory(categoryPath) == null) {
			ghidra.program.model.data.Category created = dtm.createCategory(categoryPath);
			if (created == null) {
				// Attempt to re-fetch in case of race condition
				if (dtm.getCategory(categoryPath) == null) {
					throw new RuntimeException("Failed to create or find category: " + categoryPath.getPath());
				}
			}
		}
	}
}