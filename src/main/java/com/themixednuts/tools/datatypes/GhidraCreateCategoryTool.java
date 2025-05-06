package com.themixednuts.tools.datatypes;

import java.util.Map;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.tools.ToolCategory;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.Category;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;
import reactor.util.function.Tuples;

@GhidraMcpTool(name = "Create Category", category = ToolCategory.DATATYPES, description = "Creates a new data type category.", mcpName = "create_category", mcpDescription = "Create a new category for organizing data types.")
public class GhidraCreateCategoryTool implements IGhidraMcpSpecification {

	@Override
	public JsonSchema schema() {
		IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();
		schemaRoot.property(ARG_FILE_NAME, JsonSchemaBuilder.string(mapper).description("The name of the program file."));
		schemaRoot.property(ARG_CATEGORY_PATH, JsonSchemaBuilder.string(mapper)
				.description("The full path of the new category (e.g., '/MyTypes/SubTypes')."));

		schemaRoot.requiredProperty(ARG_FILE_NAME)
				.requiredProperty(ARG_CATEGORY_PATH);

		return schemaRoot.build();
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return getProgram(args, tool).map(program -> {
			String categoryPathStr = getRequiredStringArgument(args, ARG_CATEGORY_PATH);
			CategoryPath categoryPath = new CategoryPath(categoryPathStr);
			return Tuples.of(program, categoryPath, categoryPathStr);
		})
				.flatMap(context -> {
					Program program = context.getT1();
					CategoryPath categoryPath = context.getT2();
					String categoryPathStr = context.getT3();

					return executeInTransaction(program, "Create Category " + categoryPathStr, () -> {
						DataTypeManager dtm = program.getDataTypeManager();
						Category category = dtm.createCategory(categoryPath);
						if (category == null) {
							category = dtm.getCategory(categoryPath);
							if (category == null) {
								throw new RuntimeException("Failed to create or find category: " + categoryPathStr);
							} else {
								Msg.info(this, "Category already existed: " + categoryPathStr);
								return "Category already existed: " + category.getCategoryPath().getPath();
							}
						}
						return "Category created successfully: " + category.getCategoryPath().getPath();
					});
				});
	}
}