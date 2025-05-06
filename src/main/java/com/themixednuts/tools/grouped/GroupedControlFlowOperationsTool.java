package com.themixednuts.tools.grouped;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.tools.ToolCategory;
import com.themixednuts.utils.jsonschema.JsonSchema;

import ghidra.framework.plugintool.PluginTool;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.core.publisher.Mono;

@GhidraMcpTool(name = "Grouped Control Flow Operations", category = ToolCategory.GROUPED, description = "Executes a sequence of control flow operations (get block, predecessors, successors) in a single request.", mcpName = "grouped_control_flow_operations", mcpDescription = "Perform multiple control flow analysis operations within a single tool call.")
public class GroupedControlFlowOperationsTool implements IGhidraMcpSpecification, IGroupedTool {

	private static final ToolCategory TARGET_CATEGORY = ToolCategory.CONTROL_FLOW;

	private final List<Class<? extends IGhidraMcpSpecification>> granularToolClasses = IGroupedTool
			.getGranularToolClasses(TARGET_CATEGORY.getCategoryName());

	private final Map<String, Class<? extends IGhidraMcpSpecification>> toolClassMap = this.granularToolClasses.stream()
			.filter(clazz -> clazz.getAnnotation(GhidraMcpTool.class) != null)
			.collect(Collectors.toMap(
					clazz -> clazz.getAnnotation(GhidraMcpTool.class).mcpName(),
					clazz -> clazz,
					(existing, replacement) -> existing));

	@Override
	public JsonSchema schema() {
		return getGroupedSchema(TARGET_CATEGORY);
	}

	@Override
	public Map<String, Class<? extends IGhidraMcpSpecification>> getToolClassMap() {
		return this.toolClassMap;
	}

	@Override
	public Mono<? extends Object> execute(McpAsyncServerExchange ex, Map<String, Object> args, PluginTool tool) {
		return this.executeGroupedOperations(ex, args, tool);
	}
}