package com.themixednuts.tools.grouped;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.ToolCategory;

@GhidraMcpTool(name = "Grouped Control Flow", description = "Performs multiple related control flow operations using enabled granular tools.", mcpName = "grouped_control_flow", mcpDescription = "Accepts a list of enabled control flow operations to perform as a group.", category = ToolCategory.GROUPED)
public class GroupedControlFlowOperationsTool implements IGroupedTool {

	protected static final ToolCategory TARGET_CATEGORY = ToolCategory.CONTROL_FLOW;

	@Override
	public ToolCategory getTargetCategory() {
		return TARGET_CATEGORY;
	}

}