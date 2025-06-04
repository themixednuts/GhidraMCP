package com.themixednuts.tools.grouped;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.ToolCategory;

@GhidraMcpTool(name = "Grouped Functions", description = "Performs multiple related function operations using enabled granular tools.", mcpName = "grouped_functions", mcpDescription = "Execute multiple function operations (create, update, analysis) in a single batch request. Efficient for function management and analysis workflows.", category = ToolCategory.GROUPED)
public class GroupedFunctionOperationsTool implements IGroupedTool {

	protected static final ToolCategory TARGET_CATEGORY = ToolCategory.FUNCTIONS;

	@Override
	public ToolCategory getTargetCategory() {
		return TARGET_CATEGORY;
	}

}