package com.themixednuts.tools.grouped;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.ToolCategory;

@GhidraMcpTool(name = "Grouped Project Management", description = "Performs multiple related project management operations using enabled granular tools.", mcpName = "grouped_project_management", mcpDescription = "Accepts a list of enabled project management operations to perform as a group.", category = ToolCategory.GROUPED)
public class GroupedProjectManagementOperationsTool implements IGroupedTool {

	protected static final ToolCategory TARGET_CATEGORY = ToolCategory.PROJECT_MANAGEMENT;

	@Override
	public ToolCategory getTargetCategory() {
		return TARGET_CATEGORY;
	}

}