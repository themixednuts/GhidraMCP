package com.themixednuts.tools.grouped;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.ToolCategory;

@GhidraMcpTool(name = "Grouped Memory", description = "Performs multiple related memory operations using enabled granular tools.", mcpName = "grouped_memory", mcpDescription = "Accepts a list of enabled memory operations to perform as a group.", category = ToolCategory.GROUPED)
public class GroupedMemoryOperationsTool implements IGroupedTool {

	protected static final ToolCategory TARGET_CATEGORY = ToolCategory.MEMORY;

	@Override
	public ToolCategory getTargetCategory() {
		return TARGET_CATEGORY;
	}

}