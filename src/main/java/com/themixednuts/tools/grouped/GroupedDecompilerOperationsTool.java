package com.themixednuts.tools.grouped;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.ToolCategory;

@GhidraMcpTool(name = "Grouped Decompiler", description = "Performs multiple related decompiler operations using enabled granular tools.", mcpName = "grouped_decompiler", mcpDescription = "Accepts a list of enabled decompiler operations to perform as a group.", category = ToolCategory.GROUPED)
public class GroupedDecompilerOperationsTool implements IGroupedTool {

	protected static final ToolCategory TARGET_CATEGORY = ToolCategory.DECOMPILER;

	@Override
	public ToolCategory getTargetCategory() {
		return TARGET_CATEGORY;
	}

}