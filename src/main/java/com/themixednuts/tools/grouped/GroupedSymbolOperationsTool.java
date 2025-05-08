package com.themixednuts.tools.grouped;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.ToolCategory;

@GhidraMcpTool(name = "Grouped Symbols", description = "Performs multiple related symbol operations using enabled granular tools.", mcpName = "grouped_symbols", mcpDescription = "Accepts a list of enabled symbol operations to perform as a group.", category = ToolCategory.GROUPED)
public class GroupedSymbolOperationsTool implements IGroupedTool {

	protected static final ToolCategory TARGET_CATEGORY = ToolCategory.SYMBOLS;

	@Override
	public ToolCategory getTargetCategory() {
		return TARGET_CATEGORY;
	}

}