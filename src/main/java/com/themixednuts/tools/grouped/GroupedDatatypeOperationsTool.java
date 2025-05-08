package com.themixednuts.tools.grouped;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.ToolCategory;

@GhidraMcpTool(name = "Grouped Datatype", description = "Performs multiple related datatype operations using enabled granular tools.", mcpName = "grouped_datatype", mcpDescription = "Accepts a list of enabled datatype operations (like create struct, add member) to perform as a group.", category = ToolCategory.GROUPED)
public class GroupedDatatypeOperationsTool implements IGroupedTool {

	protected static final ToolCategory TARGET_CATEGORY = ToolCategory.DATATYPES;

	/**
	 * Specifies the category of granular tools this grouped tool operates on.
	 * Required by the IGroupedTool interface.
	 */
	@Override
	public ToolCategory getTargetCategory() {
		return TARGET_CATEGORY;
	}
}