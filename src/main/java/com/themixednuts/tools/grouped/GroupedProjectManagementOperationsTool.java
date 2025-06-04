package com.themixednuts.tools.grouped;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.ToolCategory;

@GhidraMcpTool(name = "Grouped Project Management", description = "Performs multiple related project management operations using enabled granular tools.", mcpName = "grouped_project_management", mcpDescription = """
		<use_case>
		Enables batch execution of multiple project management operations such as creating/deleting bookmarks,
		listing analysis options, triggering auto-analysis, navigating to addresses, or running Ghidra scripts.
		This tool helps automate common project setup and workflow tasks, improves efficiency,
		and can manage client-side limits on the number of enabled tools.
		</use_case>

		<important_notes>
		- Operations are processed in the order they appear in the 'operations' array in the request.
		- If operations are logically dependent (e.g., creating a bookmark before attempting to list it,
		  though listing might show it regardless of batch order if committed), ensure correct order for predictability.
		- The schema does not enforce a strict execution order for unrelated operations within the batch,
		  but dependent operations MUST be ordered correctly by the client.
		- Each operation in the batch will correspond to an enabled granular project management tool.
		</important_notes>

		<return_value_summary>
		Returns a 'GroupedOperationResult' containing a list of results, one for each operation in the batch.
		Each individual result will be the success output of the corresponding granular tool (e.g., a list of bookmarks,
		program info, confirmation message) or an error object.
		</return_value_summary>
		""", category = ToolCategory.GROUPED)
public class GroupedProjectManagementOperationsTool implements IGroupedTool {

	protected static final ToolCategory TARGET_CATEGORY = ToolCategory.PROJECT_MANAGEMENT;

	@Override
	public ToolCategory getTargetCategory() {
		return TARGET_CATEGORY;
	}

}