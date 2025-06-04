package com.themixednuts.tools.grouped;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.ToolCategory;

@GhidraMcpTool(name = "Grouped Datatype", description = "Performs multiple related datatype operations using enabled granular tools.", mcpName = "grouped_datatype", mcpDescription = """
		<use_case>
		Enables the execution of multiple data type operations (e.g., creating structures, adding members, defining enums)
		as a single batched request. This is particularly useful for efficiently building or modifying complex data type
		hierarchies and can help manage client-side limits on the number of enabled tools.
		</use_case>

		<important_notes>
		- Operations are processed in the order they appear in the 'operations' array in the request.
		- If operations are logically dependent (e.g., creating a struct before adding members to it
		  within the same batch), ensure they are correctly ordered in the request.
		- The schema does not enforce a strict execution order for unrelated operations within the batch,
		  but dependent operations MUST be ordered correctly by the client.
		- Each operation in the batch will correspond to an enabled granular data type tool.
		</important_notes>

		<return_value_summary>
		Returns a 'GroupedOperationResult' containing a list of results, one for each operation in the batch.
		Each individual result will typically be the success output of the corresponding granular tool (often a confirmation message or a POJO representing the created/modified data type) or an error object.
		</return_value_summary>
		""", category = ToolCategory.GROUPED)
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