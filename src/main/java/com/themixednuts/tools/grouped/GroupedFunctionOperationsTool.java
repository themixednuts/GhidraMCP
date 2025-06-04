package com.themixednuts.tools.grouped;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.ToolCategory;

@GhidraMcpTool(name = "Grouped Functions", description = "Performs multiple related function operations using enabled granular tools.", mcpName = "grouped_functions", mcpDescription = """
		<use_case>
		Permits the execution of various function-related operations (e.g., creating, deleting, updating functions,
		getting prototypes, listing variables, or renaming symbols within functions) as a single batched request.
		This is highly beneficial for comprehensive function management and analysis, improving efficiency
		and helping to manage client-side limits on the number of enabled tools.
		</use_case>

		<important_notes>
		- Operations are processed in the order they appear in the 'operations' array in the request.
		- If operations are logically dependent (e.g., creating a function before updating its prototype
		  within the same batch), ensure they are correctly ordered in the request.
		- The schema does not enforce a strict execution order for unrelated operations within the batch,
		  but dependent operations MUST be ordered correctly by the client.
		- Each operation in the batch will correspond to an enabled granular function tool.
		</important_notes>

		<return_value_summary>
		Returns a 'GroupedOperationResult' containing a list of results, one for each operation in the batch.
		Each individual result will be the success output of the corresponding granular tool (e.g., a FunctionInfo POJO,
		a list of variables, a confirmation message) or an error object.
		</return_value_summary>
		""", category = ToolCategory.GROUPED)
public class GroupedFunctionOperationsTool implements IGroupedTool {

	protected static final ToolCategory TARGET_CATEGORY = ToolCategory.FUNCTIONS;

	@Override
	public ToolCategory getTargetCategory() {
		return TARGET_CATEGORY;
	}

}