package com.themixednuts.tools.grouped;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.ToolCategory;

@GhidraMcpTool(name = "Grouped Control Flow", description = "Performs multiple related control flow operations using enabled granular tools.", mcpName = "grouped_control_flow", mcpDescription = """
		<use_case>
		Provides a way to execute multiple control flow operations (e.g., get basic block, get predecessors, get successors)
		as a single batched request. This is useful for performing comprehensive program flow analysis efficiently
		and can help manage client-side limits on the number of enabled tools.
		</use_case>

		<important_notes>
		- Operations are processed in the order they appear in the 'operations' array in the request.
		- If operations are logically dependent (e.g., one operation relies on the output or state change of a previous one
		  within the same batch), ensure they are correctly ordered in the request.
		- The schema does not enforce a strict execution order for unrelated operations within the batch,
		  but dependent operations MUST be ordered correctly by the client.
		- Each operation in the batch will correspond to an enabled granular control flow tool.
		</important_notes>

		<return_value_summary>
		Returns a 'GroupedOperationResult' containing a list of results, one for each operation in the batch.
		Each individual result will either be the success output of the corresponding granular tool or an error object.
		</return_value_summary>
		""", category = ToolCategory.GROUPED)
public class GroupedControlFlowOperationsTool implements IGroupedTool {

	protected static final ToolCategory TARGET_CATEGORY = ToolCategory.CONTROL_FLOW;

	@Override
	public ToolCategory getTargetCategory() {
		return TARGET_CATEGORY;
	}

}