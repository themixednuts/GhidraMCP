package com.themixednuts.tools.grouped;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.ToolCategory;

@GhidraMcpTool(name = "Grouped Decompiler", description = "Performs multiple related decompiler operations using enabled granular tools.", mcpName = "grouped_decompiler", mcpDescription = """
		<use_case>
		Allows for the execution of multiple decompiler-related operations (e.g., decompiling a function, retrieving P-code for a function or at an address)
		as a single batched request. This facilitates efficient and comprehensive function analysis workflows
		and can help manage client-side limits on the number of enabled tools.
		</use_case>

		<important_notes>
		- Operations are processed in the order they appear in the 'operations' array in the request.
		- While direct dependencies between decompiler operations in a single batch are less common,
		  if any logical sequence is intended (e.g., ensuring a function exists before attempting to decompile it,
		  though that check might be better handled by a prior separate call), maintain correct order.
		- The schema does not enforce a strict execution order for unrelated operations within the batch.
		- Each operation in the batch will correspond to an enabled granular decompiler tool.
		</important_notes>

		<return_value_summary>
		Returns a 'GroupedOperationResult' containing a list of results, one for each operation in the batch.
		Each individual result will be the success output of the corresponding granular tool (e.g., decompiled code string, P-code listing) or an error object.
		</return_value_summary>
		""", category = ToolCategory.GROUPED)
public class GroupedDecompilerOperationsTool implements IGroupedTool {

	protected static final ToolCategory TARGET_CATEGORY = ToolCategory.DECOMPILER;

	@Override
	public ToolCategory getTargetCategory() {
		return TARGET_CATEGORY;
	}

}