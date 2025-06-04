package com.themixednuts.tools.grouped;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.ToolCategory;

@GhidraMcpTool(name = "Grouped Symbols", description = "Performs multiple related symbol operations using enabled granular tools.", mcpName = "grouped_symbols", mcpDescription = """
		<use_case>
		Allows for batch execution of various symbol-related operations, such as creating/deleting labels,
		getting/setting comments at addresses, applying/clearing equates, listing symbols, or renaming symbols.
		This tool enhances efficiency for symbol management tasks, code annotation, and can help manage
		client-side limits on the number of enabled tools.
		</use_case>

		<important_notes>
		- Operations are processed in the order they appear in the 'operations' array in the request.
		- If operations are logically dependent (e.g., creating a label before setting a comment at its address
		  within the same batch), ensure they are correctly ordered in the request.
		- The schema does not enforce a strict execution order for unrelated operations within the batch,
		  but dependent operations MUST be ordered correctly by the client.
		- Each operation in the batch will correspond to an enabled granular symbol tool.
		</important_notes>

		<return_value_summary>
		Returns a 'GroupedOperationResult' containing a list of results, one for each operation in the batch.
		Each individual result will be the success output of the corresponding granular tool (e.g., a SymbolInfo POJO,
		a list of comments, confirmation of a rename) or an error object.
		</return_value_summary>
		""", category = ToolCategory.GROUPED)
public class GroupedSymbolOperationsTool implements IGroupedTool {

	protected static final ToolCategory TARGET_CATEGORY = ToolCategory.SYMBOLS;

	@Override
	public ToolCategory getTargetCategory() {
		return TARGET_CATEGORY;
	}

}