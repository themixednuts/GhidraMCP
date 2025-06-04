package com.themixednuts.tools.grouped;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.ToolCategory;

@GhidraMcpTool(name = "Grouped Memory", description = "Performs multiple related memory operations using enabled granular tools.", mcpName = "grouped_memory", mcpDescription = """
		<use_case>
		Facilitates the execution of multiple memory-related operations (e.g., reading/writing bytes, searching memory,
		getting/assembling instructions, listing imports/segments, handling XRefs) as a single batched request.
		This streamlines memory analysis, patching, and modification workflows, improves efficiency,
		and helps manage client-side limits on the number of enabled tools.
		</use_case>

		<important_notes>
		- Operations are processed in the order they appear in the 'operations' array in the request.
		- If operations are logically dependent (e.g., writing to memory then reading the same location to verify,
		  or disassembling an instruction before attempting to patch it within the same batch),
		  ensure they are correctly ordered in the request.
		- The schema does not enforce a strict execution order for unrelated operations within the batch,
		  but dependent operations MUST be ordered correctly by the client.
		- Each operation in the batch will correspond to an enabled granular memory tool.
		</important_notes>

		<return_value_summary>
		Returns a 'GroupedOperationResult' containing a list of results, one for each operation in the batch.
		Each individual result will be the success output of the corresponding granular tool (e.g., read bytes as hex,
		list of XRefs, confirmation of write) or an error object.
		</return_value_summary>
		""", category = ToolCategory.GROUPED)
public class GroupedMemoryOperationsTool implements IGroupedTool {

	protected static final ToolCategory TARGET_CATEGORY = ToolCategory.MEMORY;

	@Override
	public ToolCategory getTargetCategory() {
		return TARGET_CATEGORY;
	}

}