package com.themixednuts.tools;

/**
 * Enum defining the categories for Ghidra MCP tools.
 * Used in the @GhidraMcpTool annotation for type safety and consistency.
 */
public enum ToolCategory {
	FUNCTIONS("Functions"),
	DATATYPES("Data Types"),
	PROJECT_MANAGEMENT("Project Management"),
	SYMBOLS("Symbols"),
	MEMORY("Memory"),
	DECOMPILER("Decompiler"),
	GROUPED("Grouped"), // Category for grouped tools themselves (e.g., for options)
	UNCATEGORIZED("Uncategorized"); // Default or for tools without a specific group

	private final String categoryName;

	ToolCategory(String categoryName) {
		this.categoryName = categoryName;
	}

	/**
	 * Gets the string representation of the category name, often used for option
	 * keys.
	 * 
	 * @return The category name string.
	 */
	public String getCategoryName() {
		return categoryName;
	}

	@Override
	public String toString() {
		return categoryName;
	}
}