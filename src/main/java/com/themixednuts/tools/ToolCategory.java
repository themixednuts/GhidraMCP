package com.themixednuts.tools;

/**
 * Enumeration defining the functional categories for Ghidra MCP tools.
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
	 * Returns the human-readable name of the category.
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