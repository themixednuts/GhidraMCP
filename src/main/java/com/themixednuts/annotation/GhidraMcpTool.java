package com.themixednuts.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import com.themixednuts.tools.ToolCategory;

/**
 * Annotation to define metadata for Ghidra MCP tools.
 * Used by ServiceLoader discovery to configure tool options and MCP
 * specifications.
 */
@Retention(RetentionPolicy.RUNTIME) // Needs to be available at runtime for reflection
@Target(ElementType.TYPE) // Apply to class definitions
public @interface GhidraMcpTool {
	/**
	 * The base key used for Ghidra options registration.
	 */
	String key();

	/**
	 * The description used for Ghidra options registration.
	 */
	String description();

	/**
	 * The category used for Ghidra options registration.
	 * If provided, the full option key becomes "category.key".
	 */
	ToolCategory category() default ToolCategory.UNCATEGORIZED;

	/**
	 * The name of the tool as it should appear in the MCP specification.
	 */
	String mcpName();

	/**
	 * The description of the tool as it should appear in the MCP specification.
	 */
	String mcpDescription();
}