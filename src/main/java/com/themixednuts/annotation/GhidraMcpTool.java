package com.themixednuts.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Annotation to define metadata for Ghidra MCP tools. Used by ServiceLoader discovery to configure
 * tool options and MCP specifications.
 */
@Retention(RetentionPolicy.RUNTIME) // Needs to be available at runtime for reflection
@Target(ElementType.TYPE) // Apply to class definitions
public @interface GhidraMcpTool {
  /**
   * The name used for this tool within the Ghidra Tool Options menu. Should be human-readable and
   * descriptive (e.g., "List Functions", "Rename Symbol").
   */
  String name();

  /**
   * The description displayed when hovering over the tool's option in the Ghidra Tool Options menu.
   * Provides more detail about what the tool option enables/disables.
   */
  String description();

  /** The name of the tool as it should appear in the MCP specification. */
  String mcpName();

  /** The description of the tool as it should appear in the MCP specification. */
  String mcpDescription();

  // =================== MCP Tool Annotations (Hints) ===================

  /**
   * Human-readable title for the tool (optional, used in UIs). If empty, the mcpName will be used.
   */
  String title() default "";

  /**
   * If true, indicates the tool does not modify any state (read-only operation). Clients may use
   * this to parallelize read-only operations safely.
   */
  boolean readOnlyHint() default false;

  /**
   * If true, indicates the tool may perform destructive operations (e.g., deleting functions,
   * symbols, or data types). Clients should exercise caution and potentially confirm with users.
   */
  boolean destructiveHint() default false;

  /**
   * If true, indicates the tool is idempotent - calling it multiple times with the same arguments
   * produces the same result and has no additional effect. Safe to retry on failure.
   */
  boolean idempotentHint() default false;

  /**
   * If true, indicates the tool may access external systems (network, filesystem outside project).
   * Most Ghidra tools operate on the local project and should set this to false.
   */
  boolean openWorldHint() default false;
}
