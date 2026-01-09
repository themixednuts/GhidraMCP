package com.themixednuts.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Annotation to define metadata for Ghidra MCP prompts.
 * Used by ServiceLoader discovery to configure prompt specifications.
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
public @interface GhidraMcpPrompt {

    /**
     * The unique identifier for this prompt.
     */
    String name();

    /**
     * A human-readable title for this prompt.
     */
    String title();

    /**
     * A description of what this prompt does.
     */
    String description();
}
