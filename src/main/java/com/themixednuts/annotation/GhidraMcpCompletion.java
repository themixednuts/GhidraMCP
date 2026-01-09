package com.themixednuts.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Annotation to define metadata for Ghidra MCP completion providers.
 * Used by ServiceLoader discovery to configure completion specifications.
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
public @interface GhidraMcpCompletion {

    /**
     * The type of reference this completion handles.
     * Either "prompt" or "resource".
     */
    String refType();

    /**
     * The name of the prompt or resource template this completion is for.
     */
    String refName();

    /**
     * The name of the argument this completion provides suggestions for.
     */
    String argumentName();
}
