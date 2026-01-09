package com.themixednuts.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Annotation to define metadata for Ghidra MCP resources.
 * Used by ServiceLoader discovery to configure resource specifications.
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
public @interface GhidraMcpResource {

    /**
     * The URI or URI template for this resource.
     * Static resources use a fixed URI (e.g., "ghidra://programs").
     * Template resources use URI templates with parameters (e.g., "ghidra://program/{name}/functions").
     */
    String uri();

    /**
     * The display name of this resource.
     */
    String name();

    /**
     * A description of what this resource provides.
     */
    String description();

    /**
     * The MIME type of the resource content.
     * Defaults to "application/json".
     */
    String mimeType() default "application/json";

    /**
     * Whether this resource is a template (uses URI parameters).
     * If true, the uri() should contain {param} placeholders.
     */
    boolean template() default false;
}
