package com.themixednuts.resources;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.themixednuts.annotation.GhidraMcpResource;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.utils.GhidraStateUtils;
import com.themixednuts.utils.GhidraMcpErrorUtils;
import com.themixednuts.utils.JsonMapperHolder;

import ghidra.framework.model.Project;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import io.modelcontextprotocol.common.McpTransportContext;
import io.modelcontextprotocol.server.McpStatelessServerFeatures.AsyncResourceSpecification;
import io.modelcontextprotocol.server.McpStatelessServerFeatures.AsyncResourceTemplateSpecification;
import io.modelcontextprotocol.spec.McpSchema.ReadResourceRequest;
import io.modelcontextprotocol.spec.McpSchema.ReadResourceResult;
import io.modelcontextprotocol.spec.McpSchema.Resource;
import io.modelcontextprotocol.spec.McpSchema.ResourceTemplate;
import io.modelcontextprotocol.spec.McpSchema.TextResourceContents;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Abstract base class for MCP resources.
 * Provides common functionality for exposing Ghidra data as MCP resources.
 * 
 * <p>Implementations should be annotated with @GhidraMcpResource and registered
 * via ServiceLoader in META-INF/services/com.themixednuts.resources.BaseMcpResource.
 */
public abstract class BaseMcpResource {

    protected static final ObjectMapper mapper = JsonMapperHolder.getMapper();

    // =================== Abstract Methods ===================

    /**
     * Reads the resource content.
     * 
     * @param context The MCP transport context
     * @param uri The resolved URI (for templates, this will have parameters filled in)
     * @param tool The Ghidra plugin tool
     * @return Mono emitting the resource content as a string
     */
    public abstract Mono<String> read(McpTransportContext context, String uri, PluginTool tool);

    // =================== Annotation Accessors ===================

    /**
     * Gets the annotation for this resource.
     */
    protected GhidraMcpResource getAnnotation() {
        return this.getClass().getAnnotation(GhidraMcpResource.class);
    }

    /**
     * Whether this resource is a template (uses URI template with parameters).
     */
    public boolean isTemplate() {
        GhidraMcpResource annotation = getAnnotation();
        return annotation != null && annotation.template();
    }

    /**
     * Gets the resource URI or URI template.
     */
    public String getUri() {
        GhidraMcpResource annotation = getAnnotation();
        return annotation != null ? annotation.uri() : "";
    }

    /**
     * Gets the resource name.
     */
    public String getName() {
        GhidraMcpResource annotation = getAnnotation();
        return annotation != null ? annotation.name() : getClass().getSimpleName();
    }

    /**
     * Gets the resource description.
     */
    public String getDescription() {
        GhidraMcpResource annotation = getAnnotation();
        return annotation != null ? annotation.description() : "";
    }

    /**
     * Gets the MIME type of the resource content.
     */
    public String getMimeType() {
        GhidraMcpResource annotation = getAnnotation();
        return annotation != null ? annotation.mimeType() : "application/json";
    }

    // =================== Specification Generation ===================

    /**
     * Creates an AsyncResourceSpecification for static resources.
     */
    public AsyncResourceSpecification toResourceSpecification(PluginTool tool) {
        if (isTemplate()) {
            throw new IllegalStateException("Template resources should use toTemplateSpecification()");
        }

        Resource resource = Resource.builder()
                .uri(getUri())
                .name(getName())
                .description(getDescription())
                .mimeType(getMimeType())
                .build();

        return new AsyncResourceSpecification(
                resource,
                (ctx, request) -> handleRead(ctx, request, tool));
    }

    /**
     * Creates an AsyncResourceTemplateSpecification for template resources.
     */
    public AsyncResourceTemplateSpecification toTemplateSpecification(PluginTool tool) {
        if (!isTemplate()) {
            throw new IllegalStateException("Static resources should use toResourceSpecification()");
        }

        ResourceTemplate template = ResourceTemplate.builder()
                .uriTemplate(getUri())
                .name(getName())
                .description(getDescription())
                .mimeType(getMimeType())
                .build();

        return new AsyncResourceTemplateSpecification(
                template,
                (ctx, request) -> handleRead(ctx, request, tool));
    }

    /**
     * Handles a read resource request.
     */
    protected Mono<ReadResourceResult> handleRead(McpTransportContext ctx, ReadResourceRequest request, PluginTool tool) {
        String uri = request.uri();

        return read(ctx, uri, tool)
                .map(content -> new ReadResourceResult(
                        List.of(new TextResourceContents(uri, getMimeType(), content))))
                .onErrorResume(t -> {
                    Msg.error(this, "Error reading resource " + uri, t);
                    String errorMsg = t instanceof GhidraMcpException ? t.getMessage() : "Error reading resource: " + t.getMessage();
                    return Mono.error(new RuntimeException(errorMsg));
                });
    }

    // =================== URI Template Helpers ===================

    /**
     * Extracts parameters from a URI using the resource's URI template.
     * 
     * @param uri The actual URI
     * @return Map of parameter names to values
     */
    protected Map<String, String> extractUriParams(String uri) {
        return extractUriParams(uri, getUri());
    }

    /**
     * Extracts parameters from a URI using a template pattern.
     * 
     * @param uri The actual URI
     * @param template The URI template with {param} placeholders
     * @return Map of parameter names to values
     */
    protected Map<String, String> extractUriParams(String uri, String template) {
        String regex = template.replaceAll("\\{([^}]+)\\}", "(?<$1>[^/]+)");
        Pattern pattern = Pattern.compile(regex);
        Matcher matcher = pattern.matcher(uri);

        if (matcher.matches()) {
            Map<String, String> params = new HashMap<>();
            String[] paramNames = extractParamNames(template);
            for (String name : paramNames) {
                try {
                    params.put(name, java.net.URLDecoder.decode(matcher.group(name), "UTF-8"));
                } catch (Exception e) {
                    params.put(name, matcher.group(name));
                }
            }
            return params;
        }
        return Collections.emptyMap();
    }

    private String[] extractParamNames(String template) {
        Pattern p = Pattern.compile("\\{([^}]+)\\}");
        Matcher m = p.matcher(template);
        List<String> names = new ArrayList<>();
        while (m.find()) {
            names.add(m.group(1));
        }
        return names.toArray(new String[0]);
    }

    // =================== Ghidra Helpers (delegate to GhidraStateUtils) ===================

    /**
     * Gets the active Ghidra project.
     */
    protected Project getActiveProject() throws GhidraMcpException {
        return GhidraStateUtils.getActiveProject();
    }

    /**
     * Finds a program by name.
     */
    protected Program getProgramByName(String fileName) throws GhidraMcpException {
        return GhidraStateUtils.getProgramByName(fileName, this);
    }

    /**
     * Converts an object to JSON string.
     */
    protected String toJson(Object obj) throws GhidraMcpException {
        try {
            return JsonMapperHolder.toJson(obj);
        } catch (JsonProcessingException e) {
            throw new GhidraMcpException(GhidraMcpErrorUtils.unexpectedError(
                    "resource", "toJson", e));
        }
    }
}
