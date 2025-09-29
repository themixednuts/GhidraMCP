package com.themixednuts;

import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.ServiceLoader;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.services.IGhidraMcpToolProvider;
import com.themixednuts.tools.IGhidraMcpSpecification;
import ghidra.framework.options.OptionType;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpStatelessServerFeatures.AsyncToolSpecification;

import generic.stl.Pair;

/**
 * Service implementation responsible for discovering, filtering (based on
 * Ghidra
 * Tool Options), and providing MCP tool specifications.
 * <p>
 * This class implements the {@link IGhidraMcpToolProvider} service interface
 * and is registered by {@link GhidraMcpPlugin}.
 */
public class GhidraMcpTools implements IGhidraMcpToolProvider {
	/** The Ghidra PluginTool context for accessing tool-level options. */
	private final PluginTool tool;
	/** ToolOptions instance for checking if tools are enabled. */
	private final ToolOptions options;
	/** Anchor for help documentation related to tool options. */
	private static final String OPTIONS_ANCHOR = "GhidraMcpTools";

	/**
	 * Constructs a GhidraMcpTools instance.
	 *
	 * @param tool The active {@link PluginTool} instance, providing tool-level context.
	 */
	public GhidraMcpTools(PluginTool tool) {
		this.tool = tool;
		this.options = tool.getOptions(GhidraMcpPlugin.MCP_TOOL_OPTIONS_CATEGORY);
	}

	/**
	 * Discovers available {@link IGhidraMcpSpecification} implementations using
	 * {@link ServiceLoader}, filters them based on whether they are enabled in the
	 * Ghidra Tool Options, and generates their {@link AsyncToolSpecification}.
	 *
	 * @return A list of {@code AsyncToolSpecification} for all enabled tools.
	 * @throws JsonProcessingException If there is an error serializing a tool's
	 *                                 schema.
	 *                                 (Propagated from potential schema generation
	 *                                 issues).
	 */
	@Override
	public List<Pair<String, AsyncToolSpecification>> getAvailableToolSpecifications() throws JsonProcessingException {
		// Load all tool providers and filter based on Ghidra options
		return ServiceLoader.load(IGhidraMcpSpecification.class).stream()
				.filter(provider -> {
					Class<? extends IGhidraMcpSpecification> toolClass = provider.type();
					GhidraMcpTool toolAnnotation = toolClass.getAnnotation(GhidraMcpTool.class);
					if (toolAnnotation == null) {
						Msg.warn(GhidraMcpTools.class,
								"Tool class " + toolClass.getSimpleName() +
										" is missing @GhidraMcpTool annotation. Skipping inclusion.");
						return false;
					}

					String toolKey = toolAnnotation.name();
					boolean isEnabled = this.options.getBoolean(toolKey, true);
					if (!isEnabled) {
						Msg.info(GhidraMcpTools.class, "Tool '" + toolKey + "' is disabled via options.");
					}
					return isEnabled;
				})
				.map(provider -> {
					try {
						IGhidraMcpSpecification toolInstance = provider.get();
						String toolName = toolInstance.getClass().getAnnotation(GhidraMcpTool.class).mcpName();
						return new Pair<String, AsyncToolSpecification>(toolName, toolInstance.specification(this.tool));
					} catch (Exception e) {
						String className = provider.type().getSimpleName();
						Msg.error(GhidraMcpTools.class,
								"Error getting specification for tool: " + className, e);
						return null;
					}
				})
				.filter(Objects::nonNull)
				.collect(Collectors.toList());
	}

	/**
	 * Static utility method to register Ghidra Tool Options for enabling/disabling
	 * individual MCP tools discovered via {@link ServiceLoader}.
	 * <p>
	 * This method iterates through all classes implementing
	 * {@link IGhidraMcpSpecification}, reads their {@link GhidraMcpTool}
	 * annotation, and registers a corresponding Boolean option.
	 *
	 * @param options The {@link ToolOptions} instance to register options with
	 *                (typically
	 *                obtained via {@code tool.getOptions(...)}).
	 * @param topic   The help topic string used for creating the
	 *                {@link HelpLocation}.
	 */
	public static void registerOptions(ToolOptions options, String topic) {
		HelpLocation help = new HelpLocation(topic, OPTIONS_ANCHOR);

		ServiceLoader.load(IGhidraMcpSpecification.class).stream().forEach(provider -> {
			Class<? extends IGhidraMcpSpecification> toolClass = provider.type();
			try {
				GhidraMcpTool toolAnnotation = toolClass.getAnnotation(GhidraMcpTool.class);
				if (toolAnnotation == null) {
					Msg.warn(GhidraMcpTools.class,
							"Tool class " + toolClass.getSimpleName() +
									" is missing the @GhidraMcpTool annotation. Skipping option registration.");
					// Use return to skip this iteration of the forEach lambda
					return;
				}

				String toolKey = toolAnnotation.name();
				String desc = toolAnnotation.description();

				// Register the boolean option (defaulting to true/enabled)
				options.registerOption(toolKey, OptionType.BOOLEAN_TYPE, true, help, desc);

			} catch (SecurityException e) {
				Msg.error(GhidraMcpTools.class,
						"Security exception accessing annotation for tool: " + toolClass.getSimpleName(),
						e);
			} catch (Exception e) {
				// Catch other potential errors during annotation processing
				Msg.error(GhidraMcpTools.class,
						"Error processing options for tool: " + toolClass.getSimpleName(),
						e);
			}
		}); // End of forEach
	}

}
