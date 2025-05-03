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
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;
import com.themixednuts.tools.ToolCategory;

/**
 * Service implementation responsible for discovering, filtering (based on
 * Ghidra
 * Tool Options), and providing MCP tool specifications.
 * <p>
 * This class implements the {@link IGhidraMcpToolProvider} service interface
 * and is registered by {@link GhidraMCPPlugin}.
 */
public class GhidraMcpTools implements IGhidraMcpToolProvider {
	/** The Ghidra PluginTool context used to access options and pass to tools. */
	private final PluginTool tool;
	/** ToolOptions instance for checking if tools are enabled. */
	private final ToolOptions options;
	/** Anchor for help documentation related to tool options. */
	private static final String OPTIONS_ANCHOR = "GhidraMcpTools";

	/**
	 * Constructs a GhidraMcpTools instance.
	 *
	 * @param tool The active {@link PluginTool} instance, providing context.
	 */
	public GhidraMcpTools(PluginTool tool) {
		this.tool = tool;
		this.options = tool.getOptions(GhidraMCPPlugin.MCP_TOOL_OPTIONS_CATEGORY);
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
	public List<AsyncToolSpecification> getAvailableToolSpecifications() throws JsonProcessingException {
		return ServiceLoader.load(IGhidraMcpSpecification.class).stream()
				// Filter 1: Check if the tool is enabled via Ghidra Tool Options
				.filter(provider -> {
					Class<? extends IGhidraMcpSpecification> toolClass = provider.type();
					GhidraMcpTool toolAnnotation = toolClass.getAnnotation(GhidraMcpTool.class);
					if (toolAnnotation == null) {
						Msg.warn(GhidraMcpTools.class,
								"Tool class " + toolClass.getSimpleName() +
										" is missing @GhidraMcpTool annotation. Skipping inclusion.");
						return false; // Skip tools without the required annotation
					}
					String baseKey = toolAnnotation.key();
					ToolCategory categoryEnum = toolAnnotation.category();
					String fullKey = baseKey;
					if (categoryEnum != null && categoryEnum != ToolCategory.UNCATEGORIZED) {
						fullKey = categoryEnum.getCategoryName() + "." + baseKey;
					}
					// Check the ToolOptions retrieved in the constructor
					boolean isEnabled = this.options.getBoolean(fullKey, true);
					if (!isEnabled) {
						Msg.info(GhidraMcpTools.class, "Tool '" + fullKey + "' is disabled via options.");
					}
					return isEnabled;
				})
				// Map: Instantiate enabled tools and get their specification
				.map(provider -> {
					IGhidraMcpSpecification toolInstance = null;
					try {
						toolInstance = provider.get(); // Instantiate the tool
						// Pass the PluginTool context to the tool's specification method
						return toolInstance.specification(this.tool);
					} catch (Exception e) {
						// Log error if instantiation or specification generation fails
						String className = (toolInstance != null) ? toolInstance.getClass().getSimpleName()
								: provider.type().getSimpleName();
						Msg.error(GhidraMcpTools.class,
								"Error getting specification for tool: " + className, e);
						return null; // Exclude faulty tool from the final list
					}
				})
				// Filter 2: Remove any nulls resulting from errors in the map step
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

				String baseKey = toolAnnotation.key();
				String desc = toolAnnotation.description();
				ToolCategory categoryEnum = toolAnnotation.category();

				String fullKey = baseKey;
				if (categoryEnum != null && categoryEnum != ToolCategory.UNCATEGORIZED) {
					fullKey = categoryEnum.getCategoryName() + "." + baseKey;
				}

				// Register the boolean option (defaulting to true/enabled)
				options.registerOption(fullKey, OptionType.BOOLEAN_TYPE, true, help, desc);

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
