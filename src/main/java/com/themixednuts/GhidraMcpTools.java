package com.themixednuts;

import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.ServiceLoader;
import java.util.Set;

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
import com.themixednuts.tools.grouped.IGroupedTool;

/**
 * Service implementation responsible for discovering, filtering (based on
 * Ghidra
 * Tool Options), and providing MCP tool specifications.
 * <p>
 * This class implements the {@link IGhidraMcpToolProvider} service interface
 * and is registered by {@link GhidraMcpPlugin}.
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
	public List<AsyncToolSpecification> getAvailableToolSpecifications() throws JsonProcessingException {
		// 1. Load all tool providers
		List<ServiceLoader.Provider<IGhidraMcpSpecification>> allProviders = ServiceLoader
				.load(IGhidraMcpSpecification.class).stream().collect(Collectors.toList());

		// 2. Filter based on Ghidra options
		List<ServiceLoader.Provider<IGhidraMcpSpecification>> enabledToolProviders = allProviders.stream()
				.filter(provider -> {
					Class<? extends IGhidraMcpSpecification> toolClass = provider.type();
					GhidraMcpTool toolAnnotation = toolClass.getAnnotation(GhidraMcpTool.class);
					if (toolAnnotation == null) {
						Msg.warn(GhidraMcpTools.class,
								"Tool class " + toolClass.getSimpleName() +
										" is missing @GhidraMcpTool annotation. Skipping inclusion.");
						return false;
					}
					String baseKey = toolAnnotation.name();
					ToolCategory categoryEnum = toolAnnotation.category();
					String fullKey = baseKey;
					if (categoryEnum != null && categoryEnum != ToolCategory.UNCATEGORIZED) {
						fullKey = categoryEnum.getCategoryName() + "." + baseKey;
					}
					boolean isEnabled = this.options.getBoolean(fullKey, true);
					if (!isEnabled) {
						Msg.info(GhidraMcpTools.class, "Tool '" + fullKey + "' is disabled via options.");
					}
					return isEnabled;
				})
				.collect(Collectors.toList());

		// 3. Identify categories managed by *enabled* grouped tools
		Set<String> groupedCategories = enabledToolProviders.stream()
				.filter(provider -> IGroupedTool.class.isAssignableFrom(provider.type()))
				.map(provider -> {
					try {
						IGhidraMcpSpecification instance = provider.get();
						Class<?> instanceClass = instance.getClass();
						java.lang.reflect.Field targetCategoryField = instanceClass.getDeclaredField("TARGET_CATEGORY"); // getField()
						targetCategoryField.setAccessible(true); // If not public
						ToolCategory targetCategoryEnum = (ToolCategory) targetCategoryField.get(instance);

						if (targetCategoryEnum != null) {
							return targetCategoryEnum.getCategoryName();
						}
						Msg.warn(this, "Could not retrieve TARGET_CATEGORY from grouped tool: " + provider.type().getSimpleName());
						return null;

					} catch (NoSuchFieldException e) {
						Msg.error(this,
								"Grouped tool " + provider.type().getSimpleName() + " does not have expected TARGET_CATEGORY field", e);
						return null;
					} catch (Exception e) { // Catch IllegalAccessException and other potential errors
						Msg.error(this, "Error accessing TARGET_CATEGORY for grouped tool " + provider.type().getSimpleName(), e);
						return null;
					}
				})
				.filter(Objects::nonNull)
				.collect(Collectors.toSet());

		// 4. Filter again: Keep enabled grouped tools, and only keep enabled granular
		// tools
		// if their category isn't managed by an enabled grouped tool.
		List<ServiceLoader.Provider<IGhidraMcpSpecification>> finalProviders = enabledToolProviders.stream()
				.filter(provider -> {
					Class<? extends IGhidraMcpSpecification> toolClass = provider.type();
					// Keep if it IS a grouped tool
					if (IGroupedTool.class.isAssignableFrom(toolClass)) {
						return true;
					}
					// Otherwise, keep only if its category is NOT in the groupedCategories set
					GhidraMcpTool toolAnnotation = toolClass.getAnnotation(GhidraMcpTool.class);
					if (toolAnnotation != null) {
						ToolCategory categoryEnum = toolAnnotation.category();
						if (categoryEnum != null && categoryEnum != ToolCategory.UNCATEGORIZED) {
							return !groupedCategories.contains(categoryEnum.getCategoryName());
						}
					}
					// Keep uncategorized tools or those with missing annotations (though the latter
					// were already filtered)
					return true;
				})
				.collect(Collectors.toList());

		// 5. Map the final providers to their specifications
		return finalProviders.stream()
				.map(provider -> {
					IGhidraMcpSpecification toolInstance = null;
					try {
						toolInstance = provider.get();
						return toolInstance.specification(this.tool);
					} catch (Exception e) {
						String className = (toolInstance != null) ? toolInstance.getClass().getSimpleName()
								: provider.type().getSimpleName();
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

				String baseKey = toolAnnotation.name();
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
