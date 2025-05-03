package com.themixednuts.tools.grouped;

import java.util.List;
import java.util.ServiceLoader;
import java.util.ServiceLoader.Provider;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import com.themixednuts.tools.ToolCategory;

/**
 * Marker interface for grouped operation tools.
 * Tools implementing this interface bundle multiple related granular operations
 * and will only be registered when grouping mode is enabled.
 */
public interface IGroupedTool {

	/**
	 * Finds the classes of granular tools belonging to the specified target
	 * category.
	 *
	 * @param targetCategory The category name string to filter granular tools by.
	 * @return A list of classes for the granular tools.
	 */
	public static List<Class<? extends IGhidraMcpSpecification>> getGranularToolClasses(String targetCategory) {
		return getFilteredProviders(targetCategory)
				.map(Provider::type) // Get the class type
				.collect(Collectors.toList());
	}

	// Helper method to perform common loading and filtering
	private static Stream<ServiceLoader.Provider<IGhidraMcpSpecification>> getFilteredProviders(String targetCategory) {
		ServiceLoader<IGhidraMcpSpecification> loader = ServiceLoader.load(IGhidraMcpSpecification.class);

		// Validate targetCategory
		if (targetCategory == null || targetCategory.trim().isEmpty()) {
			ghidra.util.Msg.error(IGroupedTool.class,
					"Target category provided to getFilteredProviders cannot be null or empty.");
			return Stream.empty();
		}

		return loader.stream()
				// Filter out grouped tools themselves
				.filter(specProvider -> !IGroupedTool.class.isAssignableFrom(specProvider.type()))
				// Filter based on matching the target category annotation
				.filter(specProvider -> hasMatchingCategory(specProvider, targetCategory));
	}

	private static boolean hasMatchingCategory(ServiceLoader.Provider<IGhidraMcpSpecification> specProvider,
			String targetCategory) {
		Class<?> specClass = specProvider.type();
		GhidraMcpTool specAnnotation = specClass.getAnnotation(GhidraMcpTool.class);

		if (specAnnotation == null) {
			ghidra.util.Msg.warn(IGroupedTool.class, "Service " + specClass.getName()
					+ " implements IGhidraMcpSpecification but lacks @GhidraMcpTool annotation. Skipping for grouping.");
			return false;
		}

		ToolCategory specCategoryEnum = specAnnotation.category();
		if (specCategoryEnum == null || specCategoryEnum == ToolCategory.UNCATEGORIZED
				|| specCategoryEnum == ToolCategory.GROUPED) {
			return false;
		}
		return specCategoryEnum.getCategoryName().equals(targetCategory.trim());
	}

}