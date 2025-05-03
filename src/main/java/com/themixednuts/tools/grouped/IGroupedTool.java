package com.themixednuts.tools.grouped;

import java.util.List;
import java.util.ServiceLoader;
import java.util.ServiceLoader.Provider;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;

/**
 * Marker interface for grouped operation tools.
 * Tools implementing this interface bundle multiple related granular operations
 * and will only be registered when grouping mode is enabled.
 */
public interface IGroupedTool {

	/**
	 * Finds the classes of granular tools belonging to the same category as the
	 * given
	 * grouped tool class.
	 *
	 * @param groupedToolClass The class of the grouped tool.
	 * @return A list of classes for the granular tools.
	 */
	public static List<Class<? extends IGhidraMcpSpecification>> getGranularToolClasses(
			Class<? extends IGroupedTool> groupedToolClass) {
		return getFilteredProviders(groupedToolClass)
				.map(Provider::type) // Get the class type
				.collect(Collectors.toList());
	}

	// Helper method to perform common loading and filtering
	private static Stream<ServiceLoader.Provider<IGhidraMcpSpecification>> getFilteredProviders(
			Class<? extends IGroupedTool> groupedToolClass) {
		ServiceLoader<IGhidraMcpSpecification> loader = ServiceLoader.load(IGhidraMcpSpecification.class);
		GhidraMcpTool groupedAnnotation = groupedToolClass.getAnnotation(GhidraMcpTool.class);
		if (groupedAnnotation == null) {
			ghidra.util.Msg.error(IGroupedTool.class,
					"Grouped tool class " + groupedToolClass.getName() + " is missing @GhidraMcpTool annotation.");
			return Stream.empty(); // Return empty stream if the grouped tool itself is misconfigured
		}

		return loader.stream()
				// Filter out other grouped tools themselves
				.filter(specProvider -> !IGroupedTool.class.isAssignableFrom(specProvider.type()))
				// Filter based on matching category annotation
				.filter(specProvider -> hasMatchingCategory(specProvider, groupedAnnotation));
	}

	// Helper method to check for matching category annotation
	private static boolean hasMatchingCategory(ServiceLoader.Provider<IGhidraMcpSpecification> specProvider,
			GhidraMcpTool groupedAnnotation) {
		Class<?> specClass = specProvider.type();
		GhidraMcpTool specAnnotation = specClass.getAnnotation(GhidraMcpTool.class);

		if (specAnnotation == null) {
			ghidra.util.Msg.warn(IGroupedTool.class, "Service " + specClass.getName()
					+ " implements IGhidraMcpSpecification but lacks @GhidraMcpTool annotation. Skipping for grouping.");
			return false; // Exclude spec if its annotation is missing
		}
		// Compare categories - ensure they are not null before comparing
		String specCategory = specAnnotation.category();
		String groupedCategory = groupedAnnotation.category();

		// Grouped tools must have a category defined for this logic to work
		if (groupedCategory == null || groupedCategory.trim().isEmpty()) {
			ghidra.util.Msg.warn(IGroupedTool.class,
					"Grouped tool " + groupedAnnotation.key() + " has no category defined. Cannot group tools.");
			return false;
		}
		// Granular tools must also have a category defined
		if (specCategory == null || specCategory.trim().isEmpty()) {
			return false; // Granular tool is not categorized, cannot belong to a group
		}
		return specCategory.equals(groupedCategory);
	}

}