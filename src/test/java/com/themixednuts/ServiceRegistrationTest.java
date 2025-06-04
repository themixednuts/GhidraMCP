package com.themixednuts;

import com.themixednuts.tools.IGhidraMcpSpecification;
import org.junit.jupiter.api.Test;
import org.reflections.Reflections;
import org.reflections.scanners.Scanners;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.reflect.Modifier;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;

public class ServiceRegistrationTest {

	private static final Logger log = LoggerFactory.getLogger(ServiceRegistrationTest.class);
	private static final String SERVICE_FILE_PATH = "META-INF/services/com.themixednuts.tools.IGhidraMcpSpecification";
	private static final String BASE_PACKAGE = "com.themixednuts.tools";

	@Test
	void testServiceRegistrationMatchesImplementations() throws Exception {
		log.info("Starting service registration verification test...");

		Set<String> serviceFileClasses = readServiceFile();
		log.info("Found {} classes listed in service file.", serviceFileClasses.size());

		Set<String> foundToolClasses = findToolImplementations();
		log.info("Found {} concrete implementations of IGhidraMcpSpecification in package {}.", foundToolClasses.size(),
				BASE_PACKAGE);

		Set<String> missingFromServiceFile = new HashSet<>(foundToolClasses);
		missingFromServiceFile.removeAll(serviceFileClasses);

		Set<String> extraInServiceFile = new HashSet<>(serviceFileClasses);
		extraInServiceFile.removeAll(foundToolClasses);

		if (!missingFromServiceFile.isEmpty()) {
			String errorMessage = "Service file is missing entries for the following tool(s). Please ADD them:\n  - "
					+ String.join("\n  - ", missingFromServiceFile);
			log.error(errorMessage);
			assertTrue(missingFromServiceFile.isEmpty(), errorMessage);
		}

		if (!extraInServiceFile.isEmpty()) {
			String errorMessage = "The following tool(s) are listed in the service file but were NOT FOUND or do NOT implement IGhidraMcpSpecification. Please REMOVE these entries or ensure the classes exist and are correctly implemented:\n  - "
					+ String.join("\n  - ", extraInServiceFile);
			log.error(errorMessage);
			assertTrue(extraInServiceFile.isEmpty(), errorMessage);
		}

		// Optional: Check count equality as a final verification
		if (missingFromServiceFile.isEmpty() && extraInServiceFile.isEmpty()) {
			assertEquals(serviceFileClasses.size(), foundToolClasses.size(),
					String.format(
							"Mismatch in total count between service file entries (%d) and found implementations (%d). This should not happen if the above checks passed.",
							serviceFileClasses.size(), foundToolClasses.size()));
		}

		log.info("Service registration verification test passed successfully.");
	}

	private Set<String> readServiceFile() throws Exception {
		Set<String> classes = new HashSet<>();
		// Use the class loader to find the resource, ensuring it works within
		// JARs/builds
		InputStream is = getClass().getClassLoader().getResourceAsStream(SERVICE_FILE_PATH);
		if (is == null) {
			fail("Service file not found on classpath: " + SERVICE_FILE_PATH);
		}

		try (BufferedReader reader = new BufferedReader(new InputStreamReader(is))) {
			String line;
			while ((line = reader.readLine()) != null) {
				line = line.trim();
				if (!line.isEmpty() && !line.startsWith("#")) { // Ignore empty lines and standard Java comments
					classes.add(line);
				}
			}
		} catch (Exception e) {
			log.error("Error reading service file: {}", SERVICE_FILE_PATH, e);
			throw e;
		}
		return classes;
	}

	private Set<String> findToolImplementations() {
		log.debug("Scanning package '{}' for implementations...", BASE_PACKAGE);
		// Using Reflections library
		Reflections reflections = new Reflections(BASE_PACKAGE, Scanners.SubTypes); // Scan for subtypes

		Set<Class<? extends IGhidraMcpSpecification>> subTypes = reflections.getSubTypesOf(IGhidraMcpSpecification.class);
		log.debug("Found {} raw subtypes (including interfaces/abstract).", subTypes.size());

		Set<String> concreteImplementations = subTypes.stream()
				// Filter out interfaces and abstract classes
				.filter(cls -> !cls.isInterface() && !Modifier.isAbstract(cls.getModifiers()))
				.map(Class::getName) // Get the fully qualified name
				.collect(Collectors.toSet());

		log.debug("Filtered down to {} concrete implementations.", concreteImplementations.size());
		return concreteImplementations;
	}
}