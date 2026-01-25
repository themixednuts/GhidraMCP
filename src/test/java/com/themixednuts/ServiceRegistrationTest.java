package com.themixednuts;

import static org.junit.jupiter.api.Assertions.*;

import com.themixednuts.tools.BaseMcpTool;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.reflect.Modifier;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;
import org.reflections.Reflections;
import org.reflections.scanners.Scanners;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ServiceRegistrationTest {

  private static final Logger log = LoggerFactory.getLogger(ServiceRegistrationTest.class);
  private static final String SERVICE_FILE_PATH =
      "META-INF/services/com.themixednuts.tools.BaseMcpTool";
  private static final String BASE_PACKAGE = "com.themixednuts.tools";

  @Test
  void testServiceRegistrationMatchesImplementations() throws Exception {
    log.info("Starting service registration verification test...");

    Set<String> serviceFileClasses = readServiceFile();
    log.info("Found {} classes listed in service file.", serviceFileClasses.size());

    Set<String> foundToolClasses = findToolImplementations();
    log.info(
        "Found {} concrete implementations of BaseMcpTool in package {}.",
        foundToolClasses.size(),
        BASE_PACKAGE);

    Set<String> missingFromServiceFile = new HashSet<>(foundToolClasses);
    missingFromServiceFile.removeAll(serviceFileClasses);

    Set<String> extraInServiceFile = new HashSet<>(serviceFileClasses);
    extraInServiceFile.removeAll(foundToolClasses);

    if (!missingFromServiceFile.isEmpty()) {
      String errorMessage =
          "Service file is missing entries for the following tool(s). Please ADD them:\n  - "
              + String.join("\n  - ", missingFromServiceFile);
      log.error(errorMessage);
      assertTrue(missingFromServiceFile.isEmpty(), errorMessage);
    }

    if (!extraInServiceFile.isEmpty()) {
      String errorMessage =
          "The following tool(s) are listed in the service file but were NOT FOUND or do NOT extend"
              + " BaseMcpTool. Please REMOVE these entries or ensure the classes exist and are"
              + " correctly implemented:\n"
              + "  - "
              + String.join("\n  - ", extraInServiceFile);
      log.error(errorMessage);
      assertTrue(extraInServiceFile.isEmpty(), errorMessage);
    }

    // Optional: Check count equality as a final verification
    if (missingFromServiceFile.isEmpty() && extraInServiceFile.isEmpty()) {
      assertEquals(
          serviceFileClasses.size(),
          foundToolClasses.size(),
          String.format(
              "Mismatch in total count between service file entries (%d) and found implementations"
                  + " (%d). This should not happen if the above checks passed.",
              serviceFileClasses.size(), foundToolClasses.size()));
    }

    log.info("Service registration verification test passed successfully.");
  }

  private Set<String> readServiceFile() throws Exception {
    Set<String> classes = new HashSet<>();
    InputStream is = getClass().getClassLoader().getResourceAsStream(SERVICE_FILE_PATH);
    if (is == null) {
      fail("Service file not found on classpath: " + SERVICE_FILE_PATH);
    }

    try (BufferedReader reader = new BufferedReader(new InputStreamReader(is))) {
      String line;
      while ((line = reader.readLine()) != null) {
        line = line.trim();
        if (!line.isEmpty() && !line.startsWith("#")) {
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
    Reflections reflections = new Reflections(BASE_PACKAGE, Scanners.SubTypes);

    Set<Class<? extends BaseMcpTool>> subTypes = reflections.getSubTypesOf(BaseMcpTool.class);
    log.debug("Found {} raw subtypes (including abstract).", subTypes.size());

    Set<String> concreteImplementations =
        subTypes.stream()
            // Filter out abstract classes
            .filter(cls -> !Modifier.isAbstract(cls.getModifiers()))
            .map(Class::getName)
            .collect(Collectors.toSet());

    log.debug("Filtered down to {} concrete implementations.", concreteImplementations.size());
    return concreteImplementations;
  }
}
