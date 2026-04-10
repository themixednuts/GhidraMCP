package com.themixednuts.utils;

import tools.jackson.core.JacksonException;
import tools.jackson.core.json.JsonWriteFeature;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

/**
 * Singleton holder for shared ObjectMapper instance. Provides a consistently configured
 * ObjectMapper for JSON serialization across the plugin.
 */
public final class JsonMapperHolder {

  private static final ObjectMapper INSTANCE = createMapper();

  private JsonMapperHolder() {
    // Prevent instantiation
  }

  private static ObjectMapper createMapper() {
    return JsonMapper.builder().enable(JsonWriteFeature.ESCAPE_NON_ASCII).build();
  }

  /** Gets the shared ObjectMapper instance. */
  public static ObjectMapper getMapper() {
    return INSTANCE;
  }

  /**
   * Serializes an object to JSON string.
   *
   * @param obj The object to serialize
   * @return The JSON string
   * @throws JacksonException If serialization fails
   */
  public static String toJson(Object obj) throws JacksonException {
    return INSTANCE.writeValueAsString(obj);
  }
}
