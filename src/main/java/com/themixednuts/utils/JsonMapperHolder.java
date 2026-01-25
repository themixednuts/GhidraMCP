package com.themixednuts.utils;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.json.JsonWriteFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

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
    ObjectMapper mapper = new ObjectMapper();
    mapper.getFactory().configure(JsonWriteFeature.ESCAPE_NON_ASCII.mappedFeature(), true);
    mapper.registerModule(new com.fasterxml.jackson.datatype.jdk8.Jdk8Module());
    return mapper;
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
   * @throws JsonProcessingException If serialization fails
   */
  public static String toJson(Object obj) throws JsonProcessingException {
    return INSTANCE.writeValueAsString(obj);
  }
}
