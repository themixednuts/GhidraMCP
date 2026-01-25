package com.themixednuts.utils.jsonschema.google.traits;

/**
 * Capability interface for format keyword. Supported on String, Number, and Integer types in Google
 * AI API.
 *
 * <p>The format field specifies the data format. While any value is allowed, certain formats
 * trigger special functionality in the Google AI API.
 *
 * <p>This interface follows the trait/capability pattern, allowing type-safe method chaining with
 * the concrete builder type.
 *
 * @param <SELF> The concrete builder type for method chaining
 * @see <a href="https://ai.google.dev/api/caching#Schema">Google AI API Schema (format)</a>
 */
public interface IFormat<SELF> {

  /**
   * Sets the format of the data. Any value is allowed, but most do not trigger any special
   * functionality.
   *
   * <p>Common formats:
   *
   * <ul>
   *   <li>String: email, uri, date-time, enum, etc.
   *   <li>Number: float, double
   *   <li>Integer: int32, int64
   * </ul>
   *
   * @param format The format string
   * @return This builder instance for chaining
   */
  SELF format(String format);
}
