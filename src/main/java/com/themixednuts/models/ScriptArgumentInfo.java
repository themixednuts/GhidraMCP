package com.themixednuts.models;

import java.util.List;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;

/**
 * Container class for models related to Ghidra Script arguments.
 */
public class ScriptArgumentInfo {

	/**
	 * Represents a single argument for a Ghidra script, used for both
	 * describing expected arguments (metadata) and providing input values.
	 */
	public record ScriptArgument(
			// Always present
			@JsonProperty(value = "order", required = true) int order,
			@JsonProperty(value = "type", required = true) String type,
			@JsonProperty(value = "name", required = true) String name,

			// Optional: Present in metadata from list_scripts, optional in input for
			// run_script
			@JsonProperty("description") @JsonInclude(Include.NON_NULL) String description,

			// Optional: Present with value in input for run_script, absent/null in metadata
			// from list_scripts
			@JsonProperty("value") @JsonInclude(Include.NON_NULL) Object value) {
	}

	/**
	 * Represents information about a discoverable Ghidra script, including
	 * its metadata and expected arguments.
	 * Used as the result structure for list_ghidra_scripts.
	 */
	public record ScriptInfo(
			@JsonProperty("name") String name,
			@JsonProperty("description") String description,
			@JsonProperty("category") String category,
			// Update to use the unified ScriptArgument record
			@JsonProperty("arguments") List<ScriptArgument> arguments) {
	}
}