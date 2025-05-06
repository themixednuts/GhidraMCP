package com.themixednuts.models;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Represents information about a Ghidra bookmark.
 */
public record BookmarkInfo(
		@JsonProperty("address") String address,
		@JsonProperty("type") String type,
		@JsonProperty("category") String category,
		@JsonProperty("comment") String comment) {
}