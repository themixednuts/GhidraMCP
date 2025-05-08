package com.themixednuts.models;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Model representing a single member (component) within a Structure.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class StructureMemberInfo {

	@JsonProperty("name")
	private final String name;

	@JsonProperty("data_type_path")
	private final String dataTypePath;

	@JsonProperty("offset")
	private final int offset;

	@JsonProperty("ordinal")
	private final int ordinal;

	@JsonProperty("length")
	private final int length;

	@JsonProperty("comment")
	private final String comment;

	@JsonProperty("is_bit_field")
	private final boolean isBitField;

	// @JsonProperty("bit_size") // Linter issue
	// private final Integer bitSize;

	// @JsonProperty("bit_offset") // Linter issue
	// private final Integer bitOffset;

	public StructureMemberInfo(
			String name,
			String dataTypePath,
			int offset,
			int ordinal,
			int length,
			String comment,
			boolean isBitField
	// Integer bitSize, // Linter issue
	// Integer bitOffset // Linter issue
	) {
		this.name = name;
		this.dataTypePath = dataTypePath;
		this.offset = offset;
		this.ordinal = ordinal;
		this.length = length;
		this.comment = comment;
		this.isBitField = isBitField;
		// this.bitSize = bitSize;
		// this.bitOffset = bitOffset;
	}

	// Getters
	public String getName() {
		return name;
	}

	public String getDataTypePath() {
		return dataTypePath;
	}

	public int getOffset() {
		return offset;
	}

	public int getOrdinal() {
		return ordinal;
	}

	public int getLength() {
		return length;
	}

	public String getComment() {
		return comment;
	}

	public boolean isBitField() {
		return isBitField;
	}
	// public Integer getBitSize() { return bitSize; }
	// public Integer getBitOffset() { return bitOffset; }
}
