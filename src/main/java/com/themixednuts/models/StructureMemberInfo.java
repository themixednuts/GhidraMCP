package com.themixednuts.models;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Model representing a single member (component) within a Structure.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class StructureMemberInfo {

	private final String name;

	private final String dataTypePath;

	private final int offset;

	private final int ordinal;

	private final int length;

	private final String comment;

	private final boolean isBitField;

	public StructureMemberInfo(
			String name,
			String dataTypePath,
			int offset,
			int ordinal,
			int length,
			String comment,
			boolean isBitField) {
		this.name = name;
		this.dataTypePath = dataTypePath;
		this.offset = offset;
		this.ordinal = ordinal;
		this.length = length;
		this.comment = comment;
		this.isBitField = isBitField;
	}

	@JsonProperty("name")
	public String getName() {
		return name;
	}

	@JsonProperty("data_type_path")
	public String getDataTypePath() {
		return dataTypePath;
	}

	@JsonProperty("offset")
	public int getOffset() {
		return offset;
	}

	@JsonProperty("ordinal")
	public int getOrdinal() {
		return ordinal;
	}

	@JsonProperty("length")
	public int getLength() {
		return length;
	}

	@JsonProperty("comment")
	public String getComment() {
		return comment;
	}

	@JsonProperty("is_bit_field")
	public boolean isBitField() {
		return isBitField;
	}
}
