package com.themixednuts.models;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.themixednuts.tools.datatypes.DataTypeKind;

/**
 * Base model containing common details for data types retrieved by
 * GhidraGetDataTypeTool.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public abstract class BaseDataTypeDetails {

	@JsonProperty("kind")
	private final DataTypeKind kind;

	@JsonProperty("path")
	private final String path;

	@JsonProperty("name")
	private final String name;

	@JsonProperty("category_path")
	private final String categoryPath;

	@JsonProperty("length")
	private final int length;

	@JsonProperty("alignment")
	private final int alignment;

	@JsonProperty("description")
	private final String description;

	protected BaseDataTypeDetails(
			DataTypeKind kind,
			String path,
			String name,
			String categoryPath,
			int length,
			int alignment,
			String description) {
		this.kind = kind;
		this.path = path;
		this.name = name;
		this.categoryPath = categoryPath;
		this.length = length;
		this.alignment = alignment;
		this.description = description;
	}

	// Getters
	public DataTypeKind getKind() {
		return kind;
	}

	public String getPath() {
		return path;
	}

	public String getName() {
		return name;
	}

	public String getCategoryPath() {
		return categoryPath;
	}

	public int getLength() {
		return length;
	}

	public int getAlignment() {
		return alignment;
	}

	public String getDescription() {
		return description;
	}
}
