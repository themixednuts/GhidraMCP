package com.themixednuts.models;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
// Import specific types for instanceof checks
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.Union;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.Pointer;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Utility class to hold relevant information about a Ghidra DataType for JSON
 * serialization.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class DataTypeInfo {

	@JsonProperty("name")
	private final String name;

	@JsonProperty("display_name")
	private final String displayName;

	@JsonProperty("path_name") // Consistent naming with tool
	private final String pathName;

	@JsonProperty("category_path")
	private final String categoryPath;

	@JsonProperty("length")
	private final int length;

	@JsonProperty("aligned_length")
	private final int alignedLength;

	@JsonProperty("alignment") // Add alignment
	private final int alignment;

	@JsonProperty("description")
	private final String description;

	@JsonProperty("is_zero_length")
	private final boolean isZeroLength;

	// Added type flags
	@JsonProperty("is_structure")
	private final boolean isStructure;
	@JsonProperty("is_union")
	private final boolean isUnion;
	@JsonProperty("is_enum")
	private final boolean isEnum;
	@JsonProperty("is_type_def")
	private final boolean isTypeDef;
	@JsonProperty("is_pointer")
	private final boolean isPointer;

	// New field for members (will be null if not applicable)
	@JsonProperty("members")
	private final List<?> members; // Use wildcard, specific type handled in constructor

	public DataTypeInfo(DataType dataType) {
		this.name = dataType.getName();
		this.displayName = dataType.getDisplayName();
		this.pathName = dataType.getPathName();

		CategoryPath catPath = dataType.getCategoryPath();
		this.categoryPath = (catPath != null) ? catPath.getPath() : null;

		this.length = dataType.getLength();
		this.alignedLength = dataType.getAlignedLength();
		this.alignment = dataType.getAlignment();
		this.description = dataType.getDescription();
		this.isZeroLength = dataType.isZeroLength();

		// Set type flags
		this.isStructure = dataType instanceof Structure;
		this.isUnion = dataType instanceof Union;
		this.isEnum = dataType instanceof Enum;
		this.isTypeDef = dataType instanceof TypeDef;
		this.isPointer = dataType instanceof Pointer;

		// Populate members if applicable
		if (this.isStructure) {
			// TODO: Populate with StructMemberInfo when created
			this.members = null; // Placeholder
		} else if (this.isUnion) {
			Union unionDt = (Union) dataType;
			this.members = Arrays.stream(unionDt.getDefinedComponents()) // Use getDefinedComponents
					.map(UnionMemberInfo::new)
					.collect(Collectors.toList());
		} else if (this.isEnum) {
			// TODO: Populate with EnumEntryInfo when created
			this.members = null; // Placeholder
		} else {
			this.members = null;
		}
	}

	// Getters
	public String getName() {
		return name;
	}

	public String getDisplayName() {
		return displayName;
	}

	public String getPathName() {
		return pathName;
	}

	public String getCategoryPath() {
		return categoryPath;
	}

	public int getLength() {
		return length;
	}

	public int getAlignedLength() {
		return alignedLength;
	}

	public int getAlignment() {
		return alignment;
	}

	public String getDescription() {
		return description;
	}

	public boolean isZeroLength() {
		return isZeroLength;
	}

	// Getters for type flags
	public boolean isStructure() {
		return isStructure;
	}

	public boolean isUnion() {
		return isUnion;
	}

	public boolean isEnum() {
		return isEnum;
	}

	public boolean isTypeDef() {
		return isTypeDef;
	}

	public boolean isPointer() {
		return isPointer;
	}

	// Getter for members
	public List<?> getMembers() {
		return members;
	}
}