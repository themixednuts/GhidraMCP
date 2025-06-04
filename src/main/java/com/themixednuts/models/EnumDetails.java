package com.themixednuts.models;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.themixednuts.tools.datatypes.DataTypeKind;
import ghidra.program.model.data.Enum;

/**
 * Model representing the detailed definition of an Enum data type.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class EnumDetails extends BaseDataTypeDetails {

	private final long count;
	private final List<EnumEntryInfo> entries;

	public EnumDetails(Enum enumDt) {
		super(
				DataTypeKind.ENUM,
				enumDt.getPathName(),
				enumDt.getName(),
				enumDt.getCategoryPath().getPath(),
				enumDt.getLength(),
				enumDt.getAlignment(),
				Optional.ofNullable(enumDt.getDescription()).orElse(""));
		this.count = enumDt.getCount();

		List<EnumEntryInfo> entryInfos = new ArrayList<>();
		String[] names = enumDt.getNames();
		for (String entryName : names) {
			entryInfos.add(new EnumEntryInfo(entryName, enumDt.getValue(entryName)));
		}
		this.entries = entryInfos;
	}

	@JsonProperty("count")
	public long getCount() {
		return count;
	}

	@JsonProperty("entries")
	public List<EnumEntryInfo> getEntries() {
		return entries;
	}
}
