package com.themixednuts.models;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.themixednuts.utils.PaginatedResult;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class DataTypeListResult {

  private final PaginatedResult<DataTypeListEntry> dataTypes;
  private final int totalAvailable;
  private final int returnedCount;
  private final int pageSize;
  private final String category;
  private final String filterApplied;
  private final boolean includeBuiltin;
  private final String dataTypeKind;

  public DataTypeListResult(
      PaginatedResult<DataTypeListEntry> dataTypes,
      int totalAvailable,
      int returnedCount,
      int pageSize,
      String category,
      String filterApplied,
      boolean includeBuiltin,
      String dataTypeKind) {
    this.dataTypes = dataTypes;
    this.totalAvailable = totalAvailable;
    this.returnedCount = returnedCount;
    this.pageSize = pageSize;
    this.category = category;
    this.filterApplied = filterApplied;
    this.includeBuiltin = includeBuiltin;
    this.dataTypeKind = dataTypeKind;
  }

  @JsonProperty("data_types")
  public PaginatedResult<DataTypeListEntry> getDataTypes() {
    return dataTypes;
  }

  @JsonProperty("total_available")
  public int getTotalAvailable() {
    return totalAvailable;
  }

  @JsonProperty("returned_count")
  public int getReturnedCount() {
    return returnedCount;
  }

  @JsonProperty("page_size")
  public int getPageSize() {
    return pageSize;
  }

  @JsonProperty("category")
  public String getCategory() {
    return category;
  }

  @JsonProperty("filter_applied")
  public String getFilterApplied() {
    return filterApplied;
  }

  @JsonProperty("include_builtin")
  public boolean isIncludeBuiltin() {
    return includeBuiltin;
  }

  @JsonProperty("data_type_kind")
  public String getDataTypeKind() {
    return dataTypeKind;
  }
}
