package com.themixednuts.models;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class DataTypeDeleteResult {

    private final boolean success;
    private final String message;
    private final String deletedType;
    private final String category;

    public DataTypeDeleteResult(boolean success,
                                String message,
                                String deletedType,
                                String category) {
        this.success = success;
        this.message = message;
        this.deletedType = deletedType;
        this.category = category;
    }

    @JsonProperty("success")
    public boolean isSuccess() {
        return success;
    }

    @JsonProperty("message")
    public String getMessage() {
        return message;
    }

    @JsonProperty("deleted_type")
    public String getDeletedType() {
        return deletedType;
    }

    @JsonProperty("category")
    public String getCategory() {
        return category;
    }
}

