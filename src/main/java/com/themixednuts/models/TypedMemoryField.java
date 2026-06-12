package com.themixednuts.models;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record TypedMemoryField(
    @JsonProperty("path") String path,
    @JsonProperty("name") String name,
    @JsonProperty("data_type") String dataType,
    @JsonProperty("offset") Integer offset,
    @JsonProperty("length") Integer length,
    @JsonProperty("address") String address,
    @JsonProperty("hex_data") String hexData,
    @JsonProperty("value") String value) {}
