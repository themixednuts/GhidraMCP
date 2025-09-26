package com.themixednuts.models;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class MemoryWriteResult {

    private final boolean success;
    private final String address;
    private final int bytesWritten;
    private final String hexData;

    public MemoryWriteResult(boolean success, String address, int bytesWritten, String hexData) {
        this.success = success;
        this.address = address;
        this.bytesWritten = bytesWritten;
        this.hexData = hexData;
    }

    @JsonProperty("success")
    public boolean isSuccess() {
        return success;
    }

    @JsonProperty("address")
    public String getAddress() {
        return address;
    }

    @JsonProperty("bytes_written")
    public int getBytesWritten() {
        return bytesWritten;
    }

    @JsonProperty("hex_data")
    public String getHexData() {
        return hexData;
    }
}

