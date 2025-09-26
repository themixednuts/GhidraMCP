package com.themixednuts.models;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class MemoryReadResult {

    private final String address;
    private final int length;
    private final String hexData;
    private final String readable;
    private final int bytesRequested;
    private final int bytesRead;

    public MemoryReadResult(String address,
                            int length,
                            String hexData,
                            String readable,
                            int bytesRequested,
                            int bytesRead) {
        this.address = address;
        this.length = length;
        this.hexData = hexData;
        this.readable = readable;
        this.bytesRequested = bytesRequested;
        this.bytesRead = bytesRead;
    }

    @JsonProperty("address")
    public String getAddress() {
        return address;
    }

    @JsonProperty("length")
    public int getLength() {
        return length;
    }

    @JsonProperty("hex_data")
    public String getHexData() {
        return hexData;
    }

    @JsonProperty("readable")
    public String getReadable() {
        return readable;
    }

    @JsonProperty("bytes_requested")
    public int getBytesRequested() {
        return bytesRequested;
    }

    @JsonProperty("bytes_read")
    public int getBytesRead() {
        return bytesRead;
    }
}

