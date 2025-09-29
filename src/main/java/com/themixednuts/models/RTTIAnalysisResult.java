package com.themixednuts.models;

import java.util.Map;
import java.util.Optional;

public class RTTIAnalysisResult {
    private final String rttiType;
    private final String address;
    private final Optional<String> vtableAddress;
    private final Optional<String> spareDataAddress;
    private final Optional<String> mangledName;
    private final Optional<String> demangledName;
    private final boolean demanglingSuccessful;
    private final Optional<String> demanglingError;
    private final boolean isValid;
    private final Optional<String> validationError;
    private final int length;
    private final String description;
    private final String mnemonic;
    private final String defaultLabelPrefix;
    private final Map<String, Object> additionalInfo;

    public RTTIAnalysisResult(String rttiType, String address, Optional<String> vtableAddress, 
                             Optional<String> spareDataAddress, Optional<String> mangledName, Optional<String> demangledName,
                             boolean demanglingSuccessful, Optional<String> demanglingError, 
                             boolean isValid, Optional<String> validationError, int length,
                             String description, String mnemonic, String defaultLabelPrefix,
                             Map<String, Object> additionalInfo) {
        this.rttiType = rttiType;
        this.address = address;
        this.vtableAddress = vtableAddress;
        this.spareDataAddress = spareDataAddress;
        this.mangledName = mangledName;
        this.demangledName = demangledName;
        this.demanglingSuccessful = demanglingSuccessful;
        this.demanglingError = demanglingError;
        this.isValid = isValid;
        this.validationError = validationError;
        this.length = length;
        this.description = description;
        this.mnemonic = mnemonic;
        this.defaultLabelPrefix = defaultLabelPrefix;
        this.additionalInfo = additionalInfo;
    }

    public String getRttiType() { return rttiType; }
    public String getAddress() { return address; }
    public Optional<String> getVtableAddress() { return vtableAddress; }
    public Optional<String> getSpareDataAddress() { return spareDataAddress; }
    public Optional<String> getMangledName() { return mangledName; }
    public Optional<String> getDemangledName() { return demangledName; }
    public boolean isDemanglingSuccessful() { return demanglingSuccessful; }
    public Optional<String> getDemanglingError() { return demanglingError; }
    public boolean isValid() { return isValid; }
    public Optional<String> getValidationError() { return validationError; }
    public int getLength() { return length; }
    public String getDescription() { return description; }
    public String getMnemonic() { return mnemonic; }
    public String getDefaultLabelPrefix() { return defaultLabelPrefix; }
    public Map<String, Object> getAdditionalInfo() { return additionalInfo; }
}
