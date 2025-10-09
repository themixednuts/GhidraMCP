package com.themixednuts.utils.jsonschema.draft7;

/**
 * Represents a conditional requirement specification (if/then pair) for JSON
 * Schema Draft 7.
 * Created via the ConditionalSpec.conditional() factory method.
 */
public class ConditionalSpec {
    private final String ifProperty;
    private final Object ifValue;
    private String[] thenRequired;

    public ConditionalSpec(String ifProperty, Object ifValue) {
        this.ifProperty = ifProperty;
        this.ifValue = ifValue;
    }

    /**
     * Factory method to create a conditional specification.
     * 
     * @param ifProperty The property name to check in the if clause
     * @param ifValue The value that triggers the then clause
     * @return A new ConditionalSpec instance
     */
    public static ConditionalSpec conditional(String ifProperty, Object ifValue) {
        return new ConditionalSpec(ifProperty, ifValue);
    }

    public ConditionalSpec require(String... fieldNames) {
        this.thenRequired = fieldNames;
        return this;
    }

    public String getIfProperty() {
        return ifProperty;
    }

    public Object getIfValue() {
        return ifValue;
    }

    public String[] getThenRequired() {
        return thenRequired != null ? thenRequired : new String[0];
    }
}
