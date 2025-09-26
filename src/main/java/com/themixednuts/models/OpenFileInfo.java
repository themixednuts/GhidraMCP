package com.themixednuts.models;

/**
 * Simple data transfer object representing an open file within a Ghidra project.
 */
public class OpenFileInfo {

    private final String name;
    private final String path;
    private final int version;
    private final boolean changed;
    private final boolean readOnly;

    public OpenFileInfo(
        String name,
        String path,
        int version,
        boolean changed,
        boolean readOnly
    ) {
        this.name = name;
        this.path = path;
        this.version = version;
        this.changed = changed;
        this.readOnly = readOnly;
    }

    public String getName() {
        return name;
    }

    public String getPath() {
        return path;
    }

    public int getVersion() {
        return version;
    }

    public boolean isChanged() {
        return changed;
    }

    public boolean isReadOnly() {
        return readOnly;
    }
}

