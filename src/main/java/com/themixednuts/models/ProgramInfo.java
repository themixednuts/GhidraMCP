package com.themixednuts.models;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import ghidra.framework.model.DomainFile;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * Represents summary information about the current program including metadata and memory layout.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ProgramInfo {

    private final String name;
    private final String executableFormat;
    private final String languageID;
    private final String compilerSpecID;
    private final String imageBase;
    private final List<MemoryBlockInfo> memoryBlocks;
    private final String domainFilePath;
    private final boolean readOnly;

    public ProgramInfo(Program program) {
        Objects.requireNonNull(program, "program");

        this.name = program.getName();
        this.executableFormat = program.getExecutableFormat();
        this.languageID = program.getLanguageID().getIdAsString();
        this.compilerSpecID = program.getCompilerSpec().getCompilerSpecID().getIdAsString();
        this.imageBase = program.getImageBase().toString();
        this.memoryBlocks = extractMemoryBlocks(program.getMemory());

        DomainFile domainFile = program.getDomainFile();
        this.domainFilePath = domainFile != null ? domainFile.getPathname() : null;
        this.readOnly = domainFile != null && domainFile.isReadOnly();
    }

    private static List<MemoryBlockInfo> extractMemoryBlocks(Memory memory) {
        if (memory == null) {
            return List.of();
        }
        return Arrays.stream(memory.getBlocks())
                .map(block -> new MemoryBlockInfo(
                        block.getName(),
                        block.getStart().toString(),
                        block.getEnd().toString(),
                        block.getSize(),
                        block.isInitialized(),
                        block.isRead(),
                        block.isWrite(),
                        block.isExecute(),
                        block.getComment() != null ? block.getComment() : "",
                        block.getType().toString()))
                .collect(Collectors.toList());
    }

    @JsonProperty("name")
    public String getName() {
        return name;
    }

    @JsonProperty("executable_format")
    public String getExecutableFormat() {
        return executableFormat;
    }

    @JsonProperty("language_id")
    public String getLanguageID() {
        return languageID;
    }

    @JsonProperty("compiler_spec_id")
    public String getCompilerSpecID() {
        return compilerSpecID;
    }

    @JsonProperty("image_base")
    public String getImageBase() {
        return imageBase;
    }

    @JsonProperty("memory_blocks")
    public List<MemoryBlockInfo> getMemoryBlocks() {
        return memoryBlocks;
    }

    @JsonProperty("domain_file_path")
    public String getDomainFilePath() {
        return domainFilePath;
    }

    @JsonProperty("read_only")
    public boolean isReadOnly() {
        return readOnly;
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class MemoryBlockInfo {
        private final String name;
        private final String startAddress;
        private final String endAddress;
        private final long size;
        private final boolean initialized;
        private final boolean readable;
        private final boolean writable;
        private final boolean executable;
        private final String comment;
        private final String type;

        public MemoryBlockInfo(String name,
                String startAddress,
                String endAddress,
                long size,
                boolean initialized,
                boolean readable,
                boolean writable,
                boolean executable,
                String comment,
                String type) {
            this.name = name;
            this.startAddress = startAddress;
            this.endAddress = endAddress;
            this.size = size;
            this.initialized = initialized;
            this.readable = readable;
            this.writable = writable;
            this.executable = executable;
            this.comment = comment;
            this.type = type;
        }

        @JsonProperty("name")
        public String getName() {
            return name;
        }

        @JsonProperty("start_address")
        public String getStartAddress() {
            return startAddress;
        }

        @JsonProperty("end_address")
        public String getEndAddress() {
            return endAddress;
        }

        @JsonProperty("size")
        public long getSize() {
            return size;
        }

        @JsonProperty("initialized")
        public boolean isInitialized() {
            return initialized;
        }

        @JsonProperty("readable")
        public boolean isReadable() {
            return readable;
        }

        @JsonProperty("writable")
        public boolean isWritable() {
            return writable;
        }

        @JsonProperty("executable")
        public boolean isExecutable() {
            return executable;
        }

        @JsonProperty("comment")
        public String getComment() {
            return comment;
        }

        @JsonProperty("type")
        public String getType() {
            return type;
        }
    }
}


