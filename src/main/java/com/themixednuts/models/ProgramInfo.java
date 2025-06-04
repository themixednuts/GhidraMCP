package com.themixednuts.models;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonInclude;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.CompilerSpec;
import java.util.Objects;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class ProgramInfo {

	private final String name;
	private final String path;
	private final String executablePath;
	private final String executableFormat;
	private final String creationDate;
	private final String architecture;
	private final String endianness;
	private final String processor;
	private final String compilerSpec;
	private final String imageBase;
	private final long memorySizeBytes;
	private final int numFunctions;
	private final int numSymbols;

	public ProgramInfo(Program program) {
		Objects.requireNonNull(program, "Program cannot be null");

		DomainFile domainFile = program.getDomainFile();
		Language language = program.getLanguage();
		CompilerSpec compilerSpecObj = program.getCompilerSpec();
		Address imageBaseAddr = program.getImageBase();

		this.name = program.getName();
		this.path = domainFile != null ? domainFile.getPathname() : "N/A (Not saved/associated with project)";
		this.executablePath = program.getExecutablePath();
		this.executableFormat = program.getExecutableFormat();
		this.creationDate = program.getCreationDate().toString();

		if (language != null) {
			this.architecture = language.getLanguageID().getIdAsString();
			this.endianness = language.isBigEndian() ? "Big Endian" : "Little Endian";
			this.processor = language.getProcessor().toString();
		} else {
			this.architecture = "Unknown";
			this.endianness = "Unknown";
			this.processor = "Unknown";
		}

		if (compilerSpecObj != null) {
			this.compilerSpec = compilerSpecObj.getCompilerSpecID().getIdAsString();
		} else {
			this.compilerSpec = "Unknown";
		}

		this.imageBase = imageBaseAddr != null ? imageBaseAddr.toString(true) : "N/A";
		this.memorySizeBytes = program.getMemory().getSize();
		this.numFunctions = program.getFunctionManager().getFunctionCount();
		this.numSymbols = program.getSymbolTable().getNumSymbols();
	}

	@JsonProperty("name")
	public String getName() {
		return name;
	}

	@JsonProperty("path")
	public String getPath() {
		return path;
	}

	@JsonProperty("executablePath")
	public String getExecutablePath() {
		return executablePath;
	}

	@JsonProperty("executableFormat")
	public String getExecutableFormat() {
		return executableFormat;
	}

	@JsonProperty("creationDate")
	public String getCreationDate() {
		return creationDate;
	}

	@JsonProperty("architecture")
	public String getArchitecture() {
		return architecture;
	}

	@JsonProperty("endianness")
	public String getEndianness() {
		return endianness;
	}

	@JsonProperty("processor")
	public String getProcessor() {
		return processor;
	}

	@JsonProperty("compilerSpec")
	public String getCompilerSpec() {
		return compilerSpec;
	}

	@JsonProperty("imageBase")
	public String getImageBase() {
		return imageBase;
	}

	@JsonProperty("memorySizeBytes")
	public long getMemorySizeBytes() {
		return memorySizeBytes;
	}

	@JsonProperty("numFunctions")
	public int getNumFunctions() {
		return numFunctions;
	}

	@JsonProperty("numSymbols")
	public int getNumSymbols() {
		return numSymbols;
	}
}