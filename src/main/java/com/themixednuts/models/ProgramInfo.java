package com.themixednuts.models;

import com.fasterxml.jackson.annotation.JsonProperty;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.CompilerSpec;
import java.util.Objects;

/**
 * Represents information about a Ghidra Program.
 */
public class ProgramInfo {

	@JsonProperty("name")
	private final String name;

	@JsonProperty("path")
	private final String path;

	@JsonProperty("executablePath")
	private final String executablePath;

	@JsonProperty("executableFormat")
	private final String executableFormat;

	@JsonProperty("creationDate")
	private final String creationDate;

	@JsonProperty("architecture")
	private final String architecture;

	@JsonProperty("endianness")
	private final String endianness;

	@JsonProperty("processor")
	private final String processor;

	@JsonProperty("compilerSpec")
	private final String compilerSpec;

	@JsonProperty("imageBase")
	private final String imageBase;

	@JsonProperty("memorySizeBytes")
	private final long memorySizeBytes;

	@JsonProperty("numFunctions")
	private final int numFunctions;

	@JsonProperty("numSymbols")
	private final int numSymbols;

	/**
	 * Constructs ProgramInfo by extracting data from a Ghidra Program object.
	 *
	 * @param program The Ghidra Program instance. Must not be null.
	 */
	public ProgramInfo(Program program) {
		Objects.requireNonNull(program, "Program cannot be null");

		DomainFile domainFile = program.getDomainFile();
		Language language = program.getLanguage();
		CompilerSpec compilerSpecObj = program.getCompilerSpec(); // Use different name to avoid confusion
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

	// --- Getters ---

	public String getName() {
		return name;
	}

	public String getPath() {
		return path;
	}

	public String getExecutablePath() {
		return executablePath;
	}

	public String getExecutableFormat() {
		return executableFormat;
	}

	public String getCreationDate() {
		return creationDate;
	}

	public String getArchitecture() {
		return architecture;
	}

	public String getEndianness() {
		return endianness;
	}

	public String getProcessor() {
		return processor;
	}

	public String getCompilerSpec() {
		return compilerSpec;
	}

	public String getImageBase() {
		return imageBase;
	}

	public long getMemorySizeBytes() {
		return memorySizeBytes;
	}

	public int getNumFunctions() {
		return numFunctions;
	}

	public int getNumSymbols() {
		return numSymbols;
	}
}