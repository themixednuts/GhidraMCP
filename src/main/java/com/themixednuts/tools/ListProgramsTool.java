package com.themixednuts.tools;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.models.ProgramFileInfo;
import com.themixednuts.utils.PaginatedResult;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.google.SchemaBuilder;
import com.themixednuts.utils.jsonschema.google.SchemaBuilder.IObjectSchemaBuilder;
import ghidra.framework.main.AppInfo;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.common.McpTransportContext;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import reactor.core.publisher.Mono;

@GhidraMcpTool(
    name = "List Programs",
    description = "Lists all programs (both open and closed) in the Ghidra project.",
    mcpName = "list_programs",
    title = "List Programs",
    readOnlyHint = true,
    idempotentHint = true,
    mcpDescription =
        """
        <use_case>
        List all program files within the active Ghidra project, including both currently open programs
        and programs that exist in the project but are not currently loaded. Use this to discover
        available programs before performing operations that require a file_name parameter.
        </use_case>

        <return_value_summary>
        Returns an array of ProgramFileInfo objects, where each entry includes the program's name, project path,
        version, open status, and metadata. Programs are sorted with open programs first, then by last modified time.
        </return_value_summary>

        <important_notes>
        - Requires an active project in the current PluginTool context.
        - Only lists files with program content type (executables, libraries, etc.).
        - If no programs exist in the project, returns an empty list without raising an error.
        - Closed programs can be opened by providing their file_name to other tools.
        - Results are paginated (default 100 per page). Use the next_cursor to retrieve subsequent pages.
        - TIP: For large projects with many files, use the 'format' parameter to filter by executable type (PE, ELF, MACH_O, COFF, RAW) or 'name_filter' to search by filename.
        </important_notes>
        """)
public class ListProgramsTool extends BaseMcpTool {

  private static final String CONTEXT_OPERATION = "list_programs";

  // Additional argument constants specific to this tool
  private static final String ARG_PAGE_SIZE = "page_size";
  private static final String ARG_FORMAT = "format";
  private static final String ARG_NAME_FILTER = "name_filter";
  private static final String ARG_OPEN_ONLY = "open_only";

  // Default values
  private static final int DEFAULT_PAGE_SIZE = 100;
  private static final int MAX_PAGE_SIZE = 500;

  /** Supported executable format filters */
  public enum ExecutableFormat {
    ALL("all", "All executable formats"),
    PE("Portable Executable (PE)", "Windows executables and DLLs"),
    ELF("Executable and Linkable Format (ELF)", "Linux/Unix executables and shared libraries"),
    MACH_O("Mac OS X Mach-O", "macOS executables and dylibs"),
    COFF("Common Object File Format (COFF)", "COFF object files"),
    RAW("Raw Binary", "Raw binary files");

    private final String formatName;
    private final String description;

    ExecutableFormat(String formatName, String description) {
      this.formatName = formatName;
      this.description = description;
    }

    public String getFormatName() {
      return formatName;
    }

    public String getDescription() {
      return description;
    }

    /** Check if a program format matches this filter */
    public boolean matches(String programFormat) {
      if (programFormat == null) {
        return this == ALL;
      }

      if (this == ALL) {
        return true;
      }

      // Case-insensitive matching
      String lowerFormat = programFormat.toLowerCase();
      String lowerFilterName = formatName.toLowerCase();

      return lowerFormat.contains(lowerFilterName) || lowerFormat.equals(name().toLowerCase());
    }

    /** Get format from string value */
    public static ExecutableFormat fromString(String value) {
      if (value == null) {
        return ALL;
      }

      for (ExecutableFormat format : values()) {
        if (format.name().equalsIgnoreCase(value)) {
          return format;
        }
      }
      return ALL;
    }
  }

  /**
   * Defines the JSON input schema for listing programs.
   *
   * @return The JsonSchema defining the expected input arguments
   */
  @Override
  public JsonSchema schema() {
    IObjectSchemaBuilder schemaRoot = createBaseSchemaNode();

    // Add optional pagination parameters
    schemaRoot.property(
        ARG_PAGE_SIZE,
        SchemaBuilder.integer(mapper)
            .description(
                "Number of results per page (default: "
                    + DEFAULT_PAGE_SIZE
                    + ", max: "
                    + MAX_PAGE_SIZE
                    + ")")
            .minimum(1)
            .maximum(MAX_PAGE_SIZE));

    schemaRoot.property(
        ARG_CURSOR,
        SchemaBuilder.string(mapper).description("Cursor from previous response for pagination"));

    // Add optional executable format filter
    String[] formatValues =
        java.util.Arrays.stream(ExecutableFormat.values()).map(Enum::name).toArray(String[]::new);

    schemaRoot.property(
        ARG_FORMAT,
        SchemaBuilder.string(mapper)
            .description(
                "Filter by executable format: ALL (default), PE (Windows), ELF (Linux/Unix), MACH_O (macOS), COFF (object files), RAW (raw binary)")
            .enumValues(formatValues));

    // Add optional name filter
    schemaRoot.property(
        ARG_NAME_FILTER,
        SchemaBuilder.string(mapper)
            .description("Filter programs by name (case-insensitive substring match)"));

    // Add optional open status filter
    schemaRoot.property(
        ARG_OPEN_ONLY,
        SchemaBuilder.bool(mapper)
            .description(
                "Filter to show only currently open programs (default: false, shows all programs)"));

    return schemaRoot.build();
  }

  /**
   * Executes the program listing operation.
   *
   * @param context The MCP transport context
   * @param args The tool arguments (no arguments required for this tool)
   * @param tool The Ghidra PluginTool context
   * @return A Mono emitting a list of ProgramFileInfo objects
   */
  @Override
  public Mono<? extends Object> execute(
      McpTransportContext context, Map<String, Object> args, PluginTool tool) {
    return Mono.fromCallable(() -> listPrograms(tool, args)).onErrorMap(this::wrapExecutionError);
  }

  /**
   * Lists all programs in the current project with pagination and filtering.
   *
   * @param tool The Ghidra PluginTool context
   * @param args Arguments including pagination and filter parameters
   * @return A PaginatedResult containing ProgramFileInfo objects
   * @throws GhidraMcpException If there's an error accessing the project or programs
   */
  private PaginatedResult<ProgramFileInfo> listPrograms(PluginTool tool, Map<String, Object> args)
      throws GhidraMcpException {
    // Extract parameters
    int pageSize = getOptionalIntArgument(args, ARG_PAGE_SIZE).orElse(DEFAULT_PAGE_SIZE);
    String cursor = getOptionalStringArgument(args, ARG_CURSOR).orElse(null);
    ExecutableFormat formatFilter =
        ExecutableFormat.fromString(getOptionalStringArgument(args, ARG_FORMAT).orElse(null));
    String nameFilter = getOptionalStringArgument(args, ARG_NAME_FILTER).orElse(null);
    boolean openOnly = getOptionalBooleanArgument(args, ARG_OPEN_ONLY).orElse(false);
    // Get the active project from the Application level (not from PluginTool)
    Project project = AppInfo.getActiveProject();

    if (project == null) {
      throw new GhidraMcpException(
          GhidraMcpError.execution()
              .errorCode(GhidraMcpError.ErrorCode.UNEXPECTED_ERROR)
              .message("No active project found in the application")
              .context(
                  new GhidraMcpError.ErrorContext(
                      this.getMcpName(),
                      CONTEXT_OPERATION,
                      Map.of(),
                      Map.of(),
                      Map.of("project_available", false)))
              .suggestions(
                  List.of(
                      new GhidraMcpError.ErrorSuggestion(
                          GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
                          "Open or activate a Ghidra project",
                          "Ensure a project is open in Ghidra before listing programs",
                          null,
                          null)))
              .build());
    }

    // Get all domain files from the project (recursively)
    List<DomainFile> allFiles = new ArrayList<>();
    DomainFolder rootFolder = project.getProjectData().getRootFolder();
    ghidra.util.Msg.info(this, "Scanning project root folder: " + rootFolder.getPathname());
    collectDomainFiles(rootFolder, allFiles);
    ghidra.util.Msg.info(this, "Found " + allFiles.size() + " total domain files");

    // Filter for program files and sort: open programs first, then by last modified
    // (newest first)
    List<DomainFile> programFiles =
        allFiles.stream()
            .filter(
                file -> {
                  String contentType = file.getContentType();
                  // Check if content type contains "Program" or equals the class name
                  boolean isProgram =
                      contentType.equals("Program")
                          || contentType.equals(Program.class.getName())
                          || contentType.contains("Program");
                  return isProgram;
                })
            .filter(file -> matchesNameFilter(file.getName(), nameFilter))
            .filter(file -> !openOnly || file.isOpen())
            .sorted(
                Comparator
                    // First: open programs come before closed programs
                    .comparing(DomainFile::isOpen, Comparator.reverseOrder())
                    // Then: sort by last modified time (newest first), null-safe (nulls last)
                    .thenComparing(
                        DomainFile::getLastModifiedTime,
                        Comparator.nullsLast(Comparator.reverseOrder()))
                    // Finally: break ties with case-insensitive name
                    .thenComparing(DomainFile::getName, String.CASE_INSENSITIVE_ORDER))
            .collect(Collectors.toList());

    ghidra.util.Msg.info(this, "Found " + programFiles.size() + " programs after filtering");

    // Apply pagination with format filter integration
    // Find start index from cursor (using pathname for stable cursor lookup)
    int startIndex = 0;
    if (cursor != null && !cursor.isEmpty()) {
      // Cursor is now just the pathname for stability
      for (int i = 0; i < programFiles.size(); i++) {
        if (programFiles.get(i).getPathname().equals(cursor)) {
          startIndex = i + 1;
          break;
        }
      }
    }

    // Iterate through files, applying format filter while collecting results
    // This ensures we return exactly pageSize results (if available) even with filtering
    List<ProgramFileInfo> programs = new ArrayList<>();
    int currentIndex = startIndex;
    DomainFile lastProcessedFile = null;

    while (programs.size() < pageSize && currentIndex < programFiles.size()) {
      DomainFile file = programFiles.get(currentIndex);
      ProgramFileInfo info = createProgramFileInfo(project, file);

      // Apply format filter during iteration, not after pagination
      if (formatFilter.matches(info.getFormat())) {
        programs.add(info);
        lastProcessedFile = file;
      }
      currentIndex++;
    }

    // Create next cursor if there are more files to process
    String nextCursor = null;
    if (currentIndex < programFiles.size() && lastProcessedFile != null) {
      nextCursor = createCursor(lastProcessedFile);
    }

    ghidra.util.Msg.info(this, "Returning page with " + programs.size() + " programs");

    return new PaginatedResult<>(programs, nextCursor);
  }

  /**
   * Creates a pagination cursor using the file's pathname. Using pathname alone ensures cursor
   * stability - the old format including isOpen status would become invalid if a program was
   * opened/closed between requests.
   */
  private String createCursor(DomainFile file) {
    return file.getPathname();
  }

  /** Check if a filename matches the name filter. */
  private boolean matchesNameFilter(String filename, String nameFilter) {
    if (nameFilter == null || nameFilter.isEmpty()) {
      return true;
    }
    return filename.toLowerCase().contains(nameFilter.toLowerCase());
  }

  /** Recursively collect all domain files from a folder and its subfolders. */
  private void collectDomainFiles(DomainFolder folder, List<DomainFile> files) {
    // Add files in current folder
    files.addAll(List.of(folder.getFiles()));

    // Recursively process subfolders
    for (DomainFolder subfolder : folder.getFolders()) {
      collectDomainFiles(subfolder, files);
    }
  }

  /** Create a ProgramFileInfo object from a DomainFile. */
  private ProgramFileInfo createProgramFileInfo(Project project, DomainFile file) {
    // Check if program is currently open
    boolean isOpen = isProgramOpen(file);

    // Initialize basic info
    String arch = null;
    String base = null;
    Long size = null;
    String format = null;

    // Try to get metadata - works better if program is open
    try {
      // Get immutable domain object without requesting upgrade or recovery
      Object obj = file.getImmutableDomainObject(this, DomainFile.DEFAULT_VERSION, null);
      if (obj instanceof Program) {
        Program program = (Program) obj;
        arch = program.getLanguage().getProcessor().toString();
        base = program.getImageBase().toString();
        size = program.getMemory().getSize();
        format = program.getExecutableFormat();
        program.release(this);
      }
    } catch (Exception e) {
      // Log but don't fail - just skip additional metadata
      ghidra.util.Msg.debug(
          this, "Could not get program metadata for " + file.getName() + ": " + e.getMessage());
    }

    return new ProgramFileInfo(
        file.getName(),
        file.getPathname(),
        file.getVersion(),
        isOpen,
        file.isChanged(),
        file.isReadOnly(),
        arch,
        base,
        size,
        format);
  }

  /** Check if a program is currently open. */
  private boolean isProgramOpen(DomainFile file) {
    // Check if the file is currently in use by any consumer
    return file.isOpen();
  }

  private Throwable wrapExecutionError(Throwable throwable) {
    if (throwable instanceof GhidraMcpException) {
      return throwable;
    }

    GhidraMcpError error =
        GhidraMcpError.execution()
            .errorCode(GhidraMcpError.ErrorCode.UNEXPECTED_ERROR)
            .message("Failed to list programs: " + throwable.getMessage())
            .context(
                new GhidraMcpError.ErrorContext(
                    this.getMcpName(),
                    CONTEXT_OPERATION,
                    Map.of(),
                    Map.of("exception_type", throwable.getClass().getSimpleName()),
                    Map.of()))
            .suggestions(
                List.of(
                    new GhidraMcpError.ErrorSuggestion(
                        GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
                        "Verify project state",
                        "Ensure the Ghidra project is accessible and contains program files",
                        null,
                        null)))
            .build();
    return new GhidraMcpException(error);
  }
}
