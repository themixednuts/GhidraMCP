package com.themixednuts.resources;

import com.themixednuts.annotation.GhidraMcpResource;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.framework.plugintool.PluginTool;
import io.modelcontextprotocol.common.McpTransportContext;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import reactor.core.publisher.Mono;

/** MCP resource that lists all programs in the current Ghidra project. */
@GhidraMcpResource(
    uri = "ghidra://programs",
    name = "Program List",
    description = "Lists all programs available in the current Ghidra project",
    mimeType = "application/json",
    template = false)
public class ProgramListResource extends BaseMcpResource {

  @Override
  public Mono<String> read(McpTransportContext context, String uri, PluginTool tool) {
    return Mono.fromCallable(
        () -> {
          Project project = getActiveProject();
          List<Map<String, Object>> programs = new ArrayList<>();

          // Collect all programs recursively
          collectProgramsRecursive(project.getProjectData().getRootFolder(), "", programs);

          // Also include open programs
          List<String> openPrograms = new ArrayList<>();
          for (DomainFile file : project.getOpenData()) {
            openPrograms.add(file.getName());
          }

          Map<String, Object> result =
              Map.of(
                  "projectName",
                  project.getName(),
                  "programs",
                  programs,
                  "openPrograms",
                  openPrograms,
                  "totalCount",
                  programs.size());

          return toJson(result);
        });
  }

  private void collectProgramsRecursive(
      DomainFolder folder, String path, List<Map<String, Object>> programs) {
    for (DomainFile file : folder.getFiles()) {
      Map<String, Object> programInfo = new HashMap<>();
      programInfo.put("name", file.getName());
      programInfo.put("path", path.isEmpty() ? "/" + file.getName() : path + "/" + file.getName());
      programInfo.put("contentType", file.getContentType());
      programInfo.put("isReadOnly", file.isReadOnly());
      programInfo.put("isVersioned", file.isVersioned());
      programInfo.put("version", file.getVersion());
      programs.add(programInfo);
    }

    for (DomainFolder subfolder : folder.getFolders()) {
      String subPath =
          path.isEmpty() ? "/" + subfolder.getName() : path + "/" + subfolder.getName();
      collectProgramsRecursive(subfolder, subPath, programs);
    }
  }
}
