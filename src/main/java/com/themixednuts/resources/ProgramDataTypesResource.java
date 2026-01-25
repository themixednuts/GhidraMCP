package com.themixednuts.resources;

import com.themixednuts.annotation.GhidraMcpResource;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.Category;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.Union;
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.common.McpTransportContext;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import reactor.core.publisher.Mono;

/** MCP resource template that lists data types in a specific program. */
@GhidraMcpResource(
    uri = "ghidra://program/{name}/datatypes",
    name = "Program Data Types",
    description = "Lists all data types (structs, enums, typedefs) in a specific program.",
    mimeType = "application/json",
    template = true)
public class ProgramDataTypesResource extends BaseMcpResource {

  private static final int MAX_DATA_TYPES = 1000;
  private static final int MAX_CATEGORY_DEPTH = 2;

  @Override
  public Mono<String> read(McpTransportContext context, String uri, PluginTool tool) {
    return Mono.fromCallable(
        () -> {
          Map<String, String> params = extractUriParams(uri);
          String programName = params.get("name");

          if (programName == null || programName.isEmpty()) {
            throw new IllegalArgumentException("Program name is required");
          }

          Program program = getProgramByName(programName);
          try {
            DataTypeManager dtm = program.getDataTypeManager();
            List<Map<String, Object>> dataTypes = new ArrayList<>();

            Iterator<DataType> dtIter = dtm.getAllDataTypes();
            int count = 0;

            while (dtIter.hasNext() && count < MAX_DATA_TYPES) {
              DataType dt = dtIter.next();

              // Skip built-in types
              if (dt.getDataTypeManager() != dtm) {
                continue;
              }

              Map<String, Object> dtInfo = new HashMap<>();
              dtInfo.put("name", dt.getName());
              dtInfo.put("displayName", dt.getDisplayName());
              dtInfo.put("pathName", dt.getPathName());
              dtInfo.put("categoryPath", dt.getCategoryPath().getPath());
              dtInfo.put("length", dt.getLength());
              dtInfo.put("description", dt.getDescription());
              dtInfo.put("typeClass", getDataTypeClass(dt));

              if (dt.getUniversalID() != null) {
                dtInfo.put("universalId", dt.getUniversalID().toString());
              }

              dataTypes.add(dtInfo);
              count++;
            }

            // Get category summary
            List<Map<String, Object>> categories = new ArrayList<>();
            collectCategories(dtm.getRootCategory(), categories, 0, MAX_CATEGORY_DEPTH);

            Map<String, Object> result =
                Map.of(
                    "programName",
                    programName,
                    "dataTypes",
                    dataTypes,
                    "categories",
                    categories,
                    "count",
                    dataTypes.size(),
                    "hasMore",
                    dtIter.hasNext(),
                    "totalDataTypeCount",
                    dtm.getDataTypeCount(true));

            return toJson(result);
          } finally {
            program.release(this);
          }
        });
  }

  private String getDataTypeClass(DataType dt) {
    if (dt instanceof Structure) {
      return "Structure";
    } else if (dt instanceof Union) {
      return "Union";
    } else if (dt instanceof ghidra.program.model.data.Enum) {
      return "Enum";
    } else if (dt instanceof TypeDef) {
      return "TypeDef";
    } else if (dt instanceof FunctionDefinition) {
      return "FunctionDefinition";
    } else if (dt instanceof Pointer) {
      return "Pointer";
    } else if (dt instanceof Array) {
      return "Array";
    } else {
      return "Other";
    }
  }

  private void collectCategories(
      Category category, List<Map<String, Object>> categories, int depth, int maxDepth) {
    if (depth > maxDepth) {
      return;
    }

    Map<String, Object> catInfo =
        Map.of(
            "name",
            category.getName(),
            "path",
            category.getCategoryPath().getPath(),
            "dataTypeCount",
            category.getDataTypes().length,
            "subcategoryCount",
            category.getCategories().length);
    categories.add(new HashMap<>(catInfo));

    for (Category subcat : category.getCategories()) {
      collectCategories(subcat, categories, depth + 1, maxDepth);
    }
  }
}
