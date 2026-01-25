package com.themixednuts.tools;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.models.RTTIAnalysisResult;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.google.SchemaBuilder;
import com.themixednuts.utils.jsonschema.google.SchemaBuilder.IObjectSchemaBuilder;
import ghidra.app.cmd.data.rtti.Rtti1Model;
import ghidra.app.cmd.data.rtti.Rtti2Model;
import ghidra.app.cmd.data.rtti.Rtti3Model;
import ghidra.app.cmd.data.rtti.Rtti4Model;
import ghidra.app.cmd.data.rtti.VfTableModel;
import ghidra.app.util.datatype.microsoft.DataValidationOptions;
import ghidra.app.util.datatype.microsoft.RTTI0DataType;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.common.McpTransportContext;
import java.util.Map;
import reactor.core.publisher.Mono;

@GhidraMcpTool(
    name = "Analyze RTTI",
    description = "Analyze Microsoft RTTI at a given address and return parsed metadata.",
    mcpName = "analyze_rtti",
    mcpDescription =
        """
            <use_case>
            Comprehensive analysis of Microsoft RTTI structures at a specific address in the current program.
            Automatically detects and analyzes RTTI0, RTTI1, RTTI2, RTTI3, RTTI4, and VTable structures.
            Returns detailed information about RTTI validity, relationships, vtable addresses,
            spare data addresses, mangled and demangled names, and class hierarchy information.
            </use_case>

            <parameters_summary>
            - fileName: The program file to analyze (required)
            - address: Address string (e.g., 0x401000) to probe for RTTI structures
            </parameters_summary>

            <return_value_summary>
            Returns an RTTIAnalysisResult object with comprehensive RTTI analysis including:
            - Detected RTTI type (RTTI0, RTTI1, RTTI2, RTTI3, RTTI4, or VTable)
            - Validity status and validation details
            - VTable and spare data addresses
            - Mangled and demangled class names
            - Class hierarchy information (for RTTI3)
            - Base class information (for RTTI2)
            - Complete object locator details (for RTTI4)
            </return_value_summary>

            <important_notes>
            - This tool performs comprehensive RTTI analysis using all available RTTI model classes
            - Automatically detects the appropriate RTTI type at the given address
            - Provides detailed relationship information between RTTI structures
            - Uses advanced Microsoft-specific RTTI analysis capabilities
            </important_notes>
        """)
public class AnalyzeRttiTool extends BaseMcpTool {

  @Override
  public JsonSchema schema() {
    IObjectSchemaBuilder schemaRoot = createBaseSchemaNode();

    schemaRoot.property(
        ARG_FILE_NAME,
        SchemaBuilder.string(mapper).description("The name of the Ghidra program file to analyze"));

    schemaRoot.property(
        ARG_ADDRESS,
        SchemaBuilder.string(mapper)
            .description("Address (e.g., 0x401000) where RTTI is expected"));

    schemaRoot.requiredProperty(ARG_FILE_NAME);
    schemaRoot.requiredProperty(ARG_ADDRESS);

    return schemaRoot.build();
  }

  @Override
  public Mono<? extends Object> execute(
      McpTransportContext context, Map<String, Object> args, PluginTool tool) {
    return getProgram(args, tool)
        .flatMap(
            program ->
                Mono.fromCallable(
                    () -> {
                      String addressStr = getRequiredStringArgument(args, ARG_ADDRESS);
                      return analyzeRTTIAtAddress(program, addressStr);
                    }));
  }

  private RTTIAnalysisResult analyzeRTTIAtAddress(Program program, String addressStr)
      throws GhidraMcpException {
    try {
      Address address = program.getAddressFactory().getAddress(addressStr);
      if (address == null) {
        throw new GhidraMcpException(
            GhidraMcpError.validation()
                .errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
                .message("Invalid address: " + addressStr)
                .build());
      }

      DataValidationOptions validationOptions = new DataValidationOptions();
      validationOptions.setValidateReferredToData(false);

      // Try to detect and analyze different RTTI types in priority order
      RTTIAnalysisResult result =
          tryAnalyze(
              () -> {
                Rtti4Model model = new Rtti4Model(program, address, validationOptions);
                model.validate();
                return RTTIAnalysisResult.from(model, address);
              });
      if (result.isValid()) return result;

      result =
          tryAnalyze(
              () -> {
                Rtti3Model model = new Rtti3Model(program, address, validationOptions);
                model.validate();
                return RTTIAnalysisResult.from(model, address);
              });
      if (result.isValid()) return result;

      result =
          tryAnalyze(
              () -> {
                Rtti2Model model = new Rtti2Model(program, 0, address, validationOptions);
                model.validate();
                return RTTIAnalysisResult.from(model, address);
              });
      if (result.isValid()) return result;

      result =
          tryAnalyze(
              () -> {
                Rtti1Model model = new Rtti1Model(program, address, validationOptions);
                model.validate();
                return RTTIAnalysisResult.from(model, address);
              });
      if (result.isValid()) return result;

      result =
          tryAnalyze(
              () -> {
                DataTypeManager dtm = program.getDataTypeManager();
                RTTI0DataType rtti0 = new RTTI0DataType(dtm);
                if (!rtti0.isValid(program, address, validationOptions)) {
                  throw new Exception("Invalid RTTI0");
                }
                return RTTIAnalysisResult.from(rtti0, program, address);
              });
      if (result.isValid()) return result;

      // Last resort: try VfTable analysis
      return tryAnalyze(
          () -> {
            VfTableModel model = new VfTableModel(program, address, validationOptions);
            model.validate();
            return RTTIAnalysisResult.from(model, address);
          });

    } catch (GhidraMcpException e) {
      throw e;
    } catch (Exception e) {
      throw new GhidraMcpException(
          GhidraMcpError.execution()
              .errorCode(GhidraMcpError.ErrorCode.UNEXPECTED_ERROR)
              .message("Failed to analyze RTTI at address: " + e.getMessage())
              .build());
    }
  }

  private RTTIAnalysisResult tryAnalyze(RttiAnalyzer analyzer) {
    try {
      return analyzer.analyze();
    } catch (Exception e) {
      return RTTIAnalysisResult.invalid(RTTIAnalysisResult.RttiType.UNKNOWN, "", e.getMessage());
    }
  }

  @FunctionalInterface
  private interface RttiAnalyzer {
    RTTIAnalysisResult analyze() throws Exception;
  }
}
