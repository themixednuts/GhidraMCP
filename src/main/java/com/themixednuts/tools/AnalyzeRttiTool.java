package com.themixednuts.tools;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.models.RTTIAnalysisResult;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;
import ghidra.app.util.demangler.DemanglerUtil;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBufferImpl;
import ghidra.program.model.data.DataTypeManager;
import ghidra.app.util.datatype.microsoft.RTTI0DataType;
import io.modelcontextprotocol.common.McpTransportContext;
import reactor.core.publisher.Mono;

import java.util.Map;
import java.util.Optional;

/**
 * Analyze RTTI information at a specified program address.
 * This tool only performs read/analysis operations and does not create/update data types.
 */
@GhidraMcpTool(
    name = "Analyze RTTI",
    description = "Analyze Microsoft RTTI at a given address and return parsed metadata.",
    mcpName = "analyze_rtti",
    mcpDescription = """
        <use_case>
        Analyze Microsoft RTTI structures at a specific address in the current program.
        Returns details such as RTTI validity, vtable address, spare data address, mangled and demangled names.
        </use_case>

        <parameters_summary>
        - fileName: The program file to analyze (required)
        - address: Address string (e.g., 0x401000) to probe for RTTI
        </parameters_summary>

        <return_value_summary>
        Returns an RTTIAnalysisResult object with parsed fields and diagnostic notes.
        </return_value_summary>
    """
)
public class AnalyzeRttiTool implements IGhidraMcpSpecification {

    @Override
    public JsonSchema schema() {
        IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();

        schemaRoot.property(ARG_FILE_NAME,
            JsonSchemaBuilder.string(mapper)
                .description("The name of the Ghidra program file to analyze"), true);

        schemaRoot.property(ARG_ADDRESS,
            JsonSchemaBuilder.string(mapper)
                .description("Address (e.g., 0x401000) where RTTI is expected"), true);

        return schemaRoot.build();
    }

    @Override
    public Mono<? extends Object> execute(McpTransportContext context, Map<String, Object> args, PluginTool tool) {
        return getProgram(args, tool)
            .flatMap(program -> Mono.fromCallable(() -> {
                String addressStr = getRequiredStringArgument(args, ARG_ADDRESS);
                return analyzeRTTIAtAddress(program, addressStr);
            }));
    }

    private RTTIAnalysisResult analyzeRTTIAtAddress(Program program, String addressStr) throws GhidraMcpException {
        try {
            Address address = program.getAddressFactory().getAddress(addressStr);
            if (address == null) {
                throw new GhidraMcpException(GhidraMcpError.validation()
                    .errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
                    .message("Invalid address: " + addressStr)
                    .build());
            }

            Memory memory = program.getMemory();
            DataTypeManager dtm = program.getDataTypeManager();

            RTTI0DataType rtti0 = new RTTI0DataType(dtm);
            boolean isValid = rtti0.isValid(program, address, null);

            if (!isValid) {
                return new RTTIAnalysisResult(
                    "RTTI0DataType",
                    addressStr,
                    Optional.empty(),
                    Optional.empty(),
                    Optional.empty(),
                    Optional.empty(),
                    false,
                    Optional.of("No valid RTTI0 structure found at address"),
                    false,
                    Optional.of("Address does not contain valid RTTI0 structure"),
                    0,
                    rtti0.getDescription(),
                    rtti0.getMnemonic(null),
                    rtti0.getDefaultLabelPrefix(),
                    Map.of("attemptedType", "RTTI0DataType")
                );
            }

            Optional<String> vtableAddress = Optional.empty();
            Optional<String> spareDataAddress = Optional.empty();
            Optional<String> mangledName = Optional.empty();
            Optional<String> demangledName = Optional.empty();
            boolean demanglingSuccessful = false;
            Optional<String> demanglingError = Optional.empty();
            int length = 0;

            try {
                length = rtti0.getLength(memory, address);

                vtableAddress = Optional.ofNullable(rtti0.getVFTableAddress(memory, address))
                    .map(Address::toString);

                spareDataAddress = Optional.ofNullable(rtti0.getSpareDataAddress(memory, address))
                    .map(Address::toString);

                try {
                    MemBuffer memBuffer = new MemoryBufferImpl(memory, address);
                    String name = rtti0.getVFTableName(memBuffer);
                    mangledName = Optional.ofNullable(name);
                } catch (Exception e) {
                    mangledName = Optional.empty();
                }

                if (mangledName.isPresent()) {
                    try {
                        var demangledList = DemanglerUtil.demangle(program, mangledName.get(), null);
                        demangledName = Optional.ofNullable(demangledList)
                            .filter(list -> !list.isEmpty())
                            .map(list -> list.get(0).toString());
                        demanglingSuccessful = demangledName.isPresent();
                        if (!demanglingSuccessful) {
                            demanglingError = Optional.of("No demangler could process this symbol");
                        }
                    } catch (Exception e) {
                        demanglingError = Optional.of("Demangling failed: " + e.getMessage());
                    }
                } else {
                    demanglingError = Optional.of("No mangled name found in RTTI structure");
                }
            } catch (Exception e) {
                demanglingError = Optional.of("Failed to extract RTTI information: " + e.getMessage());
            }

            Map<String, Object> additionalInfo = Map.of(
                "rttiTypeName", "RTTI0DataType",
                "length", length,
                "hasVtable", vtableAddress.isPresent(),
                "hasSpareData", spareDataAddress.isPresent()
            );

            return new RTTIAnalysisResult(
                "RTTI0DataType",
                addressStr,
                vtableAddress,
                spareDataAddress,
                mangledName,
                demangledName,
                demanglingSuccessful,
                demanglingError,
                isValid,
                Optional.empty(),
                length,
                rtti0.getDescription(),
                rtti0.getMnemonic(null),
                rtti0.getDefaultLabelPrefix(),
                additionalInfo
            );

        } catch (GhidraMcpException e) {
            throw e;
        } catch (Exception e) {
            throw new GhidraMcpException(GhidraMcpError.execution()
                .errorCode(GhidraMcpError.ErrorCode.UNEXPECTED_ERROR)
                .message("Failed to analyze RTTI at address: " + e.getMessage())
                .build());
        }
    }
}


