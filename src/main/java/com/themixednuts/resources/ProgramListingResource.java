package com.themixednuts.resources;

import com.themixednuts.annotation.GhidraMcpResource;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.common.McpTransportContext;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import reactor.core.publisher.Mono;

/** MCP resource template that provides assembly listing at/around an address. */
@GhidraMcpResource(
    uri = "ghidra://program/{name}/listing/{address}",
    name = "Program Listing",
    description =
        "Assembly listing at/around a specific address. Returns up to 50 instructions with"
            + " mnemonics, operands, and labels.",
    mimeType = "application/json",
    template = true)
public class ProgramListingResource extends BaseMcpResource {

  private static final int MAX_INSTRUCTIONS = 50;

  @Override
  public Mono<String> read(McpTransportContext context, String uri, PluginTool tool) {
    return Mono.fromCallable(
        () -> {
          Map<String, String> params = extractUriParams(uri);
          String programName = params.get("name");
          String addressStr = params.get("address");

          if (programName == null || programName.isEmpty()) {
            throw new IllegalArgumentException("Program name is required");
          }
          if (addressStr == null || addressStr.isEmpty()) {
            throw new IllegalArgumentException("Address is required");
          }

          Program program = getProgramByName(programName);
          try {
            Address address = program.getAddressFactory().getAddress(addressStr);
            if (address == null) {
              throw new IllegalArgumentException("Invalid address: " + addressStr);
            }

            Listing listing = program.getListing();
            List<Map<String, Object>> instructions = new ArrayList<>();

            CodeUnit codeUnit = listing.getCodeUnitAt(address);
            if (codeUnit == null) {
              codeUnit = listing.getCodeUnitAfter(address);
            }

            int count = 0;
            while (codeUnit != null && count < MAX_INSTRUCTIONS) {
              Map<String, Object> entry = new LinkedHashMap<>();
              entry.put("address", codeUnit.getAddress().toString());

              if (codeUnit instanceof Instruction instr) {
                entry.put("type", "instruction");
                entry.put("mnemonic", instr.getMnemonicString());
                StringBuilder operands = new StringBuilder();
                for (int i = 0; i < instr.getNumOperands(); i++) {
                  if (i > 0) operands.append(", ");
                  operands.append(instr.getDefaultOperandRepresentation(i));
                }
                entry.put("operands", operands.toString());
                entry.put("bytes", bytesToHex(instr.getBytes()));
              } else {
                entry.put("type", "data");
                entry.put("dataType", codeUnit.getClass().getSimpleName());
                entry.put("value", codeUnit.toString());
              }

              String label = codeUnit.getLabel();
              if (label != null) {
                entry.put("label", label);
              }

              instructions.add(entry);
              count++;
              codeUnit = listing.getCodeUnitAfter(codeUnit.getAddress());
            }

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("programName", programName);
            result.put("startAddress", addressStr);
            result.put("instructions", instructions);
            result.put("count", instructions.size());

            return toJson(result);
          } finally {
            program.release(this);
          }
        });
  }

  private String bytesToHex(byte[] bytes) {
    StringBuilder sb = new StringBuilder();
    for (byte b : bytes) {
      sb.append(String.format("%02x", b));
    }
    return sb.toString();
  }
}
