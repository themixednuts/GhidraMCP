package com.themixednuts.tools;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.models.ListingInfo;
import com.themixednuts.utils.PaginatedResult;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.google.SchemaBuilder;
import com.themixednuts.utils.jsonschema.google.SchemaBuilder.IObjectSchemaBuilder;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import io.modelcontextprotocol.common.McpTransportContext;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@GhidraMcpTool(name = "Read Listing", description = "View disassembly and data from Ghidra program listing.", mcpName = "read_listing", mcpDescription = """
        <use_case>
        View assembly instructions (disassembly) and data from a Ghidra program's listing. Supports viewing
        code by address, address range, or function. Returns paginated results with instruction details
        including mnemonics, operands, labels, and comments.
        </use_case>

        <important_notes>
        - Supports three viewing modes: single address, address range, or function
        - Results are paginated for large address ranges or functions
        - Returns detailed instruction information including assembly text
        - Includes function context when instructions are part of functions
        - Provides labels, comments, and operand details
        </important_notes>

        <examples>
        View listing at single address:
        {
          "file_name": "program.exe",
          "address": "0x401000"
        }

        View listing in address range:
        {
          "file_name": "program.exe",
          "address": "0x401000",
          "end_address": "0x402000"
        }

        View listing for a function:
        {
          "file_name": "program.exe",
          "function": "main"
        }

        Get next page of results:
        {
          "file_name": "program.exe",
          "address": "0x401000",
          "end_address": "0x402000",
          "cursor": "0x401050"
        }
        </examples>
        """)
public class ReadListingTool extends BaseMcpTool {

    public static final String ARG_END_ADDRESS = "end_address";
    public static final String ARG_FUNCTION = "function";
    public static final String ARG_MAX_LINES = "max_lines";

    @Override
    public JsonSchema schema() {
        IObjectSchemaBuilder schemaRoot = createBaseSchemaNode();

        schemaRoot.property(ARG_FILE_NAME,
                SchemaBuilder.string(mapper)
                        .description("The name of the program file."));

        schemaRoot.property(ARG_ADDRESS,
                SchemaBuilder.string(mapper)
                        .description("Start address to view listing for (required for address-based viewing)")
                        .pattern("^(0x)?[0-9a-fA-F]+$"));

        schemaRoot.property(ARG_END_ADDRESS,
                SchemaBuilder.string(mapper)
                        .description("Optional end address. If provided, view listing in address range")
                        .pattern("^(0x)?[0-9a-fA-F]+$"));

        schemaRoot.property(ARG_FUNCTION,
                SchemaBuilder.string(mapper)
                        .description("Function name to view listing for"));

        schemaRoot.property(ARG_MAX_LINES,
                SchemaBuilder.integer(mapper)
                        .description("Maximum number of lines to return (default: 100)")
                        .minimum(1)
                        .maximum(1000)
                        .defaultValue(DEFAULT_PAGE_LIMIT));

        schemaRoot.property(ARG_CURSOR,
                SchemaBuilder.string(mapper)
                        .description("Pagination cursor from previous request"));

        schemaRoot.requiredProperty(ARG_FILE_NAME);

        return schemaRoot.build();
    }

    @Override
    public Mono<? extends Object> execute(McpTransportContext context, Map<String, Object> args, PluginTool tool) {
        GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);

        return getProgram(args, tool).flatMap(program -> {
            // Determine which viewing mode
            if (args.containsKey(ARG_ADDRESS)) {
                if (args.containsKey(ARG_END_ADDRESS)) {
                    return handleAddressRange(program, args, annotation);
                } else {
                    return handleSingleAddress(program, args, annotation);
                }
            } else if (args.containsKey(ARG_FUNCTION)) {
                return handleFunction(program, args, annotation);
            } else {
                // Default: show first page from start of program
                return handleDefaultStart(program, args, annotation);
            }
        });
    }

    private Mono<? extends Object> handleSingleAddress(Program program, Map<String, Object> args,
            GhidraMcpTool annotation) {
        String addressStr;
        try {
            addressStr = getRequiredStringArgument(args, ARG_ADDRESS);
        } catch (GhidraMcpException e) {
            return Mono.error(e);
        }
        return parseAddress(program, addressStr, "read_listing_single")
                .flatMap(addressResult -> Mono.fromCallable(() -> {
                    Address address = addressResult.getAddress();
                    Listing listing = program.getListing();
                    CodeUnit codeUnit = listing.getCodeUnitAt(address);

                    if (codeUnit == null) {
                        throw new GhidraMcpException(GhidraMcpError.resourceNotFound()
                                .errorCode(GhidraMcpError.ErrorCode.ADDRESS_NOT_FOUND)
                                .message("No code found at address: " + address)
                                .context(new GhidraMcpError.ErrorContext(
                                        annotation.mcpName(),
                                        "listing lookup",
                                        args,
                                        Map.of(ARG_ADDRESS, address.toString()),
                                        Map.of()))
                                .suggestions(List.of(
                                        new GhidraMcpError.ErrorSuggestion(
                                                GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
                                                "Try a different address",
                                                "Use read_memory_blocks to find valid addresses",
                                                null,
                                                List.of("read_memory_blocks"))))
                                .build());
                    }

                    return createListingInfo(program, codeUnit);
                }));
    }

    private Mono<? extends Object> handleFunction(Program program, Map<String, Object> args,
            GhidraMcpTool annotation) {
        return Mono.fromCallable(() -> {
            String functionName = getRequiredStringArgument(args, ARG_FUNCTION);
            FunctionManager functionManager = program.getFunctionManager();

            Function function = null;
            for (Function f : functionManager.getFunctions(true)) {
                if (f.getName().equals(functionName)) {
                    function = f;
                    break;
                }
            }

            if (function == null) {
                List<String> availableFunctions = new ArrayList<>();
                for (Function func : functionManager.getFunctions(true)) {
                    availableFunctions.add(func.getName());
                    if (availableFunctions.size() >= 20)
                        break;
                }
                availableFunctions.sort(java.util.Comparator.naturalOrder());

                throw new GhidraMcpException(GhidraMcpError.resourceNotFound()
                        .errorCode(GhidraMcpError.ErrorCode.FUNCTION_NOT_FOUND)
                        .message("Function not found: " + functionName)
                        .context(new GhidraMcpError.ErrorContext(
                                annotation.mcpName(),
                                "function lookup",
                                args,
                                Map.of(ARG_FUNCTION, functionName),
                                Map.of("availableFunctions", availableFunctions.size())))
                        .relatedResources(availableFunctions)
                        .build());
            }

            return listListingInRange(program, function.getEntryPoint(), function.getBody().getMaxAddress(),
                    args, annotation);
        });
    }

    private Mono<? extends Object> handleAddressRange(Program program, Map<String, Object> args,
            GhidraMcpTool annotation) {
        String startStr;
        String endStr;
        try {
            startStr = getRequiredStringArgument(args, ARG_ADDRESS);
            endStr = getRequiredStringArgument(args, ARG_END_ADDRESS);
        } catch (GhidraMcpException e) {
            return Mono.error(e);
        }

        Mono<AddressResult> startMono = parseAddress(program, startStr, "read_listing_range_start");
        Mono<AddressResult> endMono = parseAddress(program, endStr, "read_listing_range_end");

        return startMono.flatMap(startResult -> endMono.flatMap(endResult -> {
            Address startAddr = startResult.getAddress();
            Address endAddr = endResult.getAddress();

            if (startAddr.compareTo(endAddr) > 0) {
                return Mono.error(new GhidraMcpException(GhidraMcpError.validation()
                        .errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
                        .message("Start address is after end address")
                        .context(new GhidraMcpError.ErrorContext(
                                annotation.mcpName(),
                                "range validation",
                                args,
                                Map.of(ARG_ADDRESS, startStr, ARG_END_ADDRESS, endStr),
                                Map.of()))
                        .suggestions(List.of(
                                new GhidraMcpError.ErrorSuggestion(
                                        GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
                                        "Swap addresses if needed",
                                        "Ensure address <= end_address",
                                        null,
                                        null)))
                        .build()));
            }

            return Mono.fromCallable(
                    () -> listListingInRange(program, startAddr, endAddr, args, annotation));
        }));
    }

    private Mono<? extends Object> handleDefaultStart(Program program, Map<String, Object> args,
            GhidraMcpTool annotation) {
        return Mono.fromCallable(() -> {
            Memory memory = program.getMemory();

            // Find first executable block
            MemoryBlock firstBlock = null;
            for (MemoryBlock block : memory.getBlocks()) {
                if (block.isExecute() && !block.isExternalBlock()) {
                    firstBlock = block;
                    break;
                }
            }

            if (firstBlock == null) {
                throw new GhidraMcpException(GhidraMcpError.resourceNotFound()
                        .errorCode(GhidraMcpError.ErrorCode.ADDRESS_NOT_FOUND)
                        .message("No executable memory found in program")
                        .context(new GhidraMcpError.ErrorContext(
                                annotation.mcpName(),
                                "default listing",
                                args,
                                Map.of(),
                                Map.of()))
                        .build());
            }

            Address startAddr = firstBlock.getStart();
            Address endAddr = firstBlock.getEnd();

            // Limit to reasonable range
            try {
                long size = endAddr.subtract(startAddr);
                if (size > 0x1000) {
                    endAddr = startAddr.add(0x1000);
                }
            } catch (Exception e) {
                // Address math failed, use block end
            }

            return listListingInRange(program, startAddr, endAddr, args, annotation);
        });
    }

    private PaginatedResult<ListingInfo> listListingInRange(Program program, Address startAddr, Address endAddr,
            Map<String, Object> args, GhidraMcpTool annotation)
            throws GhidraMcpException {
        Listing listing = program.getListing();
        Optional<String> cursorOpt = getOptionalStringArgument(args, ARG_CURSOR);
        int maxLines = getOptionalIntArgument(args, ARG_MAX_LINES).orElse(DEFAULT_PAGE_LIMIT);

        // Determine effective start address based on cursor
        Address effectiveStart = startAddr;
        if (cursorOpt.isPresent()) {
            try {
                Address cursorAddr = program.getAddressFactory().getAddress(cursorOpt.get());
                // Start from just after the cursor address (cursor points to last item returned)
                if (cursorAddr != null && cursorAddr.compareTo(startAddr) >= 0
                        && cursorAddr.compareTo(endAddr) <= 0) {
                    effectiveStart = cursorAddr.add(1);
                }
            } catch (Exception e) {
                // Invalid cursor, start from beginning
            }
        }

        List<ListingInfo> results = new ArrayList<>();

        // Get the first code unit at or after the effective start
        CodeUnit codeUnit = listing.getCodeUnitContaining(effectiveStart);
        if (codeUnit == null) {
            codeUnit = listing.getCodeUnitAfter(effectiveStart);
        } else if (codeUnit.getMinAddress().compareTo(effectiveStart) < 0) {
            // Code unit contains effectiveStart but starts before it - get the next one
            codeUnit = listing.getCodeUnitAfter(codeUnit.getMaxAddress());
        }

        // Collect items up to maxLines + 1 to determine if there are more
        while (codeUnit != null
                && codeUnit.getMinAddress().compareTo(endAddr) <= 0
                && results.size() <= maxLines) {
            try {
                results.add(createListingInfo(program, codeUnit));
                codeUnit = listing.getCodeUnitAfter(codeUnit.getMaxAddress());
            } catch (Exception e) {
                break;
            }
        }

        // Determine if there are more results
        boolean hasMore = results.size() > maxLines;
        if (hasMore) {
            results = results.subList(0, maxLines);
        }

        String nextCursor = null;
        if (hasMore && !results.isEmpty()) {
            nextCursor = results.get(results.size() - 1).getAddress();
        }

        return new PaginatedResult<>(results, nextCursor);
    }

    private ListingInfo createListingInfo(Program program, CodeUnit codeUnit) {
        String address = codeUnit.getMinAddress().toString();
        String label = null;
        String instruction = null;
        String mnemonic = null;
        String operands = null;
        String dataRepresentation = null;
        String type;
        Integer length = codeUnit.getLength();
        String functionName = null;
        String comment = null;
        try {
            comment = codeUnit.getComment(CodeUnit.EOL_COMMENT);
        } catch (Exception e) {
            // Comment API may have changed, ignore
        }

        // Get function context
        FunctionManager functionManager = program.getFunctionManager();
        Function containingFunction = functionManager.getFunctionContaining(codeUnit.getMinAddress());
        if (containingFunction != null) {
            functionName = containingFunction.getName();
        }

        // Get label if exists
        ghidra.program.model.symbol.Symbol primarySymbol = program.getSymbolTable()
                .getPrimarySymbol(codeUnit.getMinAddress());
        if (primarySymbol != null) {
            label = primarySymbol.getName();
        }

        if (codeUnit instanceof Instruction) {
            Instruction instr = (Instruction) codeUnit;
            type = "instruction";
            mnemonic = instr.getMnemonicString();
            instruction = instr.toString();
            // Extract operands from the full instruction string
            String fullStr = instr.toString();
            if (fullStr.contains(" ")) {
                operands = fullStr.substring(fullStr.indexOf(" ") + 1);
            }
        } else if (codeUnit instanceof Data) {
            Data data = (Data) codeUnit;
            type = "data";
            dataRepresentation = data.getDefaultValueRepresentation();
            instruction = dataRepresentation;
        } else {
            type = "unknown";
        }

        return new ListingInfo(address, label, instruction, mnemonic, operands,
                dataRepresentation, type, length, functionName, comment);
    }
}
