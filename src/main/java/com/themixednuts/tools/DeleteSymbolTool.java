package com.themixednuts.tools;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.models.OperationResult;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.google.SchemaBuilder;
import com.themixednuts.utils.jsonschema.google.SchemaBuilder.IObjectSchemaBuilder;

import ghidra.app.cmd.label.DeleteLabelCmd;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import io.modelcontextprotocol.common.McpTransportContext;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Map;
import java.util.Optional;

@GhidraMcpTool(name = "Delete Symbol", description = "Delete symbols and labels by address, name, or symbol ID.", mcpName = "delete_symbol", mcpDescription = """
        <use_case>
        Deletes a symbol or label from the program. Use this when you need to remove incorrect
        labels, clean up auto-generated symbols, or reorganize symbol naming conventions.
        </use_case>

        <important_notes>
        - IMPORTANT: If you plan to delete a symbol and then create/recreate it with different properties, use ManageSymbolsTool with 'update' action instead to preserve references
        - Supports multiple symbol identification methods (symbol ID, address, name)
        - Only one identifier should be provided at a time
        - Symbol deletion is permanent and cannot be undone without undo/redo
        - Use with caution as it modifies the program database
        - Some system symbols may be protected and cannot be deleted
        - Deleting and recreating will break existing references; prefer updating when possible
        </important_notes>

        <examples>
        Delete a symbol at an address:
        {
          "fileName": "program.exe",
          "address": "0x401000"
        }

        Delete a symbol by name:
        {
          "fileName": "program.exe",
          "name": "old_label"
        }

        Delete a symbol by ID:
        {
          "fileName": "program.exe",
          "symbol_id": 12345
        }
        </examples>
        """)
public class DeleteSymbolTool implements IGhidraMcpSpecification {

    public static final String ARG_ADDRESS = "address";
    public static final String ARG_NAME = "name";
    public static final String ARG_SYMBOL_ID = "symbol_id";

    @Override
    public JsonSchema schema() {
        IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();

        schemaRoot.property(ARG_FILE_NAME,
                SchemaBuilder.string(mapper)
                        .description("The name of the program file."));

        schemaRoot.property(ARG_ADDRESS, SchemaBuilder.string(mapper)
                .description("Memory address for symbol deletion")
                .pattern("^(0x)?[0-9a-fA-F]+$"));

        schemaRoot.property(ARG_NAME, SchemaBuilder.string(mapper)
                .description("Symbol name for deletion"));

        schemaRoot.property(ARG_SYMBOL_ID, SchemaBuilder.integer(mapper)
                .description("Unique symbol ID for precise identification"));

        schemaRoot.requiredProperty(ARG_FILE_NAME);

        // At least one identifier must be provided (JSON Schema Draft 7 anyOf)
        schemaRoot.anyOf(
                SchemaBuilder.object(mapper).requiredProperty(ARG_ADDRESS),
                SchemaBuilder.object(mapper).requiredProperty(ARG_NAME),
                SchemaBuilder.object(mapper).requiredProperty(ARG_SYMBOL_ID));

        return schemaRoot.build();
    }

    @Override
    public Mono<? extends Object> execute(McpTransportContext context, Map<String, Object> args, PluginTool tool) {
        GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);

        return getProgram(args, tool).flatMap(program -> handleDelete(program, args, annotation));
    }

    private Mono<? extends Object> handleDelete(Program program, Map<String, Object> args, GhidraMcpTool annotation) {
        return executeInTransaction(program, "MCP - Delete Symbol", () -> {
            Optional<String> addressOpt = getOptionalStringArgument(args, ARG_ADDRESS);
            Optional<String> nameOpt = getOptionalStringArgument(args, ARG_NAME);
            Optional<Long> symbolIdOpt = getOptionalLongArgument(args, ARG_SYMBOL_ID);

            if (addressOpt.isEmpty() && nameOpt.isEmpty() && symbolIdOpt.isEmpty()) {
                GhidraMcpError error = GhidraMcpError.validation()
                        .errorCode(GhidraMcpError.ErrorCode.MISSING_REQUIRED_ARGUMENT)
                        .message("At least one identifier must be provided")
                        .build();
                throw new GhidraMcpException(error);
            }

            SymbolTable symbolTable = program.getSymbolTable();
            Symbol symbolToDelete = null;

            if (symbolIdOpt.isPresent()) {
                symbolToDelete = symbolTable.getSymbol(symbolIdOpt.get());
            } else if (addressOpt.isPresent()) {
                try {
                    Address address = program.getAddressFactory().getAddress(addressOpt.get());
                    if (address != null) {
                        symbolToDelete = symbolTable.getPrimarySymbol(address);
                    }
                } catch (Exception e) {
                    GhidraMcpError error = GhidraMcpError.validation()
                            .errorCode(GhidraMcpError.ErrorCode.ADDRESS_PARSE_FAILED)
                            .message("Failed to parse address: " + e.getMessage())
                            .build();
                    throw new GhidraMcpException(error);
                }
            } else if (nameOpt.isPresent()) {
                SymbolIterator symbolIter = symbolTable.getSymbolIterator(nameOpt.get(), true);
                if (symbolIter.hasNext()) {
                    symbolToDelete = symbolIter.next();
                    if (symbolIter.hasNext()) {
                        GhidraMcpError error = GhidraMcpError.validation()
                                .errorCode(GhidraMcpError.ErrorCode.CONFLICTING_ARGUMENTS)
                                .message("Multiple symbols found with name: " + nameOpt.get())
                                .build();
                        throw new GhidraMcpException(error);
                    }
                }
            }

            if (symbolToDelete == null) {
                GhidraMcpError error = GhidraMcpError.resourceNotFound()
                        .errorCode(GhidraMcpError.ErrorCode.SYMBOL_NOT_FOUND)
                        .message("Symbol not found")
                        .build();
                throw new GhidraMcpException(error);
            }

            DeleteLabelCmd cmd = new DeleteLabelCmd(symbolToDelete.getAddress(), symbolToDelete.getName(),
                    symbolToDelete.getParentNamespace());
            if (!cmd.applyTo(program)) {
                GhidraMcpError error = GhidraMcpError.execution()
                        .errorCode(GhidraMcpError.ErrorCode.TRANSACTION_FAILED)
                        .message("Failed to delete symbol: " + cmd.getStatusMsg())
                        .build();
                throw new GhidraMcpException(error);
            }

            return OperationResult
                    .success("delete_symbol", symbolToDelete.getAddress().toString(), "Symbol deleted successfully")
                    .setMetadata(Map.of(
                            "name", symbolToDelete.getName(),
                            "address", symbolToDelete.getAddress().toString()));
        });
    }
}
