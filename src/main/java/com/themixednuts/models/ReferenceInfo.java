package com.themixednuts.models;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

/**
 * Represents a cross-reference between two addresses within a Ghidra program.
 */
public class ReferenceInfo {

    private final String fromAddress;
    private final String toAddress;
    private final String fromSymbol;
    private final String toSymbol;
    private final String referenceType;
    private final boolean call;
    private final boolean jump;
    private final boolean data;
    private final boolean read;
    private final boolean write;
    private final boolean primary;
    private final boolean external;
    private final int operandIndex;

    public ReferenceInfo(Program program, Reference reference) {
        SymbolTable symbolTable = program != null ? program.getSymbolTable() : null;
        this.fromAddress = toString(reference.getFromAddress());
        this.toAddress = toString(reference.getToAddress());
        this.fromSymbol = resolveSymbol(symbolTable, reference.getFromAddress());
        this.toSymbol = resolveSymbol(symbolTable, reference.getToAddress());

        RefType type = reference.getReferenceType();
        this.referenceType = type != null ? type.getName() : "UNKNOWN";
        this.call = type != null && type.isCall();
        this.jump = type != null && type.isJump();
        this.data = type != null && type.isData();
        this.read = type != null && type.isRead();
        this.write = type != null && type.isWrite();

        this.primary = reference.isPrimary();
        this.external = reference.isExternalReference();
        this.operandIndex = reference.getOperandIndex();
    }

    private static String toString(Address address) {
        return address != null ? address.toString() : null;
    }

    private static String resolveSymbol(SymbolTable symbolTable, Address address) {
        if (symbolTable == null || address == null) {
            return null;
        }
        Symbol symbol = symbolTable.getPrimarySymbol(address);
        return symbol != null ? symbol.getName(true) : null;
    }

    public String getFromAddress() {
        return fromAddress;
    }

    public String getToAddress() {
        return toAddress;
    }

    public String getFromSymbol() {
        return fromSymbol;
    }

    public String getToSymbol() {
        return toSymbol;
    }

    public String getReferenceType() {
        return referenceType;
    }

    public boolean isCall() {
        return call;
    }

    public boolean isJump() {
        return jump;
    }

    public boolean isData() {
        return data;
    }

    public boolean isRead() {
        return read;
    }

    public boolean isWrite() {
        return write;
    }

    public boolean isPrimary() {
        return primary;
    }

    public boolean isExternal() {
        return external;
    }

    public int getOperandIndex() {
        return operandIndex;
    }
}

