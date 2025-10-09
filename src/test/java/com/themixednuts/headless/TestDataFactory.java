// Test Data Factory - Creates deterministic test data for MCP tool testing
// @category Testing

package com.themixednuts.headless;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.data.*;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Creates deterministic test data for comprehensive tool testing.
 * All data is created BEFORE tests run to support deletion tests.
 */
public class TestDataFactory {

    /**
     * Context containing all test data addresses and names.
     */
    public static class TestDataContext {
        public final String programName;
        public final Address entryAddress;
        public final Address mainAddress;

        // Test data for deletion tests
        public Address testFunctionAddress;
        public Address testSymbolAddress;
        public Address testBookmarkAddress;
        public String testStructName = "TestStruct";
        public String testEnumName = "TestEnum";
        public String testFunctionName = "test_function";
        public String testLabelName = "test_label";
        public boolean testStructCreated = false;
        public boolean testEnumCreated = false;
        public boolean testBookmarkCreated = false;

        public TestDataContext(String programName, Address entryAddress, Address mainAddress) {
            this.programName = programName;
            this.entryAddress = entryAddress;
            this.mainAddress = mainAddress;
        }

        public Map<String, String> toMap() {
            Map<String, String> map = new HashMap<>();
            map.put("programName", programName);
            map.put("entryAddress", entryAddress != null ? entryAddress.toString() : null);
            map.put("mainAddress", mainAddress != null ? mainAddress.toString() : null);
            map.put("testFunctionAddress", testFunctionAddress != null ? testFunctionAddress.toString() : null);
            map.put("testSymbolAddress", testSymbolAddress != null ? testSymbolAddress.toString() : null);
            map.put("testBookmarkAddress", testBookmarkAddress != null ? testBookmarkAddress.toString() : null);
            map.put("testStructName", testStructName);
            map.put("testEnumName", testEnumName);
            map.put("testFunctionName", testFunctionName);
            map.put("testLabelName", testLabelName);
            return map;
        }
    }

    /**
     * Create all test data deterministically.
     * IMPORTANT: All modifications must be done within a transaction.
     */
    public static TestDataContext createTestData(Program program) throws Exception {
        AddressFactory addrFactory = program.getAddressFactory();
        FunctionManager funcMgr = program.getFunctionManager();
        SymbolTable symTable = program.getSymbolTable();

        // Get valid memory blocks (exclude EXTERNAL and other special blocks)
        List<Address> validAddresses = findValidExecutableAddresses(program);

        // Get program basics - use first valid address if image base is external
        Address entryAddress = program.getImageBase();
        if (!isValidAddress(program, entryAddress) && !validAddresses.isEmpty()) {
            entryAddress = validAddresses.get(0);
        }

        // Find main function
        Address mainAddress = null;
        Function mainFunc = null;
        for (Function func : funcMgr.getFunctions(true)) {
            if ("main".equals(func.getName())) {
                mainFunc = func;
                mainAddress = func.getEntryPoint();
                break;
            }
        }

        TestDataContext context = new TestDataContext(
                program.getName(),
                entryAddress,
                mainAddress);

        // Start transaction for all modifications
        int transactionId = program.startTransaction("Create Test Data");

        try {
            // Create test function at a known address in valid memory
            Address testFuncAddr = findAvailableAddressInValidMemory(program, validAddresses, 0);
            if (testFuncAddr != null) {
                try {
                    Function testFunc = funcMgr.createFunction(
                            "test_function",
                            testFuncAddr,
                            addrFactory.getAddressSet(testFuncAddr, testFuncAddr.add(16)),
                            SourceType.USER_DEFINED);
                    if (testFunc != null) {
                        context.testFunctionAddress = testFuncAddr;
                    }
                } catch (Exception e) {
                    System.err.println("[WARN] Failed to create test function: " + e.getMessage());
                }
            }

            // Create test symbol/label at a different valid address
            Address testSymAddr = findAvailableAddressInValidMemory(program, validAddresses, 1);
            if (testSymAddr != null) {
                try {
                    Symbol testSym = symTable.createLabel(
                            testSymAddr,
                            "test_label",
                            SourceType.USER_DEFINED);
                    if (testSym != null) {
                        context.testSymbolAddress = testSymAddr;
                    }
                } catch (Exception e) {
                    System.err.println("[WARN] Failed to create test symbol: " + e.getMessage());
                }
            }

            // Create test bookmark
            context.testBookmarkAddress = entryAddress;
            BookmarkManager bookmarkMgr = program.getBookmarkManager();
            try {
                bookmarkMgr.setBookmark(entryAddress, "NOTE", "Test", "Test bookmark for deletion tests");
                context.testBookmarkCreated = true;
            } catch (Exception e) {
                System.err.println("[WARN] Failed to create test bookmark: " + e.getMessage());
            }

            // Create test data types
            DataTypeManager dtm = program.getDataTypeManager();

            // Create test struct
            try {
                // Check if it already exists and remove it to ensure clean state
                DataTypePath existingStructPath = new DataTypePath(CategoryPath.ROOT, context.testStructName);
                DataType existing = dtm.getDataType(existingStructPath);
                if (existing != null) {
                    dtm.remove(existing, null);
                }

                StructureDataType testStruct = new StructureDataType(CategoryPath.ROOT, context.testStructName, 0);
                DataType intType = dtm.getDataType("/int");
                if (intType == null) {
                    intType = IntegerDataType.dataType;
                }
                testStruct.add(intType, 4, "field1", null);
                DataType addedStruct = dtm.addDataType(testStruct, DataTypeConflictHandler.REPLACE_HANDLER);
                context.testStructCreated = (addedStruct != null);
            } catch (Exception e) {
                System.err.println("[WARN] Failed to create test struct: " + e.getMessage());
                e.printStackTrace();
            }

            // Create test enum
            try {
                // Check if it already exists and remove it to ensure clean state
                DataTypePath existingEnumPath = new DataTypePath(CategoryPath.ROOT, context.testEnumName);
                DataType existing = dtm.getDataType(existingEnumPath);
                if (existing != null) {
                    dtm.remove(existing, null);
                }

                EnumDataType testEnum = new EnumDataType(CategoryPath.ROOT, context.testEnumName, 4);
                testEnum.add("VALUE1", 0);
                testEnum.add("VALUE2", 1);
                DataType addedEnum = dtm.addDataType(testEnum, DataTypeConflictHandler.REPLACE_HANDLER);
                context.testEnumCreated = (addedEnum != null);
            } catch (Exception e) {
                System.err.println("[WARN] Failed to create test enum: " + e.getMessage());
                e.printStackTrace();
            }

        } finally {
            // Always commit the transaction (even if some resources failed)
            program.endTransaction(transactionId, true);
        }

        return context;
    }

    /**
     * Find valid executable addresses in the program, excluding EXTERNAL blocks.
     */
    private static List<Address> findValidExecutableAddresses(Program program) {
        List<Address> validAddresses = new ArrayList<>();
        Memory memory = program.getMemory();

        for (MemoryBlock block : memory.getBlocks()) {
            // Skip EXTERNAL, OVERLAY, and other special blocks
            if (block.isExternalBlock() || block.getName().equals("EXTERNAL") ||
                    block.isOverlay() || !block.isInitialized()) {
                continue;
            }

            // Prefer executable blocks for test functions
            if (block.isExecute()) {
                Address blockStart = block.getStart();
                Address blockEnd = block.getEnd();

                // Sample a few addresses from this block
                try {
                    validAddresses.add(blockStart);
                    if (block.getSize() > 0x100) {
                        validAddresses.add(blockStart.add(0x100));
                    }
                    if (block.getSize() > 0x1000) {
                        validAddresses.add(blockStart.add(0x1000));
                    }
                } catch (Exception e) {
                    // Address math failed, skip
                }
            }
        }

        return validAddresses;
    }

    /**
     * Check if an address is in a valid, non-external memory block.
     */
    private static boolean isValidAddress(Program program, Address address) {
        if (address == null) {
            return false;
        }

        Memory memory = program.getMemory();
        MemoryBlock block = memory.getBlock(address);

        if (block == null) {
            return false;
        }

        // Exclude external and uninitialized blocks
        return !block.isExternalBlock() &&
                !block.getName().equals("EXTERNAL") &&
                block.isInitialized();
    }

    /**
     * Find an available address in valid memory that doesn't have a function.
     */
    private static Address findAvailableAddressInValidMemory(Program program,
            List<Address> validAddresses,
            int startIndex) {
        FunctionManager funcMgr = program.getFunctionManager();
        Memory memory = program.getMemory();

        // Try addresses from the valid list first
        for (int i = startIndex; i < validAddresses.size(); i++) {
            Address candidate = validAddresses.get(i);

            // Check if this address is available (no function, in valid memory)
            if (funcMgr.getFunctionAt(candidate) == null && isValidAddress(program, candidate)) {
                // Also check we can write to this address (not in read-only block)
                MemoryBlock block = memory.getBlock(candidate);
                if (block != null && block.isWrite()) {
                    return candidate;
                }
            }

            // Try nearby addresses
            try {
                for (int offset = 16; offset < 256; offset += 16) {
                    Address nearby = candidate.add(offset);
                    if (isValidAddress(program, nearby) &&
                            funcMgr.getFunctionAt(nearby) == null) {
                        MemoryBlock block = memory.getBlock(nearby);
                        if (block != null && block.isWrite()) {
                            return nearby;
                        }
                    }
                }
            } catch (Exception e) {
                // Address math failed, continue
            }
        }

        return null;
    }
}
