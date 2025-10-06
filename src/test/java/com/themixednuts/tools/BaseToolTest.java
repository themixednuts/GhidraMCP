package com.themixednuts.tools;

import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectData;
import ghidra.framework.model.ProjectManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import io.modelcontextprotocol.common.McpTransportContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;

import static org.junit.jupiter.api.Assertions.*;

import java.util.*;
// import java.util.stream.StreamSupport;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

/**
 * Base test class for testing Ghidra MCP tools.
 * Provides common mocking setup and utilities for testing tool execute methods.
 */
@ExtendWith(MockitoExtension.class)
public abstract class BaseToolTest {

    @Mock
    protected McpTransportContext mockContext;
    
    @Mock
    protected PluginTool mockTool;
    
    @Mock
    protected Project mockProject;
    
    @Mock
    protected ProjectData mockProjectData;
    
    @Mock
    protected ProjectManager mockProjectManager;
    
    @Mock
    protected Program mockProgram;
    
    @Mock
    protected FunctionManager mockFunctionManager;
    
    @Mock
    protected ghidra.program.model.data.ProgramBasedDataTypeManager mockDataTypeManager;
    
    @Mock
    protected Memory mockMemory;
    
    @Mock
    protected SymbolTable mockSymbolTable;
    
    @Mock
    protected AddressFactory mockAddressFactory;
    
    @Mock
    protected AddressSpace mockAddressSpace;
    
    @Mock
    protected Address mockAddress;
    
    @Mock
    protected DomainFile mockDomainFile;
    
    // No folder mocking required; tools use Project.getOpenData()

    @BeforeEach
    void setUpBaseMocks() {
        // Setup basic mock chain for tool -> project -> program
        when(mockTool.getProject()).thenReturn(mockProject);
        when(mockProject.getProjectData()).thenReturn(mockProjectData);
        when(mockTool.getProjectManager()).thenReturn(mockProjectManager);
        // Simulate open data containing our domain file (used by IGhidraMcpSpecification.findDomainFile)
        when(mockProject.getOpenData()).thenReturn(java.util.List.of(mockDomainFile));
        
        // Setup program mocks
        when(mockProgram.getFunctionManager()).thenReturn(mockFunctionManager);
        when(mockProgram.getMemory()).thenReturn(mockMemory);
        when(mockProgram.getSymbolTable()).thenReturn(mockSymbolTable);
        when(mockProgram.getAddressFactory()).thenReturn(mockAddressFactory);
        when(mockProgram.getDataTypeManager()).thenReturn(mockDataTypeManager);
        
        // Setup address mocks
        when(mockAddressFactory.getDefaultAddressSpace()).thenReturn(mockAddressSpace);
        try {
            when(mockAddressSpace.getAddress(anyString())).thenReturn(mockAddress);
        } catch (Exception ignored) {
            // Some AddressSpace.getAddress signatures throw checked exceptions depending on impl.
        }
        when(mockAddress.toString()).thenReturn("0x1000");
        when(mockAddress.compareTo(any(Address.class))).thenReturn(0);
        
        // Setup domain file mocks
        when(mockDomainFile.getName()).thenReturn("test_program.exe");
        when(mockDomainFile.getContentType()).thenReturn(Program.class.getName());
        try {
            when(mockDomainFile.getDomainObject(any(), anyBoolean(), anyBoolean(), any())).thenReturn(mockProgram);
        } catch (Exception ignored) {
        }
    }

    /**
     * Creates a test arguments map with the given key-value pairs.
     */
    protected Map<String, Object> createTestArgs(String... keyValuePairs) {
        Map<String, Object> args = new HashMap<>();
        for (int i = 0; i < keyValuePairs.length; i += 2) {
            if (i + 1 < keyValuePairs.length) {
                args.put(keyValuePairs[i], keyValuePairs[i + 1]);
            }
        }
        return args;
    }

    /**
     * Executes a tool with the given arguments and returns the result.
     */
    @SuppressWarnings("unchecked")
    protected <T> T executeTool(IGhidraMcpSpecification tool, Map<String, Object> args) throws Exception {
        Mono<? extends Object> result = tool.execute(mockContext, args, mockTool);
        return (T) result.block();
    }

    /**
     * Creates a mock function with the given name and address.
     */
    protected Function createMockFunction(String name, String address) {
        Function mockFunction = org.mockito.Mockito.mock(Function.class);
        when(mockFunction.getName()).thenReturn(name);
        when(mockFunction.getEntryPoint()).thenReturn(mockAddress);
        when(mockAddress.toString()).thenReturn(address);
        return mockFunction;
    }

    /**
     * Creates a mock data type with the given name and category path.
     */
    protected DataType createMockDataType(String name, String categoryPath) {
        DataType mockDataType = org.mockito.Mockito.mock(DataType.class);
        when(mockDataType.getName()).thenReturn(name);
        
        // Mock category path
        ghidra.program.model.data.CategoryPath mockCategoryPath = org.mockito.Mockito.mock(ghidra.program.model.data.CategoryPath.class);
        when(mockCategoryPath.getPath()).thenReturn(categoryPath);
        when(mockDataType.getCategoryPath()).thenReturn(mockCategoryPath);
        
        return mockDataType;
    }

    /**
     * Creates a mock memory block with the given name and size.
     */
    protected MemoryBlock createMockMemoryBlock(String name, long size) {
        MemoryBlock mockBlock = org.mockito.Mockito.mock(MemoryBlock.class);
        when(mockBlock.getName()).thenReturn(name);
        when(mockBlock.getSize()).thenReturn(size);
        when(mockBlock.getStart()).thenReturn(mockAddress);
        when(mockBlock.getEnd()).thenReturn(mockAddress);
        return mockBlock;
    }

    /**
     * Creates a mock symbol with the given name and address.
     */
    protected Symbol createMockSymbol(String name, String address) {
        Symbol mockSymbol = org.mockito.Mockito.mock(Symbol.class);
        when(mockSymbol.getName()).thenReturn(name);
        when(mockSymbol.getAddress()).thenReturn(mockAddress);
        when(mockAddress.toString()).thenReturn(address);
        return mockSymbol;
    }

    /**
     * Sets up the program manager to return the mock program for a given file name.
     */
    protected void setupProgramManager(String fileName) {
        when(mockTool.getProjectManager()).thenReturn(mockProjectManager);
        // Note: In real implementation, you would mock the program manager's getOpenProgram method
    }

    /**
     * Sets up the project data to return a list of domain files.
     */
    protected void setupProjectData(List<DomainFile> domainFiles) {
        // Note: In real implementation, you would mock the folder structure properly
        // This is a simplified version for testing purposes
    }

    /**
     * Creates a list of mock functions for testing.
     */
    protected List<Function> createMockFunctionList() {
        List<Function> functions = new ArrayList<>();
        functions.add(createMockFunction("main", "0x1000"));
        functions.add(createMockFunction("sub_2000", "0x2000"));
        functions.add(createMockFunction("decrypt_data", "0x3000"));
        return functions;
    }

    /**
     * Creates a list of mock data types for testing.
     */
    protected List<DataType> createMockDataTypeList() {
        List<DataType> dataTypes = new ArrayList<>();
        dataTypes.add(createMockDataType("int", "/"));
        dataTypes.add(createMockDataType("char", "/"));
        dataTypes.add(createMockDataType("MyStruct", "/structs"));
        return dataTypes;
    }

    /**
     * Creates a list of mock memory blocks for testing.
     */
    protected List<MemoryBlock> createMockMemoryBlockList() {
        List<MemoryBlock> blocks = new ArrayList<>();
        blocks.add(createMockMemoryBlock(".text", 0x1000));
        blocks.add(createMockMemoryBlock(".data", 0x500));
        blocks.add(createMockMemoryBlock(".bss", 0x200));
        return blocks;
    }

    /**
     * Creates a list of mock symbols for testing.
     */
    protected List<Symbol> createMockSymbolList() {
        List<Symbol> symbols = new ArrayList<>();
        symbols.add(createMockSymbol("main", "0x1000"));
        symbols.add(createMockSymbol("printf", "0x2000"));
        symbols.add(createMockSymbol("global_var", "0x3000"));
        return symbols;
    }

    /**
     * Asserts that a GhidraMcpException is thrown with the expected error type.
     */
    protected void assertGhidraMcpException(Class<? extends Exception> expectedException, 
                                          GhidraMcpError.ErrorType expectedErrorType,
                                          Runnable testCode) {
        Exception exception = assertThrows(expectedException, testCode::run);
        if (exception instanceof GhidraMcpException) {
            GhidraMcpException ghidraException = (GhidraMcpException) exception;
            assertEquals(expectedErrorType, ghidraException.getErrorType());
        }
    }

    /**
     * Helper method to create a mock iterator from a list.
     */
    protected <T> Iterator<T> createMockIterator(List<T> items) {
        return items.iterator();
    }

    /**
     * Helper method to create a mock iterable from a list.
     */
    protected <T> Iterable<T> createMockIterable(List<T> items) {
        return () -> items.iterator();
    }
}
