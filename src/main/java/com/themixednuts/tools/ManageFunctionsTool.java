package com.themixednuts.tools;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.FunctionVariableInfo;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.models.FunctionInfo;
import com.themixednuts.models.OperationResult;
import com.themixednuts.models.FunctionGraph;
import com.themixednuts.models.FunctionGraphNode;
import com.themixednuts.models.FunctionGraphEdge;
import com.themixednuts.utils.GhidraMcpErrorUtils;
import ghidra.program.database.data.DataTypeUtilities;
import com.themixednuts.utils.PaginatedResult;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.draft7.SchemaBuilder;
import static com.themixednuts.utils.jsonschema.draft7.ConditionalSpec.conditional;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.cmd.function.DeleteFunctionCmd;
import ghidra.app.util.NamespaceUtils;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.block.CodeBlockModel;
import ghidra.program.model.address.AddressSetView;
import io.modelcontextprotocol.common.McpTransportContext;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;
import java.util.Spliterator;
import java.util.Spliterators;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.app.services.DataTypeQueryService;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;

@GhidraMcpTool(name = "Manage Functions", description = "Function operations: create, update prototypes, list variables, and get function graphs.", mcpName = "manage_functions", mcpDescription = """
                 <use_case>
                 Function operations for reverse engineering workflows. Create, update
                 function prototypes, list function variables, and get function control-flow graphs to understand program structure, control flow, and calling conventions.
                 </use_case>

                 <important_notes>
                 - Supports multiple function identification methods (name, address, symbol ID, regex)
                 - Handles function creation with automatic boundary detection
                 - Lists both listing variables and decompiler-generated variables with detailed categorization
                 - Generates control-flow graphs showing basic blocks and their connections
                 - Use ReadFunctionsTool for reading/browsing functions with filtering
                 - Use FindFunctionTool for searching functions by name, address, or patterns
                 - Use DecompileCodeTool for decompilation analysis
                 - Use DeleteFunctionTool to delete functions
                 </important_notes>

                <examples>
                Create a function at an address with custom name:
                {
                  "fileName": "program.exe",
                  "action": "create",
                  "address": "0x401000",
                  "function_name": "decrypt_data"
                }

                Create a function at an address (auto-generated name):
                {
                  "fileName": "program.exe",
                  "action": "create",
                  "address": "0x401000"
                }

                List variables in a function:
                {
                  "fileName": "program.exe",
                  "action": "list_variables",
                  "target_type": "name",
                  "target_value": "main"
                }

                Get function control-flow graph:
                {
                  "fileName": "program.exe",
                  "action": "get_graph",
                  "name": "main"
                }
                </examples>
                """)
public class ManageFunctionsTool implements IGhidraMcpSpecification {

        public static final String ARG_ACTION = "action";
        public static final String ARG_SYMBOL_ID = "symbol_id";
        public static final String ARG_ADDRESS = "address";
        public static final String ARG_NAME = "name";
        public static final String ARG_PROTOTYPE = "prototype";

        private static final String ACTION_CREATE = "create";
        private static final String ACTION_UPDATE_PROTOTYPE = "update_prototype";
        private static final String ACTION_LIST_VARIABLES = "list_variables";
        private static final String ACTION_GET_GRAPH = "get_graph";

        /**
         * Defines the JSON input schema for function management operations.
         * 
         * @return The JsonSchema defining the expected input arguments
         */
        @Override
        public JsonSchema schema() {
                // Use Draft 7 builder for conditional support
                var schemaRoot = IGhidraMcpSpecification.createDraft7SchemaNode();

                schemaRoot.property(ARG_FILE_NAME,
                                SchemaBuilder.string(mapper)
                                                .description("The name of the program file."));

                schemaRoot.property(ARG_ACTION, SchemaBuilder.string(mapper)
                                .enumValues(ACTION_CREATE, ACTION_UPDATE_PROTOTYPE, ACTION_LIST_VARIABLES,
                                                ACTION_GET_GRAPH)
                                .description("Action to perform on functions"));

                schemaRoot.property(ARG_SYMBOL_ID, SchemaBuilder.integer(mapper)
                                .description("Symbol ID to identify target function (highest precedence)"));

                schemaRoot.property(ARG_ADDRESS, SchemaBuilder.string(mapper)
                                .description("Function address for create/delete or to identify target function")
                                .pattern("^(0x)?[0-9a-fA-F]+$"));

                schemaRoot.property(ARG_NAME, SchemaBuilder.string(mapper)
                                .description("Function name - for identification or setting name during creation"));

                schemaRoot.property(ARG_PROTOTYPE, SchemaBuilder.string(mapper)
                                .description(
                                                "Full function prototype string (C syntax). If provided, other structured fields like returnType/parameters are ignored."));

                schemaRoot.requiredProperty(ARG_FILE_NAME)
                                .requiredProperty(ARG_ACTION);

                // Add conditional requirements based on action (JSON Schema Draft 7)
                schemaRoot.addConditionals(
                                // action=create requires address
                                conditional(ARG_ACTION, ACTION_CREATE).require(ARG_ADDRESS));

                return schemaRoot.build();
        }

        /**
         * Executes the function management operation.
         * 
         * @param context The MCP transport context
         * @param args    The tool arguments containing fileName, action, and
         *                action-specific parameters
         * @param tool    The Ghidra PluginTool context
         * @return A Mono emitting the result of the function operation
         */
        @Override
        public Mono<? extends Object> execute(McpTransportContext context, Map<String, Object> args, PluginTool tool) {
                GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);

                return getProgram(args, tool).flatMap(program -> {
                        String action = getRequiredStringArgument(args, ARG_ACTION);

                        try {
                                if ("create".equalsIgnoreCase(action)) {
                                        ensureArgumentPresent(args, ARG_ADDRESS, annotation.mcpName() + ".create");
                                }
                        } catch (GhidraMcpException e) {
                                return Mono.error(e);
                        }

                        return switch (action.toLowerCase(Locale.ROOT)) {
                                case ACTION_CREATE -> handleCreate(program, args, annotation);
                                case ACTION_UPDATE_PROTOTYPE -> handleUpdatePrototype(program, tool, args, annotation);
                                case ACTION_LIST_VARIABLES -> handleListVariables(program, args, annotation);
                                case ACTION_GET_GRAPH -> handleGetGraph(program, args, annotation);
                                default -> {
                                        GhidraMcpError error = GhidraMcpError.validation()
                                                        .errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
                                                        .message("Invalid action: " + action)
                                                        .context(new GhidraMcpError.ErrorContext(
                                                                        annotation.mcpName(),
                                                                        "action validation",
                                                                        args,
                                                                        Map.of(ARG_ACTION, action),
                                                                        Map.of("validActions",
                                                                                        List.of(ACTION_CREATE,
                                                                                                        ACTION_UPDATE_PROTOTYPE,
                                                                                                        ACTION_LIST_VARIABLES,
                                                                                                        ACTION_GET_GRAPH))))
                                                        .suggestions(List.of(
                                                                        new GhidraMcpError.ErrorSuggestion(
                                                                                        GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
                                                                                        "Use a valid action",
                                                                                        "Choose from: create, update_prototype, list_variables, get_graph",
                                                                                        List.of(ACTION_CREATE,
                                                                                                        ACTION_UPDATE_PROTOTYPE,
                                                                                                        ACTION_LIST_VARIABLES,
                                                                                                        ACTION_GET_GRAPH),
                                                                                        null)))
                                                        .build();
                                        yield Mono.error(new GhidraMcpException(error));
                                }
                        };
                });
        }

        private Mono<? extends Object> handleCreate(Program program, Map<String, Object> args,
                        GhidraMcpTool annotation) {
                String toolOperation = annotation.mcpName() + ".create";
                String addressString = getRequiredStringArgument(args, ARG_ADDRESS);
                Optional<String> nameOpt = getOptionalStringArgument(args, ARG_FUNCTION_NAME);

                return parseAddressOrThrow(program, addressString, toolOperation, args).flatMap(functionAddress -> {
                        if (program.getFunctionManager().getFunctionAt(functionAddress) != null) {
                                GhidraMcpError error = GhidraMcpError.validation()
                                                .errorCode(GhidraMcpError.ErrorCode.CONFLICTING_ARGUMENTS)
                                                .message("Function already exists at the specified address")
                                                .context(new GhidraMcpError.ErrorContext(
                                                                toolOperation,
                                                                "function existence check",
                                                                args,
                                                                Map.of(ARG_ADDRESS, addressString),
                                                                Map.of("functionExists", true)))
                                                .suggestions(List.of(
                                                                new GhidraMcpError.ErrorSuggestion(
                                                                                GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
                                                                                "Verify the address is not already a function entry point",
                                                                                "Inspect existing functions around the target address",
                                                                                null,
                                                                                null)))
                                                .build();
                                return Mono.error(new GhidraMcpException(error));
                        }

                        return executeInTransaction(program, "MCP - Create Function at " + functionAddress, () -> {
                                CreateFunctionCmd cmd = new CreateFunctionCmd(
                                                nameOpt.orElse(null),
                                                functionAddress,
                                                new AddressSet(functionAddress),
                                                SourceType.USER_DEFINED);

                                boolean success = cmd.applyTo(program);
                                if (!success) {
                                        String status = Optional.ofNullable(cmd.getStatusMsg()).orElse("Unknown error");
                                        GhidraMcpError error = GhidraMcpError.execution()
                                                        .errorCode(GhidraMcpError.ErrorCode.TRANSACTION_FAILED)
                                                        .message("Failed to create function: " + status)
                                                        .context(new GhidraMcpError.ErrorContext(
                                                                        toolOperation,
                                                                        "function creation command",
                                                                        Map.of(ARG_ADDRESS, addressString,
                                                                                        ARG_FUNCTION_NAME,
                                                                                        nameOpt.orElse("default")),
                                                                        Map.of("commandStatus", status),
                                                                        Map.of("commandSuccess", false)))
                                                        .suggestions(List.of(
                                                                        new GhidraMcpError.ErrorSuggestion(
                                                                                        GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
                                                                                        "Ensure the address contains executable code",
                                                                                        "Verify the target address has been properly disassembled",
                                                                                        null,
                                                                                        null)))
                                                        .build();
                                        throw new GhidraMcpException(error);
                                }

                                Function createdFunction = cmd.getFunction();
                                if (createdFunction == null) {
                                        GhidraMcpError error = GhidraMcpError.execution()
                                                        .errorCode(GhidraMcpError.ErrorCode.UNEXPECTED_ERROR)
                                                        .message("Function creation succeeded but returned no function object")
                                                        .context(new GhidraMcpError.ErrorContext(
                                                                        toolOperation,
                                                                        "function creation result",
                                                                        Map.of(ARG_ADDRESS, addressString),
                                                                        Map.of("commandSuccess", true,
                                                                                        "functionReturned", false),
                                                                        Map.of("internalError", true)))
                                                        .suggestions(List.of(
                                                                        new GhidraMcpError.ErrorSuggestion(
                                                                                        GhidraMcpError.ErrorSuggestion.SuggestionType.CHECK_RESOURCES,
                                                                                        "Verify the new function exists",
                                                                                        "Inspect the program to confirm the created function",
                                                                                        null,
                                                                                        null)))
                                                        .build();
                                        throw new GhidraMcpException(error);
                                }

                                return new FunctionInfo(createdFunction);
                        });
                });
        }

        private List<String> getFunctionNameSamples(FunctionManager functionManager, int limit) {
                if (limit <= 0) {
                        return List.of();
                }

                return StreamSupport.stream(functionManager.getFunctions(true).spliterator(), false)
                                .map(Function::getName)
                                .filter(name -> name != null && !name.isBlank())
                                .distinct()
                                .limit(limit)
                                .collect(Collectors.toList());
        }

        private Mono<? extends Object> handleUpdatePrototype(Program program, PluginTool tool, Map<String, Object> args,
                        GhidraMcpTool annotation) {
                String toolOperation = annotation.mcpName() + ".update_prototype";

                // Extract function identifiers from both direct arguments and
                // target_type/target_value
                FunctionIdentifiers identifiers = extractFunctionIdentifiers(args);

                if (identifiers.isEmpty()) {
                        return Mono.error(new GhidraMcpException(createMissingIdentifierError(annotation, args)));
                }

                // Check if raw prototype string is provided (preferred approach)
                Optional<String> rawPrototypeOpt = getOptionalStringArgument(args, ARG_PROTOTYPE)
                                .map(String::trim)
                                .filter(value -> !value.isEmpty());

                if (rawPrototypeOpt.isPresent()) {
                        // Use raw prototype string with FunctionSignatureParser
                        return Mono.fromCallable(() -> resolveFunctionByIdentifiers(
                                        program, identifiers, annotation, args, toolOperation))
                                        .map(function -> new UpdatePrototypeContext(program, function,
                                                        rawPrototypeOpt.get()))
                                        .flatMap(context -> executePrototypeUpdate(program, annotation, tool, context));
                } else {
                        // Build prototype from structured arguments
                        String returnTypeName = getRequiredStringArgument(args, "returnType");
                        Optional<String> callingConventionOpt = getOptionalStringArgument(args, "callingConvention");
                        Optional<String> newFunctionNameOpt = getOptionalStringArgument(args, "newFunctionName");
                        Optional<List<Map<String, Object>>> parametersOpt = getOptionalListArgument(args, "parameters");
                        boolean noReturn = getOptionalBooleanArgument(args, "noReturn").orElse(false);

                        return Mono.fromCallable(() -> resolveFunctionForPrototype(program,
                                        tool, identifiers, returnTypeName, callingConventionOpt, newFunctionNameOpt,
                                        parametersOpt, noReturn, annotation, args, toolOperation))
                                        .flatMap(context -> executePrototypeUpdate(program, annotation, tool, context));
                }
        }

        private Mono<? extends Object> executePrototypeUpdate(Program program,
                        GhidraMcpTool annotation,
                        PluginTool tool,
                        UpdatePrototypeContext context) {
                return executeInTransaction(program,
                                "MCP - Update Function Prototype: " + context.function().getName(),
                                () -> applyPrototype(program, annotation, tool, context));
        }

        private Object applyPrototype(Program program,
                        GhidraMcpTool annotation,
                        PluginTool tool,
                        UpdatePrototypeContext context) throws GhidraMcpException {
                Function function = context.function();
                String prototype = context.prototypeString();

                try {
                        DataTypeManager dtm = program.getDataTypeManager();
                        DataTypeQueryService service = tool != null ? tool.getService(DataTypeQueryService.class)
                                        : null;
                        FunctionSignatureParser parser = new FunctionSignatureParser(dtm, service);
                        FunctionDefinitionDataType parsedSignature = parser.parse(function.getSignature(), prototype);

                        ghidra.app.cmd.function.ApplyFunctionSignatureCmd cmd = new ghidra.app.cmd.function.ApplyFunctionSignatureCmd(
                                        function.getEntryPoint(),
                                        parsedSignature,
                                        SourceType.USER_DEFINED);

                        if (!cmd.applyTo(program)) {
                                String status = Optional.ofNullable(cmd.getStatusMsg()).orElse("Unknown error");
                                GhidraMcpError error = GhidraMcpError.execution()
                                                .errorCode(GhidraMcpError.ErrorCode.TRANSACTION_FAILED)
                                                .message("Failed to apply function prototype: " + status)
                                                .context(new GhidraMcpError.ErrorContext(
                                                                annotation.mcpName(),
                                                                "function prototype update command",
                                                                Map.of("prototype", prototype, ARG_FUNCTION_NAME,
                                                                                function.getName()),
                                                                Map.of("commandStatus", status),
                                                                Map.of("commandSuccess", false, "prototypeValid",
                                                                                true)))
                                                .build();
                                throw new GhidraMcpException(error);
                        }

                        return new FunctionInfo(function);
                } catch (GhidraMcpException e) {
                        throw e;
                } catch (Exception e) {
                        GhidraMcpError error = GhidraMcpError.validation()
                                        .errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
                                        .message("Failed to parse constructed function prototype: " + e.getMessage())
                                        .context(new GhidraMcpError.ErrorContext(
                                                        annotation.mcpName(),
                                                        "prototype parsing",
                                                        null,
                                                        Map.of("error", e.getMessage()),
                                                        Map.of("prototypeSyntax", false)))
                                        .build();
                        throw new GhidraMcpException(error);
                }
        }

        private UpdatePrototypeContext resolveFunctionForPrototype(Program program,
                        PluginTool tool,
                        FunctionIdentifiers identifiers,
                        String returnTypeName,
                        Optional<String> callingConventionOpt,
                        Optional<String> newFunctionNameOpt,
                        Optional<List<Map<String, Object>>> parametersOpt,
                        boolean noReturn,
                        GhidraMcpTool annotation,
                        Map<String, Object> args,
                        String toolOperation) throws GhidraMcpException {
                Function function = resolveFunctionByIdentifiers(
                                program,
                                identifiers,
                                annotation,
                                args,
                                toolOperation);

                String prototype = buildPrototypeString(program,
                                tool,
                                function,
                                returnTypeName,
                                callingConventionOpt,
                                newFunctionNameOpt.orElse(function.getName()),
                                parametersOpt,
                                noReturn,
                                annotation,
                                args);

                return new UpdatePrototypeContext(program, function, prototype);
        }

        private Function resolveFunctionByIdentifiers(Program program,
                        FunctionIdentifiers identifiers,
                        GhidraMcpTool annotation,
                        Map<String, Object> args,
                        String toolOperation) throws GhidraMcpException {
                FunctionManager funcMan = program.getFunctionManager();
                SymbolTable symbolTable = program.getSymbolTable();
                Function function = null;

                if (identifiers.symbolId().isPresent()) {
                        Symbol symbol = symbolTable.getSymbol(identifiers.symbolId().get());
                        if (symbol != null && symbol.getSymbolType() == SymbolType.FUNCTION) {
                                function = funcMan.getFunctionAt(symbol.getAddress());
                        }
                }

                if (function == null && identifiers.address().isPresent()) {
                        String addressString = identifiers.address().get();
                        try {
                                Address entryPoint = program.getAddressFactory().getAddress(addressString);
                                if (entryPoint == null) {
                                        throw new IllegalArgumentException("Unresolvable address");
                                }
                                function = funcMan.getFunctionAt(entryPoint);
                        } catch (Exception e) {
                                throw new GhidraMcpException(
                                                GhidraMcpErrorUtils.addressParseError(addressString, toolOperation, e));
                        }
                }

                if (function == null && identifiers.name().isPresent()) {
                        String functionName = identifiers.name().get();

                        // Try exact name match first
                        function = StreamSupport.stream(funcMan.getFunctions(true).spliterator(), false)
                                        .filter(f -> f.getName(true).equals(functionName))
                                        .findFirst()
                                        .orElse(null);

                        // If not found and name contains "::", try qualified name search
                        if (function == null && functionName.contains("::")) {
                                function = StreamSupport.stream(funcMan.getFunctions(true).spliterator(), false)
                                                .filter(f -> {
                                                        String qualifiedName = NamespaceUtils.getNamespaceQualifiedName(
                                                                        f.getParentNamespace(),
                                                                        f.getName(),
                                                                        false);
                                                        return qualifiedName.equals(functionName);
                                                })
                                                .findFirst()
                                                .orElse(null);
                        }
                }

                if (function == null) {
                        Map<String, Object> searchCriteria = Map.of(
                                        ARG_FUNCTION_SYMBOL_ID,
                                        identifiers.symbolId().map(Object::toString).orElse("not provided"),
                                        ARG_ADDRESS, identifiers.address().orElse("not provided"),
                                        ARG_FUNCTION_NAME, identifiers.name().orElse("not provided"));

                        GhidraMcpError error = GhidraMcpError.resourceNotFound()
                                        .errorCode(GhidraMcpError.ErrorCode.FUNCTION_NOT_FOUND)
                                        .message("Function not found using provided identifiers")
                                        .context(new GhidraMcpError.ErrorContext(
                                                        annotation.mcpName(),
                                                        "function lookup",
                                                        args,
                                                        searchCriteria,
                                                        Map.of("searchAttempted", true, "functionFound", false)))
                                        .build();
                        throw new GhidraMcpException(error);
                }

                return function;
        }

        private String buildPrototypeString(Program program,
                        PluginTool tool,
                        Function function,
                        String returnTypeName,
                        Optional<String> callingConventionOpt,
                        String functionName,
                        Optional<List<Map<String, Object>>> parametersOpt,
                        boolean noReturn,
                        GhidraMcpTool annotation,
                        Map<String, Object> args) throws GhidraMcpException {
                StringBuilder prototype = new StringBuilder();

                DataType returnType = DataTypeUtilities.getCPrimitiveDataType(returnTypeName);
                if (returnType == null) {
                        throw new GhidraMcpException(createDataTypeError(
                                        GhidraMcpError.ErrorCode.INVALID_TYPE_PATH,
                                        "Invalid return type: " + returnTypeName,
                                        "Creating function",
                                        args,
                                        returnTypeName));
                }

                prototype.append(returnType.getName());
                callingConventionOpt.ifPresent(cc -> prototype.append(" ").append(cc));
                prototype.append(" ").append(functionName).append("(");

                if (parametersOpt.isPresent() && !parametersOpt.get().isEmpty()) {
                        List<String> params = new ArrayList<>();
                        for (Map<String, Object> param : parametersOpt.get()) {
                                params.add(parameterToString(program, tool, param, annotation, args));
                        }
                        prototype.append(String.join(", ", params));
                }

                if (noReturn) {
                        function.setNoReturn(true);
                }

                prototype.append(")");
                return prototype.toString();
        }

        private String parameterToString(Program program,
                        PluginTool tool,
                        Map<String, Object> paramMap,
                        GhidraMcpTool annotation,
                        Map<String, Object> args) throws GhidraMcpException {
                String name = (String) paramMap.get("name");
                String dataType = (String) paramMap.get("dataType");

                if (name == null || dataType == null) {
                        GhidraMcpError error = GhidraMcpError.validation()
                                        .errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
                                        .message("Parameter entries must include 'name' and 'dataType'")
                                        .context(new GhidraMcpError.ErrorContext(
                                                        annotation.mcpName(),
                                                        "parameter validation",
                                                        args,
                                                        paramMap,
                                                        Map.of("hasName", name != null, "hasDataType",
                                                                        dataType != null)))
                                        .build();
                        throw new RuntimeException(error.getMessage());
                }

                if ("...".equals(dataType)) {
                        return "...";
                }

                DataType resolved = DataTypeUtilities.getCPrimitiveDataType(dataType);
                if (resolved == null) {
                        throw new GhidraMcpException(createDataTypeError(
                                        GhidraMcpError.ErrorCode.INVALID_TYPE_PATH,
                                        "Invalid parameter data type: " + dataType,
                                        "Parsing function parameter",
                                        args,
                                        dataType));
                }
                return resolved.getName() + " " + name;
        }

        private record UpdatePrototypeContext(Program program, Function function, String prototypeString) {
        }

        private record FunctionIdentifiers(Optional<Long> symbolId, Optional<String> address, Optional<String> name) {
                boolean isEmpty() {
                        return symbolId.isEmpty() && address.isEmpty() && name.isEmpty();
                }
        }

        private FunctionIdentifiers extractFunctionIdentifiers(Map<String, Object> args) {
                Long symbolId = getOptionalLongArgument(args, ARG_SYMBOL_ID).orElse(null);
                String addressValue = getOptionalStringArgument(args, ARG_ADDRESS).orElse(null);
                String functionNameValue = getOptionalStringArgument(args, ARG_NAME).orElse(null);

                return new FunctionIdentifiers(
                                Optional.ofNullable(symbolId),
                                Optional.ofNullable(addressValue),
                                Optional.ofNullable(functionNameValue));
        }

        private GhidraMcpError createMissingIdentifierError(GhidraMcpTool annotation, Map<String, Object> args) {
                Map<String, Object> providedIdentifiers = Map.of(
                                ARG_FUNCTION_SYMBOL_ID, "not provided",
                                ARG_ADDRESS, "not provided",
                                ARG_FUNCTION_NAME, "not provided");

                return GhidraMcpError.validation()
                                .errorCode(GhidraMcpError.ErrorCode.MISSING_REQUIRED_ARGUMENT)
                                .message("At least one function identifier must be provided")
                                .context(new GhidraMcpError.ErrorContext(
                                                annotation.mcpName(),
                                                "function identifier validation",
                                                args,
                                                providedIdentifiers,
                                                Map.of("identifiersProvided", 0, "minimumRequired", 1)))
                                .suggestions(List.of(
                                                new GhidraMcpError.ErrorSuggestion(
                                                                GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
                                                                "Provide at least one function identifier",
                                                                "Include at least one of: " + ARG_FUNCTION_SYMBOL_ID
                                                                                + ", " + ARG_ADDRESS + ", or "
                                                                                + ARG_FUNCTION_NAME,
                                                                List.of(
                                                                                "\"" + ARG_FUNCTION_SYMBOL_ID
                                                                                                + "\": 12345",
                                                                                "\"" + ARG_ADDRESS + "\": \"0x401000\"",
                                                                                "\"" + ARG_FUNCTION_NAME
                                                                                                + "\": \"main\""),
                                                                null)))
                                .build();
        }

        private Mono<Address> parseAddressOrThrow(Program program, String addressString, String toolOperation,
                        Map<String, Object> args) {
                return Mono.fromCallable(() -> {
                        Address address = program.getAddressFactory().getAddress(addressString);
                        if (address == null) {
                                GhidraMcpError error = GhidraMcpError.validation()
                                                .errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
                                                .message("Invalid address: " + addressString)
                                                .context(new GhidraMcpError.ErrorContext(
                                                                toolOperation,
                                                                "address resolution",
                                                                args,
                                                                Map.of(ARG_ADDRESS, addressString),
                                                                Map.of("addressResolved", false)))
                                                .suggestions(List.of(
                                                                new GhidraMcpError.ErrorSuggestion(
                                                                                GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
                                                                                "Use a valid hexadecimal address",
                                                                                "Provide the function entry point as a hexadecimal value",
                                                                                List.of("0x401000", "401000",
                                                                                                "0x00401000"),
                                                                                null)))
                                                .build();
                                throw new GhidraMcpException(error);
                        }
                        return address;
                }).onErrorMap(e -> {
                        if (e instanceof GhidraMcpException) {
                                return e;
                        }
                        return new GhidraMcpException(
                                        GhidraMcpErrorUtils.addressParseError(addressString, toolOperation, e));
                });
        }

        private Mono<? extends Object> handleListVariables(Program program, Map<String, Object> args,
                        GhidraMcpTool annotation) {
                String toolOperation = annotation.mcpName() + ".list_variables";

                // Extract function identifiers from both direct arguments and
                // target_type/target_value
                FunctionIdentifiers identifiers = extractFunctionIdentifiers(args);

                if (identifiers.isEmpty()) {
                        return Mono.error(new GhidraMcpException(createMissingIdentifierError(annotation, args)));
                }

                return Mono.fromCallable(() -> {
                        Function function = resolveFunctionByIdentifiers(program, identifiers, annotation, args,
                                        toolOperation);
                        return listFunctionVariables(function, program, args, annotation);
                });
        }

        private PaginatedResult<FunctionVariableInfo> listFunctionVariables(Function function, Program program,
                        Map<String, Object> args, GhidraMcpTool annotation) {
                Optional<String> cursorOpt = getOptionalStringArgument(args, ARG_CURSOR);

                // Get listing variables
                Stream<FunctionVariableInfo> listingVarStream = Arrays.stream(function.getAllVariables())
                                .map(FunctionVariableInfo::new);

                // Get decompiler variables
                Stream<FunctionVariableInfo> decompilerVarStream = Stream.empty();
                DecompInterface decomplib = new DecompInterface();
                try {
                        decomplib.setOptions(new DecompileOptions());
                        decomplib.openProgram(program);
                        DecompileResults results = decomplib.decompileFunction(function,
                                        decomplib.getOptions().getDefaultTimeout(), new ConsoleTaskMonitor());

                        if (results == null) {
                                // Decompiler failed but continue with listing variables only
                                ghidra.util.Msg.warn(this,
                                                "Decompiler returned null results for function: " + function.getName());
                        } else {
                                HighFunction hf = results.getHighFunction();
                                if (hf != null) {
                                        LocalSymbolMap localSymbolMap = hf.getLocalSymbolMap();
                                        if (localSymbolMap != null) {
                                                java.util.Iterator<HighSymbol> highSymbolIterator = localSymbolMap
                                                                .getSymbols();
                                                decompilerVarStream = StreamSupport.stream(
                                                                Spliterators.spliteratorUnknownSize(highSymbolIterator,
                                                                                Spliterator.ORDERED),
                                                                false)
                                                                .map(HighSymbol::getHighVariable)
                                                                .filter(java.util.Objects::nonNull)
                                                                .map(hv -> new FunctionVariableInfo(hv, program));
                                        }
                                } else {
                                        ghidra.util.Msg.warn(this,
                                                        "Decompilation did not yield a HighFunction for function: "
                                                                        + function.getName());
                                }
                        }
                } catch (Exception e) {
                        // Log the error but continue with listing variables
                        ghidra.util.Msg.error(this,
                                        "Error during decompilation for ListFunctionVariables: " + e.getMessage(), e);
                } finally {
                        if (decomplib != null) {
                                decomplib.dispose();
                        }
                }

                List<FunctionVariableInfo> variablesToList = Stream.concat(listingVarStream, decompilerVarStream)
                                .sorted(Comparator.comparing(FunctionVariableInfo::getStorage)
                                                .thenComparing(FunctionVariableInfo::getEffectiveName))
                                .collect(Collectors.toList());

                final String finalCursorStr = cursorOpt.orElse(null);

                List<FunctionVariableInfo> paginatedVariables = variablesToList.stream()
                                .dropWhile(varInfo -> {
                                        if (finalCursorStr == null)
                                                return false;

                                        String[] parts = finalCursorStr.split(":", 2);
                                        String cursorStorage = parts[0];
                                        String cursorName = parts.length > 1 ? parts[1] : "";

                                        int storageCompare = varInfo.getStorage().compareTo(cursorStorage);
                                        if (storageCompare < 0)
                                                return true;
                                        if (storageCompare == 0) {
                                                return varInfo.getEffectiveName().compareTo(cursorName) <= 0;
                                        }
                                        return false;
                                })
                                .limit(DEFAULT_PAGE_LIMIT + 1)
                                .collect(Collectors.toList());

                boolean hasMore = paginatedVariables.size() > DEFAULT_PAGE_LIMIT;
                List<FunctionVariableInfo> resultsForPage = paginatedVariables.subList(0,
                                Math.min(paginatedVariables.size(), DEFAULT_PAGE_LIMIT));
                String nextCursor = null;
                if (hasMore && !resultsForPage.isEmpty()) {
                        FunctionVariableInfo lastItem = resultsForPage.get(resultsForPage.size() - 1);
                        nextCursor = lastItem.getStorage() + ":" + lastItem.getEffectiveName();
                }

                return new PaginatedResult<>(resultsForPage, nextCursor);
        }

        private void ensureArgumentPresent(Map<String, Object> args, String argumentName, String toolOperation)
                        throws GhidraMcpException {
                if (!args.containsKey(argumentName) || args.get(argumentName) == null) {
                        GhidraMcpError error = GhidraMcpError.validation()
                                        .errorCode(GhidraMcpError.ErrorCode.MISSING_REQUIRED_ARGUMENT)
                                        .message("Missing required argument: '" + argumentName + "'")
                                        .context(new GhidraMcpError.ErrorContext(
                                                        toolOperation,
                                                        "argument validation",
                                                        args,
                                                        Map.of(argumentName, "not provided"),
                                                        Map.of("required", true)))
                                        .suggestions(List.of(
                                                        new GhidraMcpError.ErrorSuggestion(
                                                                        GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
                                                                        "Provide the '" + argumentName + "' argument",
                                                                        "Include the " + argumentName
                                                                                        + " field with a valid value",
                                                                        List.of("\"" + argumentName
                                                                                        + "\": \"example_value\""),
                                                                        null)))
                                        .build();
                        throw new GhidraMcpException(error);
                }
        }

        private GhidraMcpError createFunctionNotFoundError(String toolOperation, String searchType,
                        String searchValue) {
                return GhidraMcpError.validation()
                                .errorCode(GhidraMcpError.ErrorCode.FUNCTION_NOT_FOUND)
                                .message("Function not found using " + searchType + ": " + searchValue)
                                .context(new GhidraMcpError.ErrorContext(
                                                toolOperation,
                                                "function resolution",
                                                Map.of(searchType, searchValue),
                                                Map.of(),
                                                Map.of("searchMethod", searchType)))
                                .suggestions(List.of(
                                                new GhidraMcpError.ErrorSuggestion(
                                                                GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
                                                                "Verify the function exists",
                                                                "Check that the function identifier is correct",
                                                                List.of(
                                                                                "\"symbol_id\": 12345",
                                                                                "\"address\": \"0x401000\"",
                                                                                "\"name\": \"main\""),
                                                                null)))
                                .build();
        }

        private GhidraMcpError createMultipleFunctionsFoundError(String toolOperation, String searchValue,
                        List<Function> functions) {
                List<String> functionNames = functions.stream()
                                .map(Function::getName)
                                .limit(5)
                                .collect(Collectors.toList());

                return GhidraMcpError.validation()
                                .errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
                                .message("Multiple functions found for name pattern: " + searchValue)
                                .context(new GhidraMcpError.ErrorContext(
                                                toolOperation,
                                                "function resolution",
                                                Map.of("name", searchValue),
                                                Map.of("matchCount", functions.size()),
                                                Map.of("firstFiveMatches", functionNames)))
                                .suggestions(List.of(
                                                new GhidraMcpError.ErrorSuggestion(
                                                                GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
                                                                "Use a more specific function identifier",
                                                                "Consider using symbol_id or address for exact identification",
                                                                List.of(
                                                                                "\"symbol_id\": 12345",
                                                                                "\"address\": \"0x401000\"",
                                                                                "\"name\": \"exact_function_name\""),
                                                                null)))
                                .build();
        }

        private GhidraMcpError createInvalidAddressError(String addressStr, Exception cause) {
                return GhidraMcpError.validation()
                                .errorCode(GhidraMcpError.ErrorCode.ADDRESS_PARSE_FAILED)
                                .message("Invalid address format: " + addressStr)
                                .context(new GhidraMcpError.ErrorContext(
                                                this.getClass().getAnnotation(GhidraMcpTool.class).mcpName(),
                                                "address parsing",
                                                Map.of(ARG_ADDRESS, addressStr),
                                                Map.of(),
                                                Map.of("parseError", cause.getMessage())))
                                .suggestions(List.of(
                                                new GhidraMcpError.ErrorSuggestion(
                                                                GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
                                                                "Use valid hexadecimal address format",
                                                                "Provide address in proper format",
                                                                List.of("0x401000", "401000", "0x00401000"),
                                                                null)))
                                .build();
        }

        private GhidraMcpError createInvalidRegexError(String pattern, Exception cause) {
                return GhidraMcpError.validation()
                                .errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
                                .message("Invalid regex pattern: " + cause.getMessage())
                                .context(new GhidraMcpError.ErrorContext(
                                                this.getClass().getAnnotation(GhidraMcpTool.class).mcpName(),
                                                "regex compilation",
                                                Map.of(ARG_NAME, pattern),
                                                Map.of(),
                                                Map.of("regexError", cause.getMessage())))
                                .suggestions(List.of(
                                                new GhidraMcpError.ErrorSuggestion(
                                                                GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
                                                                "Provide a valid Java regex pattern",
                                                                "Use proper regex syntax for pattern matching",
                                                                List.of(".*main.*", "decrypt_.*", "^get.*"),
                                                                null)))
                                .build();
        }

        private GhidraMcpError createMissingParameterError() {
                return GhidraMcpError.validation()
                                .errorCode(GhidraMcpError.ErrorCode.MISSING_REQUIRED_ARGUMENT)
                                .message("No search parameters provided")
                                .context(new GhidraMcpError.ErrorContext(
                                                this.getClass().getAnnotation(GhidraMcpTool.class).mcpName(),
                                                "parameter validation",
                                                Map.of(),
                                                Map.of(),
                                                Map.of("availableParameters",
                                                                List.of(ARG_SYMBOL_ID, ARG_ADDRESS, ARG_NAME))))
                                .suggestions(List.of(
                                                new GhidraMcpError.ErrorSuggestion(
                                                                GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
                                                                "Provide at least one search parameter",
                                                                "Use symbol_id, address, or name parameter",
                                                                List.of(
                                                                                "\"symbol_id\": 12345",
                                                                                "\"address\": \"0x401000\"",
                                                                                "\"name\": \"main\"",
                                                                                "\"name\": \".*decrypt.*\""),
                                                                null)))
                                .build();
        }

        private Mono<? extends Object> handleGetGraph(Program program, Map<String, Object> args,
                        GhidraMcpTool annotation) {
                String toolOperation = annotation.mcpName() + ".get_graph";

                // Extract function identifiers from both direct arguments and
                // target_type/target_value
                FunctionIdentifiers identifiers = extractFunctionIdentifiers(args);

                if (identifiers.isEmpty()) {
                        return Mono.error(new GhidraMcpException(createMissingIdentifierError(annotation, args)));
                }

                return Mono.fromCallable(() -> {
                        Function function = resolveFunctionByIdentifiers(program, identifiers, annotation, args,
                                        toolOperation);
                        return buildFunctionGraph(program, function);
                });
        }

        private FunctionGraph buildFunctionGraph(Program program, Function function) throws GhidraMcpException {
                CodeBlockModel model = new BasicBlockModel(program);
                AddressSetView body = function.getBody();

                Map<String, FunctionGraphNode> idToNode = new LinkedHashMap<>();
                List<FunctionGraphEdge> edges = new ArrayList<>();

                try {
                        // Use TaskMonitor.DUMMY instead of null
                        TaskMonitor monitor = TaskMonitor.DUMMY;
                        CodeBlockIterator blocks = model.getCodeBlocksContaining(body, monitor);
                        int index = 0;
                        Map<Address, String> startToId = new HashMap<>();
                        List<CodeBlock> blockList = new ArrayList<>();

                        while (blocks.hasNext()) {
                                CodeBlock b = blocks.next();
                                blockList.add(b);
                                String nodeId = "B" + index++;
                                startToId.put(b.getFirstStartAddress(), nodeId);
                                String range = b.getMinAddress() + "-" + b.getMaxAddress();
                                String label = b.getFirstStartAddress().toString();
                                idToNode.put(nodeId, new FunctionGraphNode(nodeId, range, label));
                        }

                        for (CodeBlock b : blockList) {
                                String srcId = startToId.get(b.getFirstStartAddress());
                                CodeBlockReferenceIterator dests = b.getDestinations(monitor);
                                while (dests.hasNext()) {
                                        CodeBlockReference ref = dests.next();
                                        CodeBlock dest = ref.getDestinationBlock();
                                        String dstId = startToId.get(dest.getFirstStartAddress());
                                        if (dstId != null) {
                                                String type = ref.getFlowType().toString();
                                                edges.add(new FunctionGraphEdge(srcId, dstId, type));
                                        }
                                }
                        }
                } catch (Exception e) {
                        GhidraMcpError error = GhidraMcpError.internal()
                                        .errorCode(GhidraMcpError.ErrorCode.UNEXPECTED_ERROR)
                                        .message("Failed to build function graph: " + e.getMessage())
                                        .context(new GhidraMcpError.ErrorContext(
                                                        this.getClass().getAnnotation(GhidraMcpTool.class).mcpName(),
                                                        "function graph construction",
                                                        Map.of("functionName", function.getName()),
                                                        Map.of("error", e.getMessage()),
                                                        Map.of("graphBuildFailed", true)))
                                        .build();
                        throw new GhidraMcpException(error);
                }

                List<FunctionGraphNode> nodes = new ArrayList<>(idToNode.values());
                String funcName = function.getName(true);
                String funcAddr = function.getEntryPoint() != null ? function.getEntryPoint().toString() : null;
                return new FunctionGraph(funcName, funcAddr, nodes, edges);
        }

        /**
         * Creates a comprehensive data type error with rich context and suggestions.
         * Provides actionable guidance for resolving data type issues.
         */
        private GhidraMcpError createDataTypeError(GhidraMcpError.ErrorCode errorCode, String message,
                        String context, Map<String, Object> args,
                        String failedTypeName) {
                GhidraMcpError.Builder errorBuilder = GhidraMcpError.dataTypeParsing()
                                .errorCode(errorCode)
                                .message(message);

                // Add context information
                GhidraMcpError.ErrorContext errorContext = new GhidraMcpError.ErrorContext(
                                this.getMcpName(),
                                context,
                                args,
                                Map.of("failedTypeName", failedTypeName),
                                Map.of());
                errorBuilder.context(errorContext);

                // Add suggestions based on the failed type name
                List<GhidraMcpError.ErrorSuggestion> suggestions = generateDataTypeSuggestions(failedTypeName);
                errorBuilder.suggestions(suggestions);

                return errorBuilder.build();
        }

        /**
         * Generates contextual suggestions for data type resolution failures.
         */
        private List<GhidraMcpError.ErrorSuggestion> generateDataTypeSuggestions(String failedTypeName) {
                List<GhidraMcpError.ErrorSuggestion> suggestions = new ArrayList<>();
                String lowerName = failedTypeName.toLowerCase();

                // Type-specific suggestions
                if (lowerName.contains("ulonglong") || lowerName.contains("unsigned_long_long")) {
                        suggestions.add(new GhidraMcpError.ErrorSuggestion(
                                        GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
                                        "Use correct 64-bit unsigned type",
                                        "For 64-bit unsigned integers",
                                        List.of("ulonglong", "unsigned long long"),
                                        null));
                } else if (lowerName.contains("ulong") || lowerName.contains("unsigned_long")) {
                        suggestions.add(new GhidraMcpError.ErrorSuggestion(
                                        GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
                                        "Specify bit width for unsigned long",
                                        "Choose appropriate size",
                                        List.of("ulonglong (64-bit)", "uint (32-bit)"),
                                        null));
                } else if (lowerName.contains("uint") || lowerName.contains("unsigned_int")) {
                        suggestions.add(new GhidraMcpError.ErrorSuggestion(
                                        GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
                                        "Use correct 32-bit unsigned type",
                                        "For 32-bit unsigned integers",
                                        List.of("uint", "unsigned int"),
                                        null));
                }

                // General suggestions
                suggestions.add(new GhidraMcpError.ErrorSuggestion(
                                GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
                                "Try common built-in types",
                                "Use standard C primitive types",
                                List.of("int", "uint", "long", "ulonglong", "float", "double", "void", "char", "uchar"),
                                null));

                return suggestions;
        }
}
