package com.themixednuts;

import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.ServiceLoader;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.tools.IGhidraMcpSpecification;
import ghidra.framework.model.Project;
import ghidra.framework.options.OptionType;
import ghidra.framework.options.ToolOptions;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpServerFeatures.AsyncToolSpecification;

public class GhidraMcpTools {
	private final Project project;
	private static final String OPTIONS_ANCHOR = "GhidraMcpTools";

	public GhidraMcpTools(Project project) {
		this.project = project;
	}

	public List<AsyncToolSpecification> getTools() throws JsonProcessingException {
		ServiceLoader<IGhidraMcpSpecification> loader = ServiceLoader.load(IGhidraMcpSpecification.class);

		return loader.stream()
				.map(provider -> {
					IGhidraMcpSpecification toolInstance = null;
					try {
						toolInstance = provider.get();
						return toolInstance.specification(this.project);
					} catch (Exception e) {
						String className = (toolInstance != null) ? toolInstance.getClass().getSimpleName()
								: provider.type().getSimpleName();
						Msg.error(GhidraMcpTools.class,
								"Error getting specification for tool: " + className, e);
						return null;
					}
				})
				.filter(Objects::nonNull)
				.collect(Collectors.toList());
	}

	public static void registerOptions(ToolOptions options, String topic) {
		HelpLocation help = new HelpLocation(topic, OPTIONS_ANCHOR);
		ServiceLoader<IGhidraMcpSpecification> loader = ServiceLoader.load(IGhidraMcpSpecification.class);

		for (ServiceLoader.Provider<IGhidraMcpSpecification> provider : loader.stream().toList()) {
			Class<? extends IGhidraMcpSpecification> toolClass = provider.type();
			try {
				GhidraMcpTool toolAnnotation = toolClass.getAnnotation(GhidraMcpTool.class);
				if (toolAnnotation == null) {
					Msg.warn(GhidraMcpTools.class,
							"Tool class " + toolClass.getSimpleName() +
									" is missing the @GhidraMcpTool annotation. Skipping option registration.");
					continue;
				}

				String baseKey = toolAnnotation.key();
				String desc = toolAnnotation.description();
				String category = toolAnnotation.category();

				String fullKey = baseKey;
				if (category != null && !category.trim().isEmpty()) {
					fullKey = category.trim() + "." + baseKey;
				}

				options.registerOption(fullKey, OptionType.BOOLEAN_TYPE, true, help, desc);

			} catch (SecurityException e) {
				Msg.error(GhidraMcpTools.class,
						"Security exception accessing annotation for tool: " + toolClass.getSimpleName(),
						e);
			} catch (Exception e) {
				Msg.error(GhidraMcpTools.class,
						"Error processing options for tool: " + toolClass.getSimpleName(),
						e);
			}
		}
	}

	// private String listExports(int offset, int limit) {
	// Program program = getCurrentProgram();
	// if (program == null) return "No program loaded";

	// SymbolTable table = program.getSymbolTable();
	// SymbolIterator it = table.getAllSymbols(true);

	// List<String> lines = new ArrayList<>();
	// while (it.hasNext()) {
	// Symbol s = it.next();
	// // On older Ghidra, "export" is recognized via isExternalEntryPoint()
	// if (s.isExternalEntryPoint()) {
	// lines.add(s.getName() + " -> " + s.getAddress());
	// }
	// }
	// return paginateList(lines, offset, limit);
	// }
	// ----------------------------------------------------------------------------------
	// // Logic for rename, decompile, etc.
	// //
	// ----------------------------------------------------------------------------------

	// private void renameDataAtAddress(String addressStr, String newName) {
	// Program program = getCurrentProgram();
	// if (program == null) return;

	// try {
	// SwingUtilities.invokeAndWait(() -> {
	// int tx = program.startTransaction("Rename data");
	// try {
	// Address addr = program.getAddressFactory().getAddress(addressStr);
	// Listing listing = program.getListing();
	// Data data = listing.getDefinedDataAt(addr);
	// if (data != null) {
	// SymbolTable symTable = program.getSymbolTable();
	// Symbol symbol = symTable.getPrimarySymbol(addr);
	// if (symbol != null) {
	// symbol.setName(newName, SourceType.USER_DEFINED);
	// } else {
	// symTable.createLabel(addr, newName, SourceType.USER_DEFINED);
	// }
	// }
	// }
	// catch (Exception e) {
	// Msg.error(this, "Rename data error", e);
	// }
	// finally {
	// program.endTransaction(tx, true);
	// }
	// });
	// }
	// catch (InterruptedException | InvocationTargetException e) {
	// Msg.error(this, "Failed to execute rename data on Swing thread", e);
	// }
	// }

	// private String renameVariableInFunction(String functionName, String
	// oldVarName, String newVarName) {
	// Program program = getCurrentProgram();
	// if (program == null) return "No program loaded";

	// DecompInterface decomp = new DecompInterface();
	// decomp.openProgram(program);

	// Function func = null;
	// for (Function f : program.getFunctionManager().getFunctions(true)) {
	// if (f.getName().equals(functionName)) {
	// func = f;
	// break;
	// }
	// }

	// if (func == null) {
	// return "Function not found";
	// }

	// DecompileResults result = decomp.decompileFunction(func, 30, new
	// ConsoleTaskMonitor());
	// if (result == null || !result.decompileCompleted()) {
	// return "Decompilation failed";
	// }

	// HighFunction highFunction = result.getHighFunction();
	// if (highFunction == null) {
	// return "Decompilation failed (no high function)";
	// }

	// LocalSymbolMap localSymbolMap = highFunction.getLocalSymbolMap();
	// if (localSymbolMap == null) {
	// return "Decompilation failed (no local symbol map)";
	// }

	// HighSymbol highSymbol = null;
	// Iterator<HighSymbol> symbols = localSymbolMap.getSymbols();
	// while (symbols.hasNext()) {
	// HighSymbol symbol = symbols.next();
	// String symbolName = symbol.getName();

	// if (symbolName.equals(oldVarName)) {
	// highSymbol = symbol;
	// }
	// if (symbolName.equals(newVarName)) {
	// return "Error: A variable with name '" + newVarName + "' already exists in
	// this function";
	// }
	// }

	// if (highSymbol == null) {
	// return "Variable not found";
	// }

	// boolean commitRequired = checkFullCommit(highSymbol, highFunction);

	// final HighSymbol finalHighSymbol = highSymbol;
	// final Function finalFunction = func;
	// AtomicBoolean successFlag = new AtomicBoolean(false);

	// try {
	// SwingUtilities.invokeAndWait(() -> {
	// int tx = program.startTransaction("Rename variable");
	// try {
	// if (commitRequired) {
	// HighFunctionDBUtil.commitParamsToDatabase(highFunction, false,
	// ReturnCommitOption.NO_COMMIT, finalFunction.getSignatureSource());
	// }
	// HighFunctionDBUtil.updateDBVariable(
	// finalHighSymbol,
	// newVarName,
	// null,
	// SourceType.USER_DEFINED
	// );
	// successFlag.set(true);
	// }
	// catch (Exception e) {
	// Msg.error(this, "Failed to rename variable", e);
	// }
	// finally {
	// program.endTransaction(tx, true);
	// }
	// });
	// } catch (InterruptedException | InvocationTargetException e) {
	// String errorMsg = "Failed to execute rename on Swing thread: " +
	// e.getMessage();
	// Msg.error(this, errorMsg, e);
	// return errorMsg;
	// }
	// return successFlag.get() ? "Variable renamed" : "Failed to rename variable";
	// }

	// /**
	// * Copied from AbstractDecompilerAction.checkFullCommit, it's protected.
	// * Compare the given HighFunction's idea of the prototype with the Function's
	// idea.
	// * Return true if there is a difference. If a specific symbol is being
	// changed,
	// * it can be passed in to check whether or not the prototype is being
	// affected.
	// * @param highSymbol (if not null) is the symbol being modified
	// * @param hfunction is the given HighFunction
	// * @return true if there is a difference (and a full commit is required)
	// */
	// protected static boolean checkFullCommit(HighSymbol highSymbol, HighFunction
	// hfunction) {
	// if (highSymbol != null && !highSymbol.isParameter()) {
	// return false;
	// }
	// Function function = hfunction.getFunction();
	// Parameter[] parameters = function.getParameters();
	// LocalSymbolMap localSymbolMap = hfunction.getLocalSymbolMap();
	// int numParams = localSymbolMap.getNumParams();
	// if (numParams != parameters.length) {
	// return true;
	// }

	// for (int i = 0; i < numParams; i++) {
	// HighSymbol param = localSymbolMap.getParamSymbol(i);
	// if (param.getCategoryIndex() != i) {
	// return true;
	// }
	// VariableStorage storage = param.getStorage();
	// // Don't compare using the equals method so that DynamicVariableStorage can
	// match
	// if (0 != storage.compareTo(parameters[i].getVariableStorage())) {
	// return true;
	// }
	// }

	// return false;
	// }

	// //
	// ----------------------------------------------------------------------------------
	// // New methods to implement the new functionalities
	// //
	// ----------------------------------------------------------------------------------

	// /**
	// * Get current function selected in Ghidra GUI
	// */
	// private String getCurrentFunction() {
	// CodeViewerService service = tool.getService(CodeViewerService.class);
	// if (service == null) return "Code viewer service not available";

	// ProgramLocation location = service.getCurrentLocation();
	// if (location == null) return "No current location";

	// Program program = getCurrentProgram();
	// if (program == null) return "No program loaded";

	// Function func =
	// program.getFunctionManager().getFunctionContaining(location.getAddress());
	// if (func == null) return "No function at current location: " +
	// location.getAddress();

	// return String.format("Function: %s at %s\nSignature: %s",
	// func.getName(),
	// func.getEntryPoint(),
	// func.getSignature());
	// }

	// /**
	// * List all functions in the database
	// */
	// private String listFunctions() {
	// Program program = getCurrentProgram();
	// if (program == null) return "No program loaded";

	// StringBuilder result = new StringBuilder();
	// for (Function func : program.getFunctionManager().getFunctions(true)) {
	// result.append(String.format("%s at %s\n",
	// func.getName(),
	// func.getEntryPoint()));
	// }

	// return result.toString();
	// }

	// /**
	// * Gets a function at the given address or containing the address
	// * @return the function or null if not found
	// */
	// private Function getFunctionForAddress(Program program, Address addr) {
	// Function func = program.getFunctionManager().getFunctionAt(addr);
	// if (func == null) {
	// func = program.getFunctionManager().getFunctionContaining(addr);
	// }
	// return func;
	// }

	// /**
	// * Decompile a function at the given address
	// */
	// private String decompileFunctionByAddress(String addressStr) {
	// Program program = getCurrentProgram();
	// if (program == null) return "No program loaded";
	// if (addressStr == null || addressStr.isEmpty()) return "Address is required";

	// try {
	// Address addr = program.getAddressFactory().getAddress(addressStr);
	// Function func = getFunctionForAddress(program, addr);
	// if (func == null) return "No function found at or containing address " +
	// addressStr;

	// DecompInterface decomp = new DecompInterface();
	// decomp.openProgram(program);
	// DecompileResults result = decomp.decompileFunction(func, 30, new
	// ConsoleTaskMonitor());

	// return (result != null && result.decompileCompleted())
	// ? result.getDecompiledFunction().getC()
	// : "Decompilation failed";
	// } catch (Exception e) {
	// return "Error decompiling function: " + e.getMessage();
	// }
	// }

	// /**
	// * Get assembly code for a function
	// */
	// private String disassembleFunction(String addressStr) {
	// Program program = getCurrentProgram();
	// if (program == null) return "No program loaded";
	// if (addressStr == null || addressStr.isEmpty()) return "Address is required";

	// try {
	// Address addr = program.getAddressFactory().getAddress(addressStr);
	// Function func = getFunctionForAddress(program, addr);
	// if (func == null) return "No function found at or containing address " +
	// addressStr;

	// StringBuilder result = new StringBuilder();
	// Listing listing = program.getListing();
	// Address start = func.getEntryPoint();
	// Address end = func.getBody().getMaxAddress();

	// InstructionIterator instructions = listing.getInstructions(start, true);
	// while (instructions.hasNext()) {
	// Instruction instr = instructions.next();
	// if (instr.getAddress().compareTo(end) > 0) {
	// break; // Stop if we've gone past the end of the function
	// }
	// String comment = listing.getComment(CodeUnit.EOL_COMMENT,
	// instr.getAddress());
	// comment = (comment != null) ? "; " + comment : "";

	// result.append(String.format("%s: %s %s\n",
	// instr.getAddress(),
	// instr.toString(),
	// comment));
	// }

	// return result.toString();
	// } catch (Exception e) {
	// return "Error disassembling function: " + e.getMessage();
	// }
	// }

	// /**
	// * Set a comment using the specified comment type (PRE_COMMENT or EOL_COMMENT)
	// */
	// private boolean setCommentAtAddress(String addressStr, String comment, int
	// commentType, String transactionName) {
	// Program program = getCurrentProgram();
	// if (program == null) return false;
	// if (addressStr == null || addressStr.isEmpty() || comment == null) return
	// false;

	// AtomicBoolean success = new AtomicBoolean(false);

	// try {
	// SwingUtilities.invokeAndWait(() -> {
	// int tx = program.startTransaction(transactionName);
	// try {
	// Address addr = program.getAddressFactory().getAddress(addressStr);
	// program.getListing().setComment(addr, commentType, comment);
	// success.set(true);
	// } catch (Exception e) {
	// Msg.error(this, "Error setting " + transactionName.toLowerCase(), e);
	// } finally {
	// program.endTransaction(tx, success.get());
	// }
	// });
	// } catch (InterruptedException | InvocationTargetException e) {
	// Msg.error(this, "Failed to execute " + transactionName.toLowerCase() + " on
	// Swing thread", e);
	// }

	// return success.get();
	// }

	// /**
	// * Set a comment for a given address in the function pseudocode
	// */
	// private boolean setDecompilerComment(String addressStr, String comment) {
	// return setCommentAtAddress(addressStr, comment, CodeUnit.PRE_COMMENT, "Set
	// decompiler comment");
	// }

	// /**
	// * Set a comment for a given address in the function disassembly
	// */
	// private boolean setDisassemblyComment(String addressStr, String comment) {
	// return setCommentAtAddress(addressStr, comment, CodeUnit.EOL_COMMENT, "Set
	// disassembly comment");
	// }

	// /**
	// * Class to hold the result of a prototype setting operation
	// */
	// private static class PrototypeResult {
	// private final boolean success;
	// private final String errorMessage;

	// public PrototypeResult(boolean success, String errorMessage) {
	// this.success = success;
	// this.errorMessage = errorMessage;
	// }

	// public boolean isSuccess() {
	// return success;
	// }

	// public String getErrorMessage() {
	// return errorMessage;
	// }
	// }

	// /**
	// * Helper method to perform the actual function rename within a transaction
	// */
	// private void performFunctionRename(Program program, String functionAddrStr,
	// String newName, AtomicBoolean success) {
	// int tx = program.startTransaction("Rename function by address");
	// try {
	// Address addr = program.getAddressFactory().getAddress(functionAddrStr);
	// Function func = getFunctionForAddress(program, addr);

	// if (func == null) {
	// Msg.error(this, "Could not find function at address: " + functionAddrStr);
	// return;
	// }

	// func.setName(newName, SourceType.USER_DEFINED);
	// success.set(true);
	// } catch (Exception e) {
	// Msg.error(this, "Error renaming function by address", e);
	// } finally {
	// program.endTransaction(tx, success.get());
	// }
	// }

	// /**
	// * Set a function's prototype with proper error handling using
	// ApplyFunctionSignatureCmd
	// */
	// private PrototypeResult setFunctionPrototype(String functionAddrStr, String
	// prototype) {
	// // Input validation
	// Program program = getCurrentProgram();
	// if (program == null) return new PrototypeResult(false, "No program loaded");
	// if (functionAddrStr == null || functionAddrStr.isEmpty()) {
	// return new PrototypeResult(false, "Function address is required");
	// }
	// if (prototype == null || prototype.isEmpty()) {
	// return new PrototypeResult(false, "Function prototype is required");
	// }

	// final StringBuilder errorMessage = new StringBuilder();
	// final AtomicBoolean success = new AtomicBoolean(false);

	// try {
	// SwingUtilities.invokeAndWait(() ->
	// applyFunctionPrototype(program, functionAddrStr, prototype, success,
	// errorMessage));
	// } catch (InterruptedException | InvocationTargetException e) {
	// String msg = "Failed to set function prototype on Swing thread: " +
	// e.getMessage();
	// errorMessage.append(msg);
	// Msg.error(this, msg, e);
	// }

	// return new PrototypeResult(success.get(), errorMessage.toString());
	// }

	// /**
	// * Helper method that applies the function prototype within a transaction
	// */
	// private void applyFunctionPrototype(Program program, String functionAddrStr,
	// String prototype,
	// AtomicBoolean success, StringBuilder errorMessage) {
	// try {
	// // Get the address and function
	// Address addr = program.getAddressFactory().getAddress(functionAddrStr);
	// Function func = getFunctionForAddress(program, addr);

	// if (func == null) {
	// String msg = "Could not find function at address: " + functionAddrStr;
	// errorMessage.append(msg);
	// Msg.error(this, msg);
	// return;
	// }

	// Msg.info(this, "Setting prototype for function " + func.getName() + ": " +
	// prototype);

	// // Store original prototype as a comment for reference
	// addPrototypeComment(program, func, prototype);

	// // Use ApplyFunctionSignatureCmd to parse and apply the signature
	// parseFunctionSignatureAndApply(program, addr, prototype, success,
	// errorMessage);

	// } catch (Exception e) {
	// String msg = "Error setting function prototype: " + e.getMessage();
	// errorMessage.append(msg);
	// Msg.error(this, msg, e);
	// }
	// }

	// /**
	// * Add a comment showing the prototype being set
	// */
	// private void addPrototypeComment(Program program, Function func, String
	// prototype) {
	// int txComment = program.startTransaction("Add prototype comment");
	// try {
	// program.getListing().setComment(
	// func.getEntryPoint(),
	// CodeUnit.PLATE_COMMENT,
	// "Setting prototype: " + prototype
	// );
	// } finally {
	// program.endTransaction(txComment, true);
	// }
	// }

	// /**
	// * Parse and apply the function signature with error handling
	// */
	// private void parseFunctionSignatureAndApply(Program program, Address addr,
	// String prototype,
	// AtomicBoolean success, StringBuilder errorMessage) {
	// // Use ApplyFunctionSignatureCmd to parse and apply the signature
	// int txProto = program.startTransaction("Set function prototype");
	// try {
	// // Get data type manager
	// DataTypeManager dtm = program.getDataTypeManager();

	// // Get data type manager service
	// ghidra.app.services.DataTypeManagerService dtms =
	// tool.getService(ghidra.app.services.DataTypeManagerService.class);

	// // Create function signature parser
	// ghidra.app.util.parser.FunctionSignatureParser parser =
	// new ghidra.app.util.parser.FunctionSignatureParser(dtm, dtms);

	// // Parse the prototype into a function signature
	// ghidra.program.model.data.FunctionDefinitionDataType sig = parser.parse(null,
	// prototype);

	// if (sig == null) {
	// String msg = "Failed to parse function prototype";
	// errorMessage.append(msg);
	// Msg.error(this, msg);
	// return;
	// }

	// // Create and apply the command
	// ghidra.app.cmd.function.ApplyFunctionSignatureCmd cmd =
	// new ghidra.app.cmd.function.ApplyFunctionSignatureCmd(
	// addr, sig, SourceType.USER_DEFINED);

	// // Apply the command to the program
	// boolean cmdResult = cmd.applyTo(program, new ConsoleTaskMonitor());

	// if (cmdResult) {
	// success.set(true);
	// Msg.info(this, "Successfully applied function signature");
	// } else {
	// String msg = "Command failed: " + cmd.getStatusMsg();
	// errorMessage.append(msg);
	// Msg.error(this, msg);
	// }
	// } catch (Exception e) {
	// String msg = "Error applying function signature: " + e.getMessage();
	// errorMessage.append(msg);
	// Msg.error(this, msg, e);
	// } finally {
	// program.endTransaction(txProto, success.get());
	// }
	// }

	// /**
	// * List all defined strings in the program with their addresses
	// */
	// private String listDefinedStrings(int offset, int limit, String filter) {
	// Program program = getCurrentProgram();
	// if (program == null) return "No program loaded";

	// List<String> lines = new ArrayList<>();
	// DataIterator dataIt = program.getListing().getDefinedData(true);

	// TaskMonitor monitor = new ConsoleTaskMonitor();
	// int currentIndex = 0;
	// int count = 0;

	// try {
	// while (dataIt.hasNext()) {
	// if (monitor.isCancelled()) break;
	// Data data = dataIt.next();

	// if (data != null && isStringData(data)) {
	// String value = data.getValue() != null ? data.getValue().toString() : "";

	// if (filter == null || value.toLowerCase().contains(filter.toLowerCase())) {
	// String escapedValue = escapeString(value);
	// // Check pagination limits *before* adding to list
	// if (currentIndex >= offset && count < limit) {
	// lines.add(String.format("%s: \"%s\"", data.getAddress(), escapedValue));
	// count++;
	// }
	// currentIndex++; // Increment index for every string
	// }
	// }
	// monitor.incrementProgress(1); // Indicate progress
	// }
	// } catch (Exception e) {
	// Msg.error(this, "Error listing defined strings", e);
	// return "Error listing defined strings: " + e.getMessage();
	// }

	// return paginateList(lines, offset, limit);
	// }

	// /**
	// * Check if the given data is a string type
	// */
	// private boolean isStringData(Data data) {
	// if (data == null) return false;

	// DataType dt = data.getDataType();
	// String typeName = dt.getName().toLowerCase();
	// return typeName.contains("string") || typeName.contains("char") ||
	// typeName.equals("unicode");
	// }

	// //
	// ----------------------------------------------------------------------------------
	// // Utility: parse query params, parse post params, pagination, etc.
	// //
	// ----------------------------------------------------------------------------------

	// /**
	// * Parse query parameters from the URL, e.g. ?offset=10&limit=100
	// */
	// private Map<String, String> parseQueryParams(HttpExchange exchange) {
	// Map<String, String> result = new HashMap<>();
	// String query = exchange.getRequestURI().getQuery(); // e.g.
	// offset=10&limit=100
	// if (query != null) {
	// String[] pairs = query.split("&");
	// for (String p : pairs) {
	// String[] kv = p.split("=");
	// if (kv.length == 2) {
	// // URL decode parameter values
	// try {
	// String key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
	// String value = URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
	// result.put(key, value);
	// } catch (Exception e) {
	// Msg.error(this, "Error decoding URL parameter", e);
	// }
	// }
	// }
	// }
	// return result;
	// }

	// /**
	// * Parse post body form params, e.g. oldName=foo&newName=bar
	// */
	// private Map<String, String> parsePostParams(HttpExchange exchange) throws
	// IOException {
	// byte[] body = exchange.getRequestBody().readAllBytes();
	// String bodyStr = new String(body, StandardCharsets.UTF_8);
	// Map<String, String> params = new HashMap<>();
	// for (String pair : bodyStr.split("&")) {
	// String[] kv = pair.split("=");
	// if (kv.length == 2) {
	// // URL decode parameter values
	// try {
	// String key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
	// String value = URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
	// params.put(key, value);
	// } catch (Exception e) {
	// Msg.error(this, "Error decoding URL parameter", e);
	// }
	// }
	// }
	// return params;
	// }

	// /**
	// * Convert a list of strings into one big newline-delimited string, applying
	// offset & limit.
	// */
	// private String paginateList(List<String> items, int offset, int limit) {
	// int start = Math.max(0, offset);
	// int end = Math.min(items.size(), offset + limit);

	// if (start >= items.size()) {
	// return ""; // no items in range
	// }
	// List<String> sub = items.subList(start, end);
	// return String.join("\n", sub);
	// }

	// /**
	// * Parse an integer from a string, or return defaultValue if null/invalid.
	// */
	// private int parseIntOrDefault(String val, int defaultValue) {
	// if (val == null) return defaultValue;
	// try {
	// return Integer.parseInt(val);
	// }
	// catch (NumberFormatException e) {
	// return defaultValue;
	// }
	// }

	// /**
	// * Escape non-ASCII chars to avoid potential decode issues.
	// */
	// private String escapeNonAscii(String input) {
	// if (input == null) return "";
	// StringBuilder sb = new StringBuilder();
	// for (char c : input.toCharArray()) {
	// if (c >= 32 && c < 127) {
	// sb.append(c);
	// }
	// else {
	// sb.append("\\x");
	// sb.append(Integer.toHexString(c & 0xFF));
	// }
	// }
	// return sb.toString();
	// }

	// public Program getCurrentProgram() {
	// ProgramManager pm = tool.getService(ProgramManager.class);
	// return pm != null ? pm.getCurrentProgram() : null;
	// }

	// private void sendResponse(HttpExchange exchange, String response) throws
	// IOException {
	// byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
	// exchange.getResponseHeaders().set("Content-Type", "text/plain;
	// charset=utf-8");
	// exchange.sendResponseHeaders(200, bytes.length);
	// try (OutputStream os = exchange.getResponseBody()) {
	// os.write(bytes);
	// }
	// }

	// /**
	// * List all data types in the program, optionally filtering by name.
	// */
	// private String listDataTypes(int offset, int limit, String filter) {
	// Program program = getCurrentProgram();
	// if (program == null) return "No program loaded";

	// DataTypeManager dtm = program.getDataTypeManager();
	// List<String> typeNames = new ArrayList<>();
	// Iterator<DataType> allTypes = dtm.getAllDataTypes();

	// while (allTypes.hasNext()) {
	// DataType dt = allTypes.next();
	// String pathName = dt.getPathName(); // Use path name for uniqueness

	// // Apply filter if provided (case-insensitive substring match)
	// if (filter == null || pathName.toLowerCase().contains(filter.toLowerCase()))
	// {
	// typeNames.add(pathName);
	// }
	// }

	// // Sort for consistent results
	// Collections.sort(typeNames);

	// return paginateList(typeNames, offset, limit);
	// }

	// //
	// ----------------------------------------------------------------------------------
	// // New methods for Data Type Management
	// //
	// ----------------------------------------------------------------------------------

	// /**
	// * Get details about a data type (size, alignment, members for structures).
	// */
	// private String getDataTypeDetails(String typeName) {
	// Program program = getCurrentProgram();
	// if (program == null) return "No program loaded";
	// if (typeName == null || typeName.isEmpty()) return "Type name is required";

	// DataTypeManager dtm = program.getDataTypeManager();
	// DataType dt = findDataTypeByNameInAllCategories(dtm, typeName);

	// if (dt == null) {
	// return "Data type not found: " + typeName;
	// }

	// StringBuilder details = new StringBuilder();
	// details.append(String.format("Type: %s\n", dt.getPathName()));
	// details.append(String.format("Size: %d bytes\n", dt.getLength()));
	// details.append(String.format("Alignment: %d\n", dt.getAlignment()));
	// details.append(String.format("Description: %s\n", dt.getDescription() != null
	// ? dt.getDescription() : "(none)"));

	// if (dt instanceof Structure) {
	// Structure struct = (Structure) dt;
	// details.append(String.format("Structure Members (%d):\n",
	// struct.getNumComponents()));
	// for (DataTypeComponent component : struct.getComponents()) {
	// details.append(String.format(" Offset 0x%X: %s %s [%d bytes]\n",
	// component.getOffset(),
	// component.getDataType().getName(),
	// component.getFieldName() != null ? component.getFieldName() : "(unnamed)",
	// component.getLength()
	// ));
	// if (component.getComment() != null) {
	// details.append(String.format(" Comment: %s\n", component.getComment()));
	// }
	// }
	// // TODO: Add similar logic for Union if needed

	// return details.toString();
	// }

	// /**
	// * Create a new structure data type.
	// */
	// private boolean createStruct(String structPath, int size) {
	// Program program = getCurrentProgram();
	// if (program == null) return false;
	// if (structPath == null || structPath.isEmpty()) return false;

	// AtomicBoolean success = new AtomicBoolean(false);
	// DataTypeManager dtm = program.getDataTypeManager();

	// try {
	// SwingUtilities.invokeAndWait(() -> {
	// int tx = program.startTransaction("Create Structure");
	// try {
	// CategoryPath path = new CategoryPath(structPath);
	// String name = path.getName();
	// CategoryPath parentPath = path.getParent();
	// if (parentPath == null || parentPath.isRoot()) {
	// parentPath = CategoryPath.ROOT;
	// }

	// // Ensure category exists
	// Category category = dtm.createCategory(parentPath);
	// if (category == null) {
	// Msg.error(this, "Failed to create or get category: " + parentPath);
	// return; // Exit lambda
	// }

	// // Check if type already exists using the full path string
	// if (dtm.getDataType(structPath) != null) { // Use the original full path
	// string
	// Msg.warn(this, "Structure already exists: " + structPath);
	// success.set(true); // Count existing as success
	// return; // Exit lambda
	// }

	// // Create the structure within the correct category path
	// Structure struct = new StructureDataType(category.getCategoryPath(), name,
	// size, dtm);
	// // Add the new data type to the manager
	// DataType newDt = dtm.addDataType(struct,
	// DataTypeConflictHandler.DEFAULT_HANDLER);
	// if (newDt != null) { // Check if adding was successful
	// success.set(true);
	// } else {
	// Msg.error(this, "Failed to add new structure to data type manager: " +
	// structPath);
	// }
	// } catch (Exception e) {
	// Msg.error(this, "Error creating structure: " + structPath, e);
	// } finally {
	// program.endTransaction(tx, success.get());
	// }
	// });
	// } catch (InterruptedException | InvocationTargetException e) {
	// Msg.error(this, "Failed to execute create structure on Swing thread", e);
	// }
	// return success.get();
	// }

	// /**
	// * Add a member to an existing structure.
	// */
	// private boolean addStructMember(String structPath, Integer offset, String
	// memberName, String memberTypeName, int memberSize, String comment) {
	// Program program = getCurrentProgram();
	// if (program == null) return false;
	// if (structPath == null || structPath.isEmpty() || memberName == null ||
	// memberName.isEmpty() || memberTypeName == null || memberTypeName.isEmpty()) {
	// Msg.error(this, "Missing required parameters for adding struct member.");
	// return false;
	// }

	// AtomicBoolean success = new AtomicBoolean(false);
	// DataTypeManager dtm = program.getDataTypeManager();

	// try {
	// SwingUtilities.invokeAndWait(() -> {
	// int tx = program.startTransaction("Add Structure Member");
	// try {
	// DataType dt = findDataTypeByNameInAllCategories(dtm, structPath);
	// if (!(dt instanceof Structure)) {
	// Msg.error(this, "Data type is not a structure: " + structPath);
	// return; // Exit lambda
	// }
	// Structure struct = (Structure) dt;

	// DataType memberType = resolveDataType(dtm, memberTypeName);
	// if (memberType == null) {
	// Msg.error(this, "Could not resolve member data type: " + memberTypeName);
	// return; // Exit lambda
	// }

	// // Use provided size if > 0, otherwise use type's default size
	// int resolvedSize = (memberSize > 0) ? memberSize : memberType.getLength();
	// if (resolvedSize <= 0) {
	// // Cannot determine size, default to 1 byte? Or error?
	// Msg.error(this, "Could not determine size for member type: " + memberTypeName
	// + ". Please specify member_size.");
	// return; // Exit lambda
	// }

	// if (offset != null) {
	// // Insert at specific offset
	// struct.insert(offset, memberType, resolvedSize, memberName, comment);
	// } else {
	// // Add to the end
	// struct.add(memberType, resolvedSize, memberName, comment);
	// }

	// // Update the data type in the manager after modification
	// dtm.addDataType(struct, DataTypeConflictHandler.REPLACE_HANDLER);

	// success.set(true);
	// } catch (Exception e) {
	// Msg.error(this, "Error adding member to structure: " + structPath, e);
	// } finally {
	// program.endTransaction(tx, success.get());
	// }
	// });
	// } catch (InterruptedException | InvocationTargetException e) {
	// Msg.error(this, "Failed to execute add struct member on Swing thread", e);
	// }
	// return success.get();
	// }

	// /**
	// * Apply a data type to a memory address.
	// */
	// private boolean applyDataType(String addressStr, String typeName, int length)
	// {
	// Program program = getCurrentProgram();
	// if (program == null) return false;
	// if (addressStr == null || addressStr.isEmpty() || typeName == null ||
	// typeName.isEmpty() || length <= 0) {
	// return false;
	// }

	// AtomicBoolean success = new AtomicBoolean(false);
	// DataTypeManager dtm = program.getDataTypeManager();
	// Listing listing = program.getListing();

	// try {
	// SwingUtilities.invokeAndWait(() -> {
	// int tx = program.startTransaction("Apply Data Type");
	// try {
	// Address addr = program.getAddressFactory().getAddress(addressStr);
	// DataType dt = resolveDataType(dtm, typeName);

	// if (dt == null) {
	// Msg.error(this, "Could not resolve data type: " + typeName);
	// return; // Exit lambda
	// }

	// // Clear existing code/data units that would conflict
	// listing.clearCodeUnits(addr, addr.add(dt.getLength() * length - 1), false);

	// // Create the data unit
	// if (length == 1) {
	// listing.createData(addr, dt);
	// } else {
	// // Create an array
	// ghidra.program.model.data.ArrayDataType arrayDt = new
	// ghidra.program.model.data.ArrayDataType(dt, length, dt.getLength());
	// listing.createData(addr, arrayDt);
	// }

	// success.set(true);
	// } catch (Exception e) {
	// Msg.error(this, "Error applying data type at address: " + addressStr, e);
	// } finally {
	// program.endTransaction(tx, success.get());
	// }
	// });
	// } catch (InterruptedException | InvocationTargetException e) {
	// Msg.error(this, "Failed to execute apply data type on Swing thread", e);
	// }
	// return success.get();
	// }

	// /**
	// * Edit an existing structure member.
	// */
	// private boolean editStructMember(String structName, String memberName, String
	// newMemberName, String newMemberType, Integer newMemberSize, String
	// newComment) {
	// Program program = getCurrentProgram();
	// if (program == null) return false;
	// if (structName == null || structName.isEmpty() || memberName == null ||
	// memberName.isEmpty()) {
	// Msg.error(this, "Missing required parameters for editing struct member.");
	// return false;
	// }

	// AtomicBoolean success = new AtomicBoolean(false);
	// DataTypeManager dtm = program.getDataTypeManager();

	// try {
	// SwingUtilities.invokeAndWait(() -> {
	// int tx = program.startTransaction("Edit Structure Member");
	// try {
	// DataType dt = findDataTypeByNameInAllCategories(dtm, structName);
	// if (!(dt instanceof Structure)) {
	// Msg.error(this, "Data type is not a structure: " + structName);
	// return; // Exit lambda
	// }
	// Structure struct = (Structure) dt;

	// // Find the component by iterating through members
	// DataTypeComponent component = null;
	// for (DataTypeComponent c : struct.getComponents()) {
	// if (memberName.equals(c.getFieldName())) {
	// component = c;
	// break;
	// }
	// }

	// if (component == null) {
	// Msg.error(this, "Member not found in structure: " + memberName);
	// return; // Exit lambda
	// }

	// DataType newMemberTypeDt = resolveDataType(dtm, newMemberType);
	// if (newMemberTypeDt == null) {
	// Msg.error(this, "Could not resolve new member data type: " + newMemberType);
	// return; // Exit lambda
	// }

	// // Use provided size if > 0, otherwise use type's default size
	// int resolvedSize = (newMemberSize != null && newMemberSize > 0) ?
	// newMemberSize : newMemberTypeDt.getLength();
	// if (resolvedSize <= 0) {
	// // Cannot determine size, default to 1 byte? Or error?
	// Msg.error(this, "Could not determine size for new member type: " +
	// newMemberType + ". Please specify new_member_size.");
	// return; // Exit lambda
	// }

	// // Edit the member
	// struct.replace(component.getOffset(), newMemberTypeDt, resolvedSize,
	// newMemberName, newComment);

	// // Update the data type in the manager after modification
	// dtm.addDataType(struct, DataTypeConflictHandler.REPLACE_HANDLER);

	// success.set(true);
	// } catch (Exception e) {
	// Msg.error(this, "Error editing member in structure: " + structName, e);
	// } finally {
	// program.endTransaction(tx, success.get());
	// }
	// });
	// } catch (InterruptedException | InvocationTargetException e) {
	// Msg.error(this, "Failed to execute edit struct member on Swing thread", e);
	// }
	// return success.get();
	// }

	// /**
	// * Delete a structure member.
	// */
	// private boolean deleteStructMember(String structName, String memberName) {
	// Program program = getCurrentProgram();
	// if (program == null) return false;
	// if (structName == null || structName.isEmpty() || memberName == null ||
	// memberName.isEmpty()) {
	// Msg.error(this, "Missing required parameters for deleting struct member.");
	// return false;
	// }

	// AtomicBoolean success = new AtomicBoolean(false);
	// DataTypeManager dtm = program.getDataTypeManager();

	// try {
	// SwingUtilities.invokeAndWait(() -> {
	// int tx = program.startTransaction("Delete Structure Member");
	// try {
	// DataType dt = findDataTypeByNameInAllCategories(dtm, structName);
	// if (!(dt instanceof Structure)) {
	// Msg.error(this, "Data type is not a structure: " + structName);
	// return; // Exit lambda
	// }
	// Structure struct = (Structure) dt;

	// // Find the component by iterating through members
	// DataTypeComponent component = null;
	// for (DataTypeComponent c : struct.getComponents()) {
	// if (memberName.equals(c.getFieldName())) {
	// component = c;
	// break;
	// }
	// }

	// if (component == null) {
	// Msg.error(this, "Member not found in structure: " + memberName);
	// return; // Exit lambda
	// }

	// // Delete the member
	// struct.delete(component.getOffset());

	// // Update the data type in the manager after modification
	// dtm.addDataType(struct, DataTypeConflictHandler.REPLACE_HANDLER);

	// success.set(true);
	// } catch (Exception e) {
	// Msg.error(this, "Error deleting member from structure: " + structName, e);
	// } finally {
	// program.endTransaction(tx, success.get());
	// }
	// });
	// } catch (InterruptedException | InvocationTargetException e) {
	// Msg.error(this, "Failed to execute delete struct member on Swing thread", e);
	// }
	// return success.get();
	// }

	// /**
	// * Get data information by symbol/label name.
	// */
	// private String getDataByLabel(String labelName) {
	// Program program = getCurrentProgram();
	// if (program == null) return "No program loaded";
	// if (labelName == null || labelName.isEmpty()) return "Label name is
	// required";

	// SymbolTable symbolTable = program.getSymbolTable();
	// SymbolIterator symbols = symbolTable.getSymbols(labelName);

	// if (!symbols.hasNext()) {
	// return "Symbol not found: " + labelName;
	// }

	// Symbol symbol = symbols.next();
	// Address address = symbol.getAddress();
	// Data data = program.getListing().getDataAt(address);

	// if (data == null) {
	// return "No data found at symbol address: " + address;
	// }

	// StringBuilder info = new StringBuilder();
	// info.append(String.format("Address: %s\n", address));
	// info.append(String.format("Symbol: %s\n", symbol.getName()));
	// info.append(String.format("Data Type: %s\n", data.getDataType().getName()));
	// info.append(String.format("Value: %s\n", data.getValue()));

	// return info.toString();
	// }

	// /**
	// * Read raw bytes from an address.
	// */
	// private String getBytes(String addressStr, int count) {
	// Program program = getCurrentProgram();
	// if (program == null) return "No program loaded";
	// if (addressStr == null || addressStr.isEmpty()) return "Address is required";
	// if (count <= 0) return "Count must be greater than 0";

	// try {
	// Address address = program.getAddressFactory().getAddress(addressStr);
	// byte[] bytes = new byte[count];
	// program.getMemory().getBytes(address, bytes);
	// return bytesToHexString(bytes);
	// } catch (Exception e) {
	// Msg.error(this, "Error reading bytes", e);
	// return "Error reading bytes: " + e.getMessage();
	// }
	// }

	// /**
	// * Convert a byte array to a hexadecimal string.
	// */
	// private String bytesToHexString(byte[] bytes) {
	// StringBuilder sb = new StringBuilder();
	// for (byte b : bytes) {
	// sb.append(String.format("%02x", b));
	// }
	// return sb.toString();
	// }

	// /**
	// * Search for a byte sequence in the program memory.
	// */
	// private String searchBytes(String byteSequenceStr, int offset, int limit) {
	// Program program = getCurrentProgram();
	// if (program == null) return "No program loaded";
	// if (byteSequenceStr == null || byteSequenceStr.isEmpty()) return "Byte
	// sequence is required";

	// ByteSequenceMatcher matcher;
	// try {
	// matcher = new ByteSequenceMatcher(byteSequenceStr);
	// } catch (IllegalArgumentException e) {
	// return "Invalid byte sequence format: " + e.getMessage();
	// }

	// List<String> foundAddresses = new ArrayList<>();
	// TaskMonitor monitor = new ConsoleTaskMonitor();
	// int currentIndex = 0;
	// int count = 0;

	// try {
	// for (MemoryBlock block : program.getMemory().getBlocks()) {
	// if (monitor.isCancelled()) break;
	// // Optional: Add filter for block permissions like block.isExecute() if
	// needed

	// Address start = block.getStart();
	// while (start != null && start.compareTo(block.getEnd()) <= 0) {
	// if (monitor.isCancelled()) break;

	// Address found = program.getMemory().findBytes(start, matcher.getBytes(),
	// matcher.getMask(), true, monitor);

	// if (found == null || found.compareTo(block.getEnd()) > 0) {
	// break; // Not found in this block or went past the end
	// }

	// // Check pagination limits *before* adding to list
	// if (currentIndex >= offset && count < limit) {
	// foundAddresses.add(found.toString());
	// count++;
	// }
	// currentIndex++; // Increment index for every found match

	// // Stop searching if we've found enough for the requested page
	// if (count >= limit) {
	// // We can break the inner loop, but need to signal the outer loop too
	// monitor.cancel(); // Use monitor cancellation to break outer loop
	// break;
	// }

	// // Move start address past the found match
	// start = found.add(1);
	// // Avoid infinite loop if start address becomes null after adding 1 (unlikely
	// but safe)
	// if (start == null) break;
	// }
	// // Check cancellation status again after inner loop
	// if (monitor.isCancelled()) break;
	// }

	// if (monitor.isCancelled() && count < limit) { // Check if cancelled before
	// page full
	// return "Byte search cancelled.";
	// }

	// if (foundAddresses.isEmpty()) {
	// return "Byte sequence not found: " + byteSequenceStr;
	// }

	// // Return the collected (already paginated) list
	// return String.join("\n", foundAddresses);

	// } catch (Exception e) {
	// Msg.error(this, "Error searching for bytes", e);
	// return "Error searching for bytes: " + e.getMessage();
	// }
	// }

	// // Helper class to parse byte sequence string with wildcards
	// private static class ByteSequenceMatcher {
	// private final byte[] bytes;
	// private final byte[] mask;

	// public ByteSequenceMatcher(String sequence) throws IllegalArgumentException {
	// String cleanSequence = sequence.replaceAll("\\s+", ""); // Remove spaces
	// if (cleanSequence.length() % 2 != 0 && !cleanSequence.contains("?")) {
	// // Allow single '?' but not incomplete hex bytes otherwise
	// throw new IllegalArgumentException("Hex string must have an even number of
	// characters or use '?' for wildcards.");
	// }

	// ArrayList<Byte> byteList = new ArrayList<>();
	// ArrayList<Byte> maskList = new ArrayList<>();

	// for (int i = 0; i < cleanSequence.length(); /* increment inside loop */) {
	// char c1 = cleanSequence.charAt(i);
	// if (c1 == '?') {
	// // Handle single '?' wildcard
	// if (i + 1 < cleanSequence.length() && cleanSequence.charAt(i+1) == '?') {
	// // Handle '??' wildcard
	// byteList.add((byte) 0x00);
	// maskList.add((byte) 0x00);
	// i += 2;
	// } else {
	// // Single '?' assumes wildcard for a full byte
	// byteList.add((byte) 0x00);
	// maskList.add((byte) 0x00);
	// i += 1;
	// }
	// } else {
	// // Handle hex byte
	// if (i + 1 >= cleanSequence.length()) {
	// throw new IllegalArgumentException("Incomplete hex byte at end of
	// sequence.");
	// }
	// char c2 = cleanSequence.charAt(i + 1);
	// try {
	// String hexPair = "" + c1 + c2;
	// byteList.add((byte) Integer.parseInt(hexPair, 16));
	// maskList.add((byte) 0xFF); // Full match required
	// i += 2;
	// } catch (NumberFormatException e) {
	// throw new IllegalArgumentException("Invalid hex character in sequence: " + c1
	// + c2);
	// }
	// }
	// }

	// this.bytes = toByteArray(byteList);
	// this.mask = toByteArray(maskList);
	// }

	// public byte[] getBytes() { return bytes; }
	// public byte[] getMask() { return mask; }

	// private static byte[] toByteArray(List<Byte> list) {
	// byte[] array = new byte[list.size()];
	// for (int i = 0; i < list.size(); i++) {
	// array[i] = list.get(i);
	// }
	// return array;
	// }
	// }

}
