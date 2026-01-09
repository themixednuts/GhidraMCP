package com.themixednuts.tools;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.draft7.SchemaBuilder;
import com.themixednuts.models.SymbolInfo;
import com.themixednuts.models.OperationResult;

import ghidra.app.cmd.label.AddLabelCmd;
import ghidra.app.cmd.label.DeleteLabelCmd;
import ghidra.app.cmd.label.RenameLabelCmd;
import ghidra.app.util.NamespaceUtils;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.util.exception.InvalidInputException;
import io.modelcontextprotocol.common.McpTransportContext;
import reactor.core.publisher.Mono;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;
import java.util.Spliterator;
import java.util.Spliterators;

@GhidraMcpTool(name = "Manage Symbols", description = "Symbol operations: create, update, and convert symbols and labels.", mcpName = "manage_symbols", mcpDescription = """
			  <use_case>
			  Symbol operations for reverse engineering. Create labels,
			  rename functions and variables, update symbol properties. Essential
			  for organizing analysis results and improving code readability.
			  </use_case>

			 <important_notes>
			 - Supports multiple symbol identification methods for updates (current_name, address, symbol_id)
			 - Handles namespace organization and symbol scoping
			 - Validates symbol names according to Ghidra rules
			 - Can convert existing namespaces to classes using the convert_to_class action
			 - Namespace to class conversion requires the namespace to not be within a function
			 - For searching/listing symbols, use ReadSymbolsTool instead
			 - For deleting symbols, use DeleteSymbolTool instead
			 </important_notes>

			<examples>
			Create a label at a specific address:
			{
			  "fileName": "program.exe",
			  "action": "create",
			  "symbol_type": "label",
			  "address": "0x401000",
			  "name": "main_entry"
			}

			Create a namespace:
			{
			  "fileName": "program.exe",
			  "action": "create",
			  "symbol_type": "namespace",
			  "name": "MyNamespace",
			  "namespace": "ParentNamespace"
			}

			Rename a symbol by its current name:
			{
			  "fileName": "program.exe",
			  "action": "update",
			  "current_name": "FUN_00401000",
			  "new_name": "main_function"
			}

			Convert a namespace to a class:
			{
			  "fileName": "program.exe",
			  "action": "convert_to_class",
			  "name": "AutoClass3",
			  "namespace": "optional::parent::namespace"
			}
			</examples>
			 """)
public class ManageSymbolsTool extends BaseMcpTool {

	public static final String ARG_SYMBOL_TYPE = "symbol_type";

	private static final String ACTION_CREATE = "create";
	private static final String ACTION_UPDATE = "update";
	private static final String ACTION_CONVERT_TO_CLASS = "convert_to_class";

	/**
	 * Defines the JSON input schema for symbol management operations.
	 * 
	 * @return The JsonSchema defining the expected input arguments
	 */
	@Override
	public JsonSchema schema() {
		// Use Draft 7 builder for conditional support with additive approach
		var schemaRoot = createDraft7SchemaNode();

		// Global properties (always available)
		schemaRoot.property(ARG_FILE_NAME,
				SchemaBuilder.string(mapper)
						.description("The name of the program file."));

		schemaRoot.property(ARG_ACTION, SchemaBuilder.string(mapper)
				.enumValues(
						ACTION_CREATE,
						ACTION_UPDATE,
						ACTION_CONVERT_TO_CLASS)
				.description("Action to perform on symbols"));

		schemaRoot.property(ARG_NAMESPACE, SchemaBuilder.string(mapper)
				.description("Namespace for symbol organization (optional for all actions)"));

		schemaRoot.requiredProperty(ARG_FILE_NAME)
				.requiredProperty(ARG_ACTION);

		// Add conditional requirements based on action (JSON Schema Draft 7)
		schemaRoot.allOf(
				// action=create: requires symbol_type, name; allows address, namespace
				SchemaBuilder.objectDraft7(mapper)
						.ifThen(
								SchemaBuilder.objectDraft7(mapper)
										.property(ARG_ACTION, SchemaBuilder
												.string(mapper)
												.constValue(ACTION_CREATE)),
								SchemaBuilder.objectDraft7(mapper)
										.requiredProperty(ARG_SYMBOL_TYPE)
										.requiredProperty(ARG_NAME)
										.property(ARG_SYMBOL_TYPE, SchemaBuilder
												.string(mapper)
												.enumValues("label",
														"function",
														"parameter",
														"local_variable",
														"global_variable",
														"namespace",
														"class")
												.description("Type of symbol to create"))
										.property(ARG_NAME, SchemaBuilder
												.string(mapper)
												.description("Name for the new symbol"))
										.property(ARG_ADDRESS, SchemaBuilder
												.string(mapper)
												.description("Memory address (required for labels, optional for class/namespace)")
												.pattern("^(0x)?[0-9a-fA-F]+$"))),
				// symbol_type=label requires address (when creating labels)
				SchemaBuilder.objectDraft7(mapper)
						.ifThen(
								SchemaBuilder.objectDraft7(mapper)
										.property(ARG_SYMBOL_TYPE, SchemaBuilder
												.string(mapper)
												.constValue("label")),
								SchemaBuilder.objectDraft7(mapper)
										.requiredProperty(ARG_ADDRESS)),
				// action=update: requires new_name; allows symbol_id, current_name, address,
				// namespace
				SchemaBuilder.objectDraft7(mapper)
						.ifThen(
								SchemaBuilder.objectDraft7(mapper)
										.property(ARG_ACTION, SchemaBuilder
												.string(mapper)
												.constValue(ACTION_UPDATE)),
								SchemaBuilder.objectDraft7(mapper)
										.requiredProperty(ARG_NEW_NAME)
										.property(ARG_NEW_NAME, SchemaBuilder
												.string(mapper)
												.description("New name for the symbol"))
										.property(ARG_SYMBOL_ID, SchemaBuilder
												.integer(mapper)
												.description("Symbol ID for identification (use one of: symbol_id, current_name, or address)"))
										.property(ARG_CURRENT_NAME,
												SchemaBuilder.string(
														mapper)
														.description("Current symbol name for identification (use one of: symbol_id, current_name, or address)"))
										.property(ARG_ADDRESS, SchemaBuilder
												.string(mapper)
												.description("Address for symbol identification (use one of: symbol_id, current_name, or address)")
												.pattern("^(0x)?[0-9a-fA-F]+$"))),
				// action=convert_to_class: requires name; allows namespace
				SchemaBuilder.objectDraft7(mapper)
						.ifThen(
								SchemaBuilder.objectDraft7(mapper)
										.property(ARG_ACTION, SchemaBuilder
												.string(mapper)
												.constValue(ACTION_CONVERT_TO_CLASS)),
								SchemaBuilder.objectDraft7(mapper)
										.requiredProperty(ARG_NAME)
										.property(ARG_NAME, SchemaBuilder
												.string(mapper)
												.description("Name of the namespace to convert to a class"))));

		return schemaRoot.build();
	}

	/**
	 * Executes the symbol management operation.
	 * 
	 * @param context The MCP transport context
	 * @param args    The tool arguments containing fileName, action, and
	 *                action-specific parameters
	 * @param tool    The Ghidra PluginTool context
	 * @return A Mono emitting the result of the symbol operation
	 */
	@Override
	public Mono<? extends Object> execute(McpTransportContext context, Map<String, Object> args, PluginTool tool) {
		GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);

		return getProgram(args, tool).flatMap(program -> {
			String action = getRequiredStringArgument(args, ARG_ACTION);

			return switch (action.toLowerCase()) {
				case ACTION_CREATE -> handleCreate(program, args, annotation);
				case ACTION_UPDATE -> handleUpdate(program, args, annotation);
				case ACTION_CONVERT_TO_CLASS -> handleConvertToClass(program, args, annotation);
				default -> {
					GhidraMcpError error = GhidraMcpError.invalid(ARG_ACTION, action,
							"Must be one of: create, update, convert_to_class");
					yield Mono.error(new GhidraMcpException(error));
				}
			};
		});
	}

	private Mono<? extends Object> handleCreate(Program program, Map<String, Object> args,
			GhidraMcpTool annotation) {
		String symbolType = getRequiredStringArgument(args, ARG_SYMBOL_TYPE);
		String name = getRequiredStringArgument(args, ARG_NAME);
		Optional<String> namespaceOpt = getOptionalStringArgument(args, ARG_NAMESPACE);

		// Address is optional for class and namespace symbols (they use NO_ADDRESS)
		String addressStr = (symbolType.equalsIgnoreCase("class") || symbolType.equalsIgnoreCase("namespace"))
				? null
				: getRequiredStringArgument(args, ARG_ADDRESS);

		return executeInTransaction(program, "MCP - Create " + symbolType + " " + name, () -> {
			// Validate symbol name
			try {
				SymbolUtilities.validateName(name);
			} catch (InvalidInputException e) {
				throw new GhidraMcpException(GhidraMcpError.invalid(ARG_NAME, name, e.getMessage()));
			}

			// Parse address (skip for class symbols)
			Address address = null;
			if (addressStr != null) {
				try {
					address = program.getAddressFactory().getAddress(addressStr);
					if (address == null) {
						throw new IllegalArgumentException("Invalid address format");
					}
				} catch (Exception e) {
					throw new GhidraMcpException(GhidraMcpError.parse("address", addressStr));
				}
			}

			// Create symbol based on type
			return switch (symbolType.toLowerCase()) {
				case "label" -> createLabel(program, name, address, namespaceOpt, annotation);
				case "class" -> createClass(program, name, namespaceOpt, annotation);
				case "namespace" -> createNamespace(program, name, namespaceOpt, annotation);
				default -> {
					throw new GhidraMcpException(GhidraMcpError.invalid(ARG_SYMBOL_TYPE, symbolType,
							"Unsupported symbol type for creation"));
				}
			};
		});
	}

	private Object createLabel(Program program, String name, Address address,
			Optional<String> namespaceOpt, GhidraMcpTool annotation) throws GhidraMcpException {
		AddLabelCmd cmd = new AddLabelCmd(address, name, SourceType.USER_DEFINED);

		if (!cmd.applyTo(program)) {
			throw new GhidraMcpException(GhidraMcpError.failed("create label",
					cmd.getStatusMsg() + " - check if label already exists at address"));
		}

		// Get the created symbol to return its info
		Symbol[] symbols = program.getSymbolTable().getSymbols(address);
		Symbol createdSymbol = null;
		for (Symbol symbol : symbols) {
			if (symbol.getName().equals(name)) {
				createdSymbol = symbol;
				break;
			}
		}

		if (createdSymbol == null) {
			// This shouldn't happen if creation succeeded, but handle it
			throw new GhidraMcpException(GhidraMcpError.internal("Symbol created but could not be retrieved"));
		}

		return new SymbolInfo(createdSymbol);
	}

	private Object createClass(Program program, String name, Optional<String> namespaceOpt,
			GhidraMcpTool annotation) throws GhidraMcpException {
		SymbolTable symbolTable = program.getSymbolTable();

		// Support hierarchical class creation with namespace path
		try {
			Namespace parentNamespace;
			if (namespaceOpt.isPresent()) {
				parentNamespace = resolveTargetNamespace(symbolTable, program, namespaceOpt);
			} else {
				parentNamespace = program.getGlobalNamespace();
			}

			// Use NamespaceUtils for clean hierarchical class creation:
			// 1. Create full namespace hierarchy (even for simple names)
			// 2. Convert the final namespace to a class
			Namespace namespace = NamespaceUtils.createNamespaceHierarchy(
					name,
					parentNamespace,
					program,
					SourceType.USER_DEFINED);

			// Convert the namespace to a class
			Namespace classNamespace = NamespaceUtils.convertNamespaceToClass(namespace);
			Symbol classSymbol = classNamespace.getSymbol();
			return new SymbolInfo(classSymbol);
		} catch (InvalidInputException e) {
			throw new GhidraMcpException(GhidraMcpError.invalid(ARG_NAME, name,
					"Invalid class name: " + e.getMessage() + ". Use '::' to create nested classes."));
		} catch (GhidraMcpException e) {
			throw e;
		} catch (Exception e) {
			throw new GhidraMcpException(GhidraMcpError.failed("create class",
					e.getMessage() + " - check if class already exists"));
		}
	}

	private Object createNamespace(Program program, String name, Optional<String> namespaceOpt,
			GhidraMcpTool annotation) throws GhidraMcpException {
		SymbolTable symbolTable = program.getSymbolTable();

		// Support hierarchical namespace creation (e.g., "Outer::Middle::Inner")
		try {
			Namespace parentNamespace;
			if (namespaceOpt.isPresent()) {
				parentNamespace = resolveTargetNamespace(symbolTable, program, namespaceOpt);
			} else {
				parentNamespace = program.getGlobalNamespace();
			}

			// Use NamespaceUtils to create namespace hierarchy if needed
			Namespace namespace = NamespaceUtils.createNamespaceHierarchy(
					name,
					parentNamespace,
					program,
					SourceType.USER_DEFINED);

			Symbol namespaceSymbol = namespace.getSymbol();
			return new SymbolInfo(namespaceSymbol);
		} catch (InvalidInputException e) {
			throw new GhidraMcpException(GhidraMcpError.invalid(ARG_NAME, name,
					"Invalid namespace name: " + e.getMessage() + ". Use '::' to create nested namespaces."));
		} catch (GhidraMcpException e) {
			throw e;
		} catch (Exception e) {
			throw new GhidraMcpException(GhidraMcpError.failed("create namespace",
					e.getMessage() + " - check if namespace already exists"));
		}
	}

	private Mono<? extends Object> handleRead(Program program, Map<String, Object> args, GhidraMcpTool annotation) {
		return Mono.fromCallable(() -> {
			SymbolTable symbolTable = program.getSymbolTable();

			// Apply precedence: symbol_id > address > name
			if (args.containsKey(ARG_SYMBOL_ID)) {
				Long symbolId = getOptionalLongArgument(args, ARG_SYMBOL_ID).orElse(null);
				if (symbolId != null) {
					Symbol symbol = symbolTable.getSymbol(symbolId);
					if (symbol != null) {
						return new SymbolInfo(symbol);
					}
				}
				throw new GhidraMcpException(GhidraMcpError.notFound("symbol", "id=" + symbolId));
			} else if (args.containsKey(ARG_ADDRESS)) {
				String address = getOptionalStringArgument(args, ARG_ADDRESS).orElse(null);
				if (address != null && !address.trim().isEmpty()) {
					try {
						Address addr = program.getAddressFactory().getAddress(address);
						if (addr != null) {
							Symbol[] symbols = symbolTable.getSymbols(addr);
							if (symbols.length > 0) {
								return new SymbolInfo(symbols[0]); // Return first
								                                   // symbol at address
							}
						}
						throw new GhidraMcpException(GhidraMcpError.notFound("symbol", "address=" + address));
					} catch (GhidraMcpException e) {
						throw e;
					} catch (Exception e) {
						throw new GhidraMcpException(GhidraMcpError.parse("address", address));
					}
				}
				throw new GhidraMcpException(GhidraMcpError.missing("symbol_id, address, or name"));
			} else if (args.containsKey(ARG_NAME)) {
				String name = getOptionalStringArgument(args, ARG_NAME).orElse(null);
				if (name != null && !name.trim().isEmpty()) {
					// First try exact match
					SymbolIterator exactIter = symbolTable.getSymbolIterator(name, true);
					if (exactIter.hasNext()) {
						return new SymbolInfo(exactIter.next());
					}

					// Then try regex
					try {
						Symbol firstMatch = StreamSupport
								.stream(symbolTable.getAllSymbols(true).spliterator(),
										false)
								.filter(s -> s.getName().matches(name))
								.findFirst()
								.orElse(null);

						if (firstMatch != null) {
							return new SymbolInfo(firstMatch);
						}
						throw new GhidraMcpException(GhidraMcpError.notFound("symbol", "name=" + name));
					} catch (GhidraMcpException e) {
						throw e;
					} catch (Exception e) {
						throw new GhidraMcpException(GhidraMcpError.invalid(ARG_NAME, name,
								"Invalid regex pattern: " + e.getMessage()));
					}
				}
				throw new GhidraMcpException(GhidraMcpError.missing("symbol_id, address, or name"));
			} else {
				throw new GhidraMcpException(GhidraMcpError.missing("symbol_id, address, or name"));
			}
		});
	}

	private Mono<? extends Object> handleUpdate(Program program, Map<String, Object> args,
			GhidraMcpTool annotation) {
		Optional<Long> symbolIdOpt = getOptionalLongArgument(args, ARG_SYMBOL_ID);
		Optional<String> currentNameOpt = getOptionalStringArgument(args, ARG_CURRENT_NAME);
		Optional<String> addressOpt = getOptionalStringArgument(args, ARG_ADDRESS);
		Optional<String> namespaceOpt = getOptionalStringArgument(args, ARG_NAMESPACE);
		String newName = getRequiredStringArgument(args, ARG_NEW_NAME);

		boolean hasSymbolId = symbolIdOpt.isPresent();
		boolean hasCurrentName = currentNameOpt.filter(name -> !name.isBlank()).isPresent();
		boolean hasAddress = addressOpt.filter(addr -> !addr.isBlank()).isPresent();

		// Count provided identifiers
		int identifierCount = (hasSymbolId ? 1 : 0) + (hasCurrentName ? 1 : 0) + (hasAddress ? 1 : 0);

		if (identifierCount > 1) {
			return Mono.error(multipleIdentifierError(symbolIdOpt, currentNameOpt, addressOpt));
		}

		if (identifierCount == 0) {
			return Mono.error(missingIdentifierError());
		}

		return executeInTransaction(program, "MCP - Rename Symbol", () -> {
			SymbolTable symbolTable = program.getSymbolTable();
			SymbolResolveResult resolveResult = resolveSymbolForRename(symbolTable, program, args,
					symbolIdOpt,
					currentNameOpt, addressOpt, namespaceOpt);

			// Check if the new name already exists in the target namespace
			SymbolIterator existingSymbolIterator = symbolTable.getSymbolIterator(newName, true);
			List<Symbol> existingSymbols = new ArrayList<>();
			while (existingSymbolIterator.hasNext()) {
				Symbol existingSymbol = existingSymbolIterator.next();
				if (existingSymbol.getParentNamespace().equals(resolveResult.targetNamespace())) {
					existingSymbols.add(existingSymbol);
				}
			}

			// If there's already a symbol with the same name in the target namespace,
			// provide detailed info
			if (!existingSymbols.isEmpty()) {
				List<String> conflictingNames = existingSymbols.stream()
						.map(s -> s.getName() + " (ID=" + s.getID() + ", addr=" + s.getAddress() + ")")
						.collect(Collectors.toList());
				throw new GhidraMcpException(GhidraMcpError.conflict(
						"Symbol '" + newName + "' already exists in namespace '"
								+ resolveResult.targetNamespace().getName(false) + "': " + conflictingNames));
			}

			RenameLabelCmd cmd = new RenameLabelCmd(resolveResult.symbol(), newName,
					resolveResult.targetNamespace(),
					SourceType.USER_DEFINED);
			if (!cmd.applyTo(program)) {
				throw new GhidraMcpException(GhidraMcpError.failed("rename symbol", cmd.getStatusMsg()));
			}

			// Return the updated symbol info
			return new SymbolInfo(resolveResult.symbol());
		});
	}

	private SymbolResolveResult resolveSymbolForRename(SymbolTable symbolTable,
			Program program,
			Map<String, Object> args,
			Optional<Long> symbolIdOpt,
			Optional<String> currentNameOpt,
			Optional<String> addressOpt,
			Optional<String> namespaceOpt) throws GhidraMcpException {

		if (symbolIdOpt.isPresent()) {
			Symbol symbol = symbolTable.getSymbol(symbolIdOpt.get());
			if (symbol == null) {
				throw new GhidraMcpException(GhidraMcpError.notFound("symbol", "id=" + symbolIdOpt.get()));
			}

			Namespace targetNamespace = resolveTargetNamespace(symbolTable, program, namespaceOpt);
			return new SymbolResolveResult(symbol, symbol.getName(false), targetNamespace);
		}

		if (addressOpt.isPresent()) {
			try {
				Address address = program.getAddressFactory().getAddress(addressOpt.get());
				if (address == null) {
					throw new IllegalArgumentException(
							"Invalid address format: " + addressOpt.get());
				}

				Symbol primarySymbol = symbolTable.getPrimarySymbol(address);
				if (primarySymbol == null) {
					throw new GhidraMcpException(GhidraMcpError.notFound("symbol", "address=" + addressOpt.get()));
				}

				Namespace targetNamespace = resolveTargetNamespace(symbolTable, program, namespaceOpt);
				return new SymbolResolveResult(primarySymbol, primarySymbol.getName(false),
						targetNamespace);
			} catch (GhidraMcpException e) {
				throw e;
			} catch (Exception e) {
				throw new GhidraMcpException(GhidraMcpError.parse("address", addressOpt.get()));
			}
		}

		String currentName = currentNameOpt.map(String::trim).orElse("");

		List<Symbol> matchingSymbols = findSymbolsByName(symbolTable, currentName);

		if (matchingSymbols.isEmpty()) {
			String namespaceHint = namespaceOpt.map(ns -> " in namespace '" + ns + "'").orElse("");
			throw new GhidraMcpException(GhidraMcpError.notFound("symbol", "name='" + currentName + "'" + namespaceHint));
		}

		Namespace targetNamespace = resolveTargetNamespace(symbolTable, program, namespaceOpt);
		Symbol selectedSymbol = selectSymbolWithinNamespace(matchingSymbols, targetNamespace);

		return new SymbolResolveResult(selectedSymbol, currentName, targetNamespace);
	}

	private Namespace resolveTargetNamespace(SymbolTable symbolTable, Program program,
			Optional<String> namespaceOpt)
			throws GhidraMcpException {
		if (namespaceOpt.isEmpty() || namespaceOpt.get().isBlank()
				|| namespaceOpt.get().equalsIgnoreCase("global")) {
			return program.getGlobalNamespace();
		}

		String namespacePath = namespaceOpt.get();

		// Try to resolve namespace by path (supports hierarchical paths like
		// "Outer::Inner")
		try {
			List<Namespace> namespaces = NamespaceUtils.getNamespaceByPath(
					program,
					program.getGlobalNamespace(),
					namespacePath);

			if (namespaces != null && !namespaces.isEmpty()) {
				// If multiple namespaces match, return the first one
				return namespaces.get(0);
			}
		} catch (Exception e) {
			// Fall through to error
		}

		throw new GhidraMcpException(GhidraMcpError.notFound("namespace", namespacePath));
	}

	private List<Symbol> findSymbolsByName(SymbolTable symbolTable, String currentName) {
		SymbolIterator iterator = symbolTable.getSymbolIterator(currentName, true);
		return StreamSupport.stream(
				Spliterators.spliteratorUnknownSize(iterator, Spliterator.ORDERED), false)
				.collect(Collectors.toList());
	}

	private Symbol selectSymbolWithinNamespace(List<Symbol> symbols, Namespace targetNamespace) throws GhidraMcpException {
		List<Symbol> scopedMatches = symbols.stream()
				.filter(symbol -> symbol.getParentNamespace().equals(targetNamespace))
				.collect(Collectors.toList());

		if (scopedMatches.size() == 1) {
			return scopedMatches.get(0);
		}

		if (scopedMatches.isEmpty() && symbols.size() == 1) {
			return symbols.get(0);
		}

		List<String> conflicting = symbols.stream()
				.map(symbol -> symbol.getName(false) + " (ID=" + symbol.getID() + ")")
				.collect(Collectors.toList());

		throw new GhidraMcpException(GhidraMcpError.conflict(
				"Multiple symbols matched. Disambiguate with 'symbol_id' or 'namespace': " + conflicting));
	}

	private GhidraMcpException multipleIdentifierError(Optional<Long> symbolIdOpt,
			Optional<String> currentNameOpt, Optional<String> addressOpt) {
		List<String> providedIdentifiers = new ArrayList<>();

		if (symbolIdOpt.isPresent()) {
			providedIdentifiers.add(ARG_SYMBOL_ID + "=" + symbolIdOpt.get());
		}
		if (currentNameOpt.filter(name -> !name.isBlank()).isPresent()) {
			providedIdentifiers.add(ARG_CURRENT_NAME + "=" + currentNameOpt.get());
		}
		if (addressOpt.filter(addr -> !addr.isBlank()).isPresent()) {
			providedIdentifiers.add(ARG_ADDRESS + "=" + addressOpt.get());
		}

		return new GhidraMcpException(GhidraMcpError.conflict(
				"Provide only one identifier, but got: " + String.join(", ", providedIdentifiers)));
	}

	private GhidraMcpException missingIdentifierError() {
		return new GhidraMcpException(GhidraMcpError.missing(
				"symbol_id, current_name, or address (provide one to identify the symbol)"));
	}

	private record SymbolResolveResult(Symbol symbol, String originalDisplayName, Namespace targetNamespace) {
	}

	private Mono<? extends Object> handleConvertToClass(Program program, Map<String, Object> args,
			GhidraMcpTool annotation) {
		String name = getRequiredStringArgument(args, ARG_NAME);
		Optional<String> namespaceOpt = getOptionalStringArgument(args, ARG_NAMESPACE);

		return executeInTransaction(program, "MCP - Convert Namespace to Class: " + name, () -> {
			SymbolTable symbolTable = program.getSymbolTable();

			Namespace parentNamespace;
			if (namespaceOpt.isPresent()) {
				parentNamespace = resolveTargetNamespace(symbolTable, program, namespaceOpt);
			} else {
				parentNamespace = program.getGlobalNamespace();
			}

			Namespace namespaceToConvert = NamespaceUtils.getFirstNonFunctionNamespace(
					parentNamespace,
					name,
					program);

			if (namespaceToConvert == null) {
				throw new GhidraMcpException(GhidraMcpError.notFound("namespace", name +
						" (in parent: " + parentNamespace.getName() + ")"));
			}

			try {
				Namespace classNamespace = NamespaceUtils.convertNamespaceToClass(namespaceToConvert);
				Symbol classSymbol = classNamespace.getSymbol();
				return new SymbolInfo(classSymbol);
			} catch (InvalidInputException e) {
				throw new GhidraMcpException(GhidraMcpError.invalid(ARG_NAME, name,
						"Cannot convert namespace to class: " + e.getMessage() +
								". Namespace cannot be within a function."));
			}
		});
	}
}
