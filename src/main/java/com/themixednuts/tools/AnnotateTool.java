package com.themixednuts.tools;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.models.OperationResult;
import com.themixednuts.utils.OpaqueCursorCodec;
import com.themixednuts.utils.PaginatedResult;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.draft7.SchemaBuilder;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.common.McpTransportContext;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import reactor.core.publisher.Mono;

@GhidraMcpTool(
    name = "Annotate",
    description = "Set comments and manage bookmarks at program locations.",
    mcpName = "annotate",
    mcpDescription =
        """
        <use_case>
        Document findings at program locations using comments and bookmarks. This is the
        primary tool for writing back analysis results — every effective RE workflow ends
        with renaming, commenting, and retyping. Use after inspecting and understanding code.
        </use_case>

        <important_notes>
        - Comments support 5 types: EOL (end-of-line), PRE (before code), POST (after code),
          PLATE (block header), REPEATABLE (inherited by references)
        - Setting a comment with empty text removes the existing comment of that type
        - Bookmarks require type, category, and comment — use for marking locations for review
        - Use `delete` tool to remove bookmarks (destructive operation kept separate)
        - Comments and bookmarks are the agent's primary output mechanism for documenting findings
        </important_notes>

        <examples>
        Set an end-of-line comment:
        { "file_name": "program.exe", "action": "set_comment", "address": "0x401000",
          "comment_type": "EOL", "text": "Main entry point — initializes subsystems" }

        Get all comments at an address:
        { "file_name": "program.exe", "action": "get_comments", "address": "0x401000" }

        Create a bookmark for later review:
        { "file_name": "program.exe", "action": "create_bookmark", "address": "0x401500",
          "bookmark_type": "Analysis", "bookmark_category": "Suspicious", "comment": "Potential C2 callback" }

        List all bookmarks:
        { "file_name": "program.exe", "action": "list_bookmarks" }
        </examples>
        """)
public class AnnotateTool extends BaseMcpTool {

  private static final String ACTION_SET_COMMENT = "set_comment";
  private static final String ACTION_GET_COMMENTS = "get_comments";
  private static final String ACTION_CREATE_BOOKMARK = "create_bookmark";
  private static final String ACTION_LIST_BOOKMARKS = "list_bookmarks";

  private static final String ARG_COMMENT_TYPE = "comment_type";
  private static final String ARG_TEXT = "text";
  private static final String ARG_BOOKMARK_TYPE = "bookmark_type";
  private static final String ARG_BOOKMARK_CATEGORY = "bookmark_category";

  @Override
  public JsonSchema schema() {
    var schemaRoot = createDraft7SchemaNode();

    schemaRoot.property(
        ARG_FILE_NAME, SchemaBuilder.string(mapper).description("The name of the program file."));

    schemaRoot.property(
        ARG_ACTION,
        SchemaBuilder.string(mapper)
            .enumValues(
                ACTION_SET_COMMENT,
                ACTION_GET_COMMENTS,
                ACTION_CREATE_BOOKMARK,
                ACTION_LIST_BOOKMARKS)
            .description("Annotation operation to perform."));

    schemaRoot.property(
        ARG_ADDRESS,
        SchemaBuilder.string(mapper)
            .description("Target address for the annotation.")
            .pattern("^(0x)?[0-9a-fA-F]+$"));

    schemaRoot.property(
        ARG_COMMENT_TYPE,
        SchemaBuilder.string(mapper)
            .enumValues("EOL", "PRE", "POST", "PLATE", "REPEATABLE")
            .description(
                "Comment type: EOL (end-of-line), PRE (before code), POST (after code),"
                    + " PLATE (block header), REPEATABLE (inherited by references)."));

    schemaRoot.property(
        ARG_TEXT,
        SchemaBuilder.string(mapper)
            .description("Comment text. Set to empty string to remove an existing comment."));

    schemaRoot.property(
        ARG_BOOKMARK_TYPE,
        SchemaBuilder.string(mapper).description("Bookmark type (e.g., 'Note', 'Analysis')."));

    schemaRoot.property(
        ARG_BOOKMARK_CATEGORY,
        SchemaBuilder.string(mapper).description("Bookmark category for organization."));

    schemaRoot.property(
        ARG_COMMENT, SchemaBuilder.string(mapper).description("Bookmark comment text."));

    schemaRoot.property(
        ARG_CURSOR,
        SchemaBuilder.string(mapper).description("Pagination cursor from a previous request."));

    schemaRoot.property(
        ARG_PAGE_SIZE,
        SchemaBuilder.integer(mapper)
            .description("Number of results per page (default 50, max 500)."));

    schemaRoot.requiredProperty(ARG_FILE_NAME).requiredProperty(ARG_ACTION);

    schemaRoot.allOf(
        // set_comment requires address, comment_type, text
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_ACTION, SchemaBuilder.string(mapper).constValue(ACTION_SET_COMMENT)),
                SchemaBuilder.objectDraft7(mapper)
                    .requiredProperty(ARG_ADDRESS)
                    .requiredProperty(ARG_COMMENT_TYPE)
                    .requiredProperty(ARG_TEXT)),
        // get_comments requires address
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_ACTION, SchemaBuilder.string(mapper).constValue(ACTION_GET_COMMENTS)),
                SchemaBuilder.objectDraft7(mapper).requiredProperty(ARG_ADDRESS)),
        // create_bookmark requires address, bookmark_type, bookmark_category, comment
        SchemaBuilder.objectDraft7(mapper)
            .ifThen(
                SchemaBuilder.objectDraft7(mapper)
                    .property(
                        ARG_ACTION,
                        SchemaBuilder.string(mapper).constValue(ACTION_CREATE_BOOKMARK)),
                SchemaBuilder.objectDraft7(mapper)
                    .requiredProperty(ARG_ADDRESS)
                    .requiredProperty(ARG_BOOKMARK_TYPE)
                    .requiredProperty(ARG_BOOKMARK_CATEGORY)
                    .requiredProperty(ARG_COMMENT)));

    return schemaRoot.build();
  }

  @Override
  public Mono<? extends Object> execute(
      McpTransportContext context, Map<String, Object> args, PluginTool tool) {
    return getProgram(args, tool)
        .flatMap(
            program -> {
              String action;
              try {
                action = getRequiredStringArgument(args, ARG_ACTION);
              } catch (GhidraMcpException e) {
                return Mono.error(e);
              }

              return switch (action.toLowerCase()) {
                case ACTION_SET_COMMENT -> handleSetComment(program, args);
                case ACTION_GET_COMMENTS -> handleGetComments(program, args);
                case ACTION_CREATE_BOOKMARK -> handleCreateBookmark(program, args);
                case ACTION_LIST_BOOKMARKS -> handleListBookmarks(program, args);
                default -> {
                  GhidraMcpError error =
                      GhidraMcpError.invalid(
                          ARG_ACTION,
                          action,
                          "must be one of: "
                              + ACTION_SET_COMMENT
                              + ", "
                              + ACTION_GET_COMMENTS
                              + ", "
                              + ACTION_CREATE_BOOKMARK
                              + ", "
                              + ACTION_LIST_BOOKMARKS);
                  yield Mono.error(new GhidraMcpException(error));
                }
              };
            });
  }

  private Mono<? extends Object> handleSetComment(Program program, Map<String, Object> args) {
    String addressStr;
    String commentTypeStr;
    String text;
    try {
      addressStr = getRequiredStringArgument(args, ARG_ADDRESS);
      commentTypeStr = getRequiredStringArgument(args, ARG_COMMENT_TYPE);
      text = getRequiredStringArgument(args, ARG_TEXT);
    } catch (GhidraMcpException e) {
      return Mono.error(e);
    }

    int commentType = parseCommentType(commentTypeStr);

    return parseAddress(program, addressStr, ACTION_SET_COMMENT)
        .flatMap(
            addressResult ->
                executeInTransaction(
                    program,
                    "MCP - Set Comment",
                    () -> {
                      Address address = addressResult.getAddress();
                      Listing listing = program.getListing();

                      // Empty text removes the comment
                      String commentText = text.isEmpty() ? null : text;
                      listing.setComment(address, commentType, commentText);

                      String action = commentText == null ? "removed" : "set";
                      return OperationResult.success(
                              ACTION_SET_COMMENT,
                              address.toString(),
                              commentTypeStr + " comment " + action + " successfully.")
                          .setMetadata(Map.of(ARG_COMMENT_TYPE, commentTypeStr, "action", action));
                    }));
  }

  private Mono<? extends Object> handleGetComments(Program program, Map<String, Object> args) {
    String addressStr;
    try {
      addressStr = getRequiredStringArgument(args, ARG_ADDRESS);
    } catch (GhidraMcpException e) {
      return Mono.error(e);
    }

    return parseAddress(program, addressStr, ACTION_GET_COMMENTS)
        .flatMap(
            addressResult ->
                Mono.fromCallable(
                    () -> {
                      Address address = addressResult.getAddress();
                      Listing listing = program.getListing();

                      Map<String, Object> comments = new LinkedHashMap<>();
                      comments.put("address", address.toString());

                      addCommentIfPresent(
                          comments, "eol", listing.getComment(CodeUnit.EOL_COMMENT, address));
                      addCommentIfPresent(
                          comments, "pre", listing.getComment(CodeUnit.PRE_COMMENT, address));
                      addCommentIfPresent(
                          comments, "post", listing.getComment(CodeUnit.POST_COMMENT, address));
                      addCommentIfPresent(
                          comments, "plate", listing.getComment(CodeUnit.PLATE_COMMENT, address));
                      addCommentIfPresent(
                          comments,
                          "repeatable",
                          listing.getComment(CodeUnit.REPEATABLE_COMMENT, address));

                      return comments;
                    }));
  }

  private void addCommentIfPresent(Map<String, Object> map, String key, String value) {
    if (value != null) {
      map.put(key, value);
    }
  }

  private Mono<? extends Object> handleCreateBookmark(Program program, Map<String, Object> args) {
    String addressStr;
    String bookmarkType;
    String bookmarkCategory;
    String comment;
    try {
      addressStr = getRequiredStringArgument(args, ARG_ADDRESS);
      bookmarkType = getRequiredStringArgument(args, ARG_BOOKMARK_TYPE);
      bookmarkCategory = getRequiredStringArgument(args, ARG_BOOKMARK_CATEGORY);
      comment = getRequiredStringArgument(args, ARG_COMMENT);
    } catch (GhidraMcpException e) {
      return Mono.error(e);
    }

    return parseAddress(program, addressStr, ACTION_CREATE_BOOKMARK)
        .flatMap(
            addressResult ->
                executeInTransaction(
                    program,
                    "MCP - Create Bookmark",
                    () -> {
                      Address address = addressResult.getAddress();
                      BookmarkManager bm = program.getBookmarkManager();
                      bm.setBookmark(address, bookmarkType, bookmarkCategory, comment);

                      return OperationResult.success(
                              ACTION_CREATE_BOOKMARK,
                              address.toString(),
                              "Bookmark created successfully.")
                          .setMetadata(
                              Map.of(
                                  ARG_BOOKMARK_TYPE, bookmarkType,
                                  ARG_BOOKMARK_CATEGORY, bookmarkCategory));
                    }));
  }

  private Mono<? extends Object> handleListBookmarks(Program program, Map<String, Object> args) {
    String addressFilter = getOptionalStringArgument(args, ARG_ADDRESS).orElse(null);
    String typeFilter = getOptionalStringArgument(args, ARG_BOOKMARK_TYPE).orElse(null);
    String categoryFilter = getOptionalStringArgument(args, ARG_BOOKMARK_CATEGORY).orElse(null);
    int pageSize = getPageSizeArgument(args, DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT);
    String cursorValue = getOptionalStringArgument(args, ARG_CURSOR).orElse(null);

    return Mono.fromCallable(
        () -> {
          BookmarkManager bm = program.getBookmarkManager();
          List<Map<String, Object>> results = new ArrayList<>();

          // Decode cursor if present
          String cursorAddress = null;
          if (cursorValue != null) {
            List<String> parts =
                OpaqueCursorCodec.decodeV1(cursorValue, 1, ARG_CURSOR, "v1:address");
            cursorAddress = parts.get(0);
          }

          Iterator<Bookmark> iter;
          if (addressFilter != null) {
            Address address = program.getAddressFactory().getAddress(addressFilter);
            if (address == null) {
              throw new GhidraMcpException(
                  GhidraMcpError.invalid(ARG_ADDRESS, addressFilter, "Invalid address"));
            }
            Bookmark[] bookmarks = bm.getBookmarks(address);
            iter = List.of(bookmarks).iterator();
          } else {
            iter = bm.getBookmarksIterator();
          }

          boolean pastCursor = cursorAddress == null;
          String lastAddress = null;

          while (iter.hasNext() && results.size() <= pageSize) {
            Bookmark bookmark = iter.next();

            // Skip past cursor
            if (!pastCursor) {
              if (bookmark.getAddress().toString().equals(cursorAddress)) {
                pastCursor = true;
              }
              continue;
            }

            // Apply filters
            if (typeFilter != null && !typeFilter.equals(bookmark.getTypeString())) {
              continue;
            }
            if (categoryFilter != null && !categoryFilter.equals(bookmark.getCategory())) {
              continue;
            }

            if (results.size() == pageSize) {
              // We have enough — the extra one tells us there's more
              String nextCursor = OpaqueCursorCodec.encodeV1(lastAddress);
              return new PaginatedResult<>(results, nextCursor);
            }

            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("address", bookmark.getAddress().toString());
            entry.put("type", bookmark.getTypeString());
            entry.put("category", bookmark.getCategory());
            entry.put("comment", bookmark.getComment());
            results.add(entry);
            lastAddress = bookmark.getAddress().toString();
          }

          return new PaginatedResult<>(results, null);
        });
  }

  private int parseCommentType(String commentTypeStr) {
    return switch (commentTypeStr.toUpperCase()) {
      case "EOL" -> CodeUnit.EOL_COMMENT;
      case "PRE" -> CodeUnit.PRE_COMMENT;
      case "POST" -> CodeUnit.POST_COMMENT;
      case "PLATE" -> CodeUnit.PLATE_COMMENT;
      case "REPEATABLE" -> CodeUnit.REPEATABLE_COMMENT;
      default ->
          throw new GhidraMcpException(
              GhidraMcpError.invalid(
                  ARG_COMMENT_TYPE,
                  commentTypeStr,
                  "must be one of: EOL, PRE, POST, PLATE, REPEATABLE"));
    };
  }
}
