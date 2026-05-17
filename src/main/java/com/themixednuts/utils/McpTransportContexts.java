package com.themixednuts.utils;

import io.modelcontextprotocol.common.McpTransportContext;
import io.modelcontextprotocol.server.McpAsyncServerExchange;
import reactor.util.context.Context;
import reactor.util.context.ContextView;

public final class McpTransportContexts {

  private McpTransportContexts() {}

  public static McpTransportContext resolve(
      McpAsyncServerExchange exchange, ContextView contextView) {
    if (exchange != null) {
      return exchange.transportContext();
    }
    return contextView.getOrDefault(McpTransportContext.KEY, McpTransportContext.EMPTY);
  }

  public static Context put(Context context, McpTransportContext transportContext) {
    return context.put(
        McpTransportContext.KEY,
        transportContext != null ? transportContext : McpTransportContext.EMPTY);
  }
}
