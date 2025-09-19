package com.lauriewired;

import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.GlobalNamespace;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighFunctionDBUtil.ReturnCommitOption;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.CodeViewerService;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.cmd.function.SetVariableNameCmd;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Undefined1DataType;
import ghidra.program.model.listing.Variable;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.app.decompiler.ClangToken;
import ghidra.framework.options.Options;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import javax.swing.SwingUtilities;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.InvocationTargetException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.security.MessageDigest;

@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = ghidra.app.DeveloperPluginPackage.NAME,
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "HTTP server plugin",
    description = "Starts an embedded HTTP server to expose program data. Port configurable via Tool Options."
)
public class GhidraMCPPlugin extends Plugin {

    private HttpServer server;
    private static final String OPTION_CATEGORY_NAME = "GhidraMCP HTTP Server";
    private static final String PORT_OPTION_NAME = "Server Port";
    private static final String BIND_HOST_OPTION_NAME = "Bind Host";
    private static final String TOKEN_OPTION_NAME = "Access Token";
    private static final int DEFAULT_PORT = 8080;
    private static final String DEFAULT_BIND_HOST = "127.0.0.1";
    private static final String DEFAULT_TOKEN = "";

    private volatile byte[] sharedSecretBytes = new byte[0];
    private volatile boolean enforceOriginCheck = false;
    private volatile Set<String> allowedOrigins = Collections.emptySet();

    public GhidraMCPPlugin(PluginTool tool) {
        super(tool);
        Msg.info(this, "GhidraMCPPlugin loading...");

        // Register the configuration option
        Options options = tool.getOptions(OPTION_CATEGORY_NAME);
        options.registerOption(PORT_OPTION_NAME, DEFAULT_PORT,
            null, // No help location for now
            "The network port number the embedded HTTP server will listen on. " +
            "Requires Ghidra restart or plugin reload to take effect after changing.");
        options.registerOption(BIND_HOST_OPTION_NAME, DEFAULT_BIND_HOST,
            null,
            "The network interface or hostname the HTTP server will bind to. " +
            "Defaults to 127.0.0.1 for local-only access.");
        options.registerOption(TOKEN_OPTION_NAME, DEFAULT_TOKEN,
            null,
            "Optional shared secret that clients must supply on each request via the " +
            "X-GhidraMCP-Token header or an Authorization bearer token.");

        try {
            startServer();
        }
        catch (IOException e) {
            Msg.error(this, "Failed to start HTTP server", e);
        }
        Msg.info(this, "GhidraMCPPlugin loaded!");
    }

    private void startServer() throws IOException {
        // Read configured network parameters
        Options options = tool.getOptions(OPTION_CATEGORY_NAME);
        int port = options.getInt(PORT_OPTION_NAME, DEFAULT_PORT);
        String configuredHost = options.getString(BIND_HOST_OPTION_NAME, DEFAULT_BIND_HOST);
        if (configuredHost == null || configuredHost.trim().isEmpty()) {
            configuredHost = DEFAULT_BIND_HOST;
        }
        configuredHost = configuredHost.trim();

        String configuredToken = options.getString(TOKEN_OPTION_NAME, DEFAULT_TOKEN);
        if (configuredToken == null) {
            configuredToken = DEFAULT_TOKEN;
        }
        configuredToken = configuredToken.trim();

        this.sharedSecretBytes = configuredToken.isEmpty()
            ? new byte[0]
            : configuredToken.getBytes(StandardCharsets.UTF_8);

        Set<String> originCandidates = buildAllowedOrigins(configuredHost, port);
        if (originCandidates == null) {
            this.allowedOrigins = null;
            this.enforceOriginCheck = true;
        }
        else if (originCandidates.isEmpty()) {
            this.allowedOrigins = Collections.emptySet();
            this.enforceOriginCheck = false;
        }
        else {
            this.allowedOrigins = Collections.unmodifiableSet(originCandidates);
            this.enforceOriginCheck = true;
        }

        // Stop existing server if running (e.g., if plugin is reloaded)
        if (server != null) {
            Msg.info(this, "Stopping existing HTTP server before starting new one.");
            server.stop(0);
            server = null;
        }

        server = HttpServer.create(new InetSocketAddress(configuredHost, port), 0);

        // Each listing endpoint uses offset & limit from query params:
        registerContext("/methods", ex -> {
            Map<String, String> qparams = parseQueryParams(ex);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(ex, getAllFunctionNames(offset, limit));
        });

        registerContext("/classes", ex -> {
            Map<String, String> qparams = parseQueryParams(ex);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(ex, getAllClassNames(offset, limit));
        });

        registerContext("/decompile", ex -> {
            String name = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            sendResponse(ex, decompileFunctionByName(name));
        });

        registerContext("/renameFunction", ex -> {
            Map<String, String> params = parsePostParams(ex);
            String response = renameFunction(params.get("oldName"), params.get("newName"))
                    ? "Renamed successfully" : "Rename failed";
            sendResponse(ex, response);
        });

        registerContext("/renameData", ex -> {
            Map<String, String> params = parsePostParams(ex);
            renameDataAtAddress(params.get("address"), params.get("newName"));
            sendResponse(ex, "Rename data attempted");
        });

        registerContext("/renameVariable", ex -> {
            Map<String, String> params = parsePostParams(ex);
            String functionName = params.get("functionName");
            String oldName = params.get("oldName");
            String newName = params.get("newName");
            String result = renameVariableInFunction(functionName, oldName, newName);
            sendResponse(ex, result);
        });

        registerContext("/segments", ex -> {
            Map<String, String> qparams = parseQueryParams(ex);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(ex, listSegments(offset, limit));
        });

        registerContext("/imports", ex -> {
            Map<String, String> qparams = parseQueryParams(ex);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(ex, listImports(offset, limit));
        });

        registerContext("/exports", ex -> {
            Map<String, String> qparams = parseQueryParams(ex);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(ex, listExports(offset, limit));
        });

        registerContext("/namespaces", ex -> {
            Map<String, String> qparams = parseQueryParams(ex);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(ex, listNamespaces(offset, limit));
        });

        registerContext("/data", ex -> {
            Map<String, String> qparams = parseQueryParams(ex);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(ex, listDefinedData(offset, limit));
        });

        registerContext("/searchFunctions", ex -> {
            Map<String, String> qparams = parseQueryParams(ex);
            String searchTerm = qparams.get("query");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(ex, searchFunctionsByName(searchTerm, offset, limit));
        });

        // New API endpoints based on requirements
        
        registerContext("/get_function_by_address", ex -> {
            Map<String, String> qparams = parseQueryParams(ex);
            String address = qparams.get("address");
            sendResponse(ex, getFunctionByAddress(address));
        });

        registerContext("/get_current_address", ex -> {
            sendResponse(ex, getCurrentAddress());
        });

        registerContext("/get_current_function", ex -> {
            sendResponse(ex, getCurrentFunction());
        });

        registerContext("/list_functions", ex -> {
            sendResponse(ex, listFunctions());
        });

        registerContext("/decompile_function", ex -> {
            Map<String, String> qparams = parseQueryParams(ex);
            String address = qparams.get("address");
            sendResponse(ex, decompileFunctionByAddress(address));
        });

        registerContext("/disassemble_function", ex -> {
            Map<String, String> qparams = parseQueryParams(ex);
            String address = qparams.get("address");
            sendResponse(ex, disassembleFunction(address));
        });

        registerContext("/set_decompiler_comment", ex -> {
            Map<String, String> params = parsePostParams(ex);
            String address = params.get("address");
            String comment = params.get("comment");
            boolean success = setDecompilerComment(address, comment);
            sendResponse(ex, success ? "Comment set successfully" : "Failed to set comment");
        });

        registerContext("/set_disassembly_comment", ex -> {
            Map<String, String> params = parsePostParams(ex);
            String address = params.get("address");
            String comment = params.get("comment");
            boolean success = setDisassemblyComment(address, comment);
            sendResponse(ex, success ? "Comment set successfully" : "Failed to set comment");
        });

        registerContext("/rename_function_by_address", ex -> {
            Map<String, String> params = parsePostParams(ex);
            String functionAddress = params.get("function_address");
            String newName = params.get("new_name");
            boolean success = renameFunctionByAddress(functionAddress, newName);
            sendResponse(ex, success ? "Function renamed successfully" : "Failed to rename function");
        });

        registerContext("/set_function_prototype", ex -> {
            Map<String, String> params = parsePostParams(ex);
            String functionAddress = params.get("function_address");
            String prototype = params.get("prototype");

            // Call the set prototype function and get detailed result
            PrototypeResult result = setFunctionPrototype(functionAddress, prototype);

            if (result.isSuccess()) {
                // Even with successful operations, include any warning messages for debugging
                String successMsg = "Function prototype set successfully";
                if (!result.getErrorMessage().isEmpty()) {
                    successMsg += "\n\nWarnings/Debug Info:\n" + result.getErrorMessage();
                }
                sendResponse(ex, successMsg);
            } else {
                // Return the detailed error message to the client
                sendResponse(ex, "Failed to set function prototype: " + result.getErrorMessage());
            }
        });

        registerContext("/set_local_variable_type", ex -> {
            Map<String, String> params = parsePostParams(ex);
            String functionAddress = params.get("function_address");
            String variableName = params.get("variable_name");
            String newType = params.get("new_type");

            // Capture detailed information about setting the type
            StringBuilder responseMsg = new StringBuilder();
            responseMsg.append("Setting variable type: ").append(variableName)
                      .append(" to ").append(newType)
                      .append(" in function at ").append(functionAddress).append("\n\n");

            // Attempt to find the data type in various categories
            Program program = getCurrentProgram();
            if (program != null) {
                DataTypeManager dtm = program.getDataTypeManager();
                DataType directType = findDataTypeByNameInAllCategories(dtm, newType);
                if (directType != null) {
                    responseMsg.append("Found type: ").append(directType.getPathName()).append("\n");
                } else if (newType.startsWith("P") && newType.length() > 1) {
                    String baseTypeName = newType.substring(1);
                    DataType baseType = findDataTypeByNameInAllCategories(dtm, baseTypeName);
                    if (baseType != null) {
                        responseMsg.append("Found base type for pointer: ").append(baseType.getPathName()).append("\n");
                    } else {
                        responseMsg.append("Base type not found for pointer: ").append(baseTypeName).append("\n");
                    }
                } else {
                    responseMsg.append("Type not found directly: ").append(newType).append("\n");
                }
            }

            // Try to set the type
            boolean success = setLocalVariableType(functionAddress, variableName, newType);

            String successMsg = success ? "Variable type set successfully" : "Failed to set variable type";
            responseMsg.append("\nResult: ").append(successMsg);

            sendResponse(ex, responseMsg.toString());
        });

        registerContext("/xrefs_to", ex -> {
            Map<String, String> qparams = parseQueryParams(ex);
            String address = qparams.get("address");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(ex, getXrefsTo(address, offset, limit));
        });

        registerContext("/xrefs_from", ex -> {
            Map<String, String> qparams = parseQueryParams(ex);
            String address = qparams.get("address");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(ex, getXrefsFrom(address, offset, limit));
        });

        registerContext("/function_xrefs", ex -> {
            Map<String, String> qparams = parseQueryParams(ex);
            String name = qparams.get("name");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(ex, getFunctionXrefs(name, offset, limit));
        });

        registerContext("/strings", ex -> {
            Map<String, String> qparams = parseQueryParams(ex);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            String filter = qparams.get("filter");
            sendResponse(ex, listDefinedStrings(offset, limit, filter));
        });

        server.setExecutor(null);
        new Thread(() -> {
            try {
                server.start();
                Msg.info(this, "GhidraMCP HTTP server started on " + configuredHost + ":" + port);
            } catch (Exception e) {
                Msg.error(this, "Failed to start HTTP server on port " + port + ". Port might be in use.", e);
                server = null; // Ensure server isn't considered running
            }
        }, "GhidraMCP-HTTP-Server").start();
    }

    private void registerContext(String path, CheckedExchangeHandler handler) {
        server.createContext(path, exchange -> handleRequest(exchange, handler));
    }

    @FunctionalInterface
    private interface CheckedExchangeHandler {
        void handle(HttpExchange exchange) throws Exception;
    }

    private void handleRequest(HttpExchange exchange, CheckedExchangeHandler handler) {
        try {
            AuthorizationResult authResult = authorize(exchange);
            if (!authResult.allowed) {
                safeSendResponse(exchange, authResult.statusCode, authResult.message);
                return;
            }
            handler.handle(exchange);
        }
        catch (Exception e) {
            Msg.error(this, "Error handling request for " + exchange.getRequestURI(), e);
            safeSendResponse(exchange, 500, "Internal server error");
        }
        finally {
            exchange.close();
        }
    }

    private AuthorizationResult authorize(HttpExchange exchange) {
        if (enforceOriginCheck && !isOriginAllowed(exchange)) {
            Msg.warn(this, "Rejecting request from " + exchange.getRemoteAddress() + " due to disallowed Origin header.");
            return AuthorizationResult.deny(403, "Origin not allowed");
        }

        if (sharedSecretBytes.length == 0) {
            return AuthorizationResult.allow();
        }

        String providedToken = extractToken(exchange);
        if (providedToken == null || providedToken.isEmpty()) {
            Msg.warn(this, "Rejecting request from " + exchange.getRemoteAddress() + " due to missing authentication token.");
            return AuthorizationResult.deny(401, "Missing authentication token");
        }

        byte[] providedBytes = providedToken.getBytes(StandardCharsets.UTF_8);
        if (!MessageDigest.isEqual(sharedSecretBytes, providedBytes)) {
            Msg.warn(this, "Rejecting request from " + exchange.getRemoteAddress() + " due to invalid authentication token.");
            return AuthorizationResult.deny(403, "Invalid authentication token");
        }

        return AuthorizationResult.allow();
    }

    private boolean isOriginAllowed(HttpExchange exchange) {
        List<String> originHeaders = exchange.getRequestHeaders().get("Origin");
        if (originHeaders == null || originHeaders.isEmpty()) {
            return true;
        }

        if (allowedOrigins == null) {
            return originMatchesHostHeader(exchange, originHeaders);
        }

        if (allowedOrigins.isEmpty()) {
            return true;
        }

        for (String origin : originHeaders) {
            if (origin == null || origin.isBlank() || "null".equalsIgnoreCase(origin)) {
                return true;
            }

            try {
                URI originUri = URI.create(origin);
                String scheme = originUri.getScheme();
                String host = originUri.getHost();
                if (scheme == null || host == null) {
                    continue;
                }

                int port = originUri.getPort();
                if (port == -1) {
                    port = "https".equalsIgnoreCase(scheme) ? 443 : 80;
                }

                String normalizedHost = normalizeHostForOrigin(host);
                String normalizedOrigin = (scheme + "://" + normalizedHost + ":" + port).toLowerCase(Locale.ROOT);
                if (allowedOrigins.contains(normalizedOrigin)) {
                    return true;
                }
            }
            catch (IllegalArgumentException e) {
                Msg.warn(this, "Rejecting request with malformed Origin header: " + origin);
                return false;
            }
        }

        return false;
    }

    private boolean originMatchesHostHeader(HttpExchange exchange, List<String> originHeaders) {
        String hostHeader = exchange.getRequestHeaders().getFirst("Host");
        if (hostHeader == null || hostHeader.isBlank()) {
            return false;
        }

        HostPort requestHost = parseHostAndPort(hostHeader, exchange.getLocalAddress().getPort());
        if (requestHost == null) {
            return false;
        }

        String normalizedRequestHost = normalizeHostForOrigin(requestHost.host).toLowerCase(Locale.ROOT);

        for (String origin : originHeaders) {
            if (origin == null || origin.isBlank() || "null".equalsIgnoreCase(origin)) {
                return true;
            }

            try {
                URI originUri = URI.create(origin);
                String originHost = originUri.getHost();
                if (originHost == null) {
                    continue;
                }

                int originPort = originUri.getPort();
                if (originPort == -1) {
                    originPort = "https".equalsIgnoreCase(originUri.getScheme()) ? 443 : 80;
                }

                String normalizedOriginHost = normalizeHostForOrigin(originHost).toLowerCase(Locale.ROOT);
                if (normalizedOriginHost.equals(normalizedRequestHost) && originPort == requestHost.port) {
                    return true;
                }
            }
            catch (IllegalArgumentException e) {
                Msg.warn(this, "Rejecting request with malformed Origin header: " + origin);
                return false;
            }
        }

        return false;
    }

    private HostPort parseHostAndPort(String hostHeader, int defaultPort) {
        if (hostHeader == null) {
            return null;
        }

        String trimmed = hostHeader.trim();
        if (trimmed.isEmpty()) {
            return null;
        }

        String host = trimmed;
        int port = defaultPort;

        if (trimmed.startsWith("[")) {
            int closingIndex = trimmed.indexOf(']');
            if (closingIndex < 0) {
                return null;
            }
            host = trimmed.substring(1, closingIndex);
            if (closingIndex + 1 < trimmed.length() && trimmed.charAt(closingIndex + 1) == ':') {
                String portPart = trimmed.substring(closingIndex + 2);
                int parsedPort = parsePort(portPart);
                port = parsedPort >= 0 ? parsedPort : defaultPort;
            }
            return new HostPort(host, port);
        }

        int colonIndex = trimmed.lastIndexOf(':');
        if (colonIndex > 0 && trimmed.indexOf(':') == colonIndex) {
            String hostPart = trimmed.substring(0, colonIndex);
            String portPart = trimmed.substring(colonIndex + 1);
            int parsedPort = parsePort(portPart);
            if (parsedPort >= 0) {
                host = hostPart;
                port = parsedPort;
            }
            else {
                host = trimmed;
            }
        }
        else {
            host = trimmed;
        }

        return new HostPort(host, port);
    }

    private int parsePort(String value) {
        if (value == null) {
            return -1;
        }
        try {
            return Integer.parseInt(value.trim());
        }
        catch (NumberFormatException e) {
            return -1;
        }
    }

    private String extractToken(HttpExchange exchange) {
        List<String> headerTokens = exchange.getRequestHeaders().get("X-GhidraMCP-Token");
        if (headerTokens != null) {
            for (String headerToken : headerTokens) {
                if (headerToken != null && !headerToken.trim().isEmpty()) {
                    return headerToken.trim();
                }
            }
        }

        String authHeader = exchange.getRequestHeaders().getFirst("Authorization");
        if (authHeader != null) {
            String trimmed = authHeader.trim();
            if (trimmed.regionMatches(true, 0, "Bearer ", 0, 7)) {
                return trimmed.substring(7).trim();
            }
            if (trimmed.regionMatches(true, 0, "Token ", 0, 6)) {
                return trimmed.substring(6).trim();
            }
        }

        Map<String, String> qparams = parseQueryParams(exchange);
        String queryToken = qparams.get("token");
        if (queryToken == null) {
            queryToken = qparams.get("authToken");
        }
        if (queryToken != null && !queryToken.trim().isEmpty()) {
            return queryToken.trim();
        }

        return null;
    }

    private Set<String> buildAllowedOrigins(String host, int port) {
        if (host == null) {
            return null;
        }

        String trimmed = host.trim();
        if (trimmed.isEmpty() || isWildcardHost(trimmed)) {
            return null;
        }

        Set<String> origins = new HashSet<>();
        addOriginForHost(origins, trimmed, port);

        if (isLoopbackHost(trimmed)) {
            addOriginForHost(origins, "localhost", port);
            addOriginForHost(origins, "127.0.0.1", port);
            addOriginForHost(origins, "::1", port);
        }

        return origins;
    }

    private void addOriginForHost(Set<String> origins, String host, int port) {
        String normalizedHost = normalizeHostForOrigin(host);
        origins.add(("http://" + normalizedHost + ":" + port).toLowerCase(Locale.ROOT));
        origins.add(("https://" + normalizedHost + ":" + port).toLowerCase(Locale.ROOT));
    }

    private String normalizeHostForOrigin(String host) {
        if (host == null) {
            return "";
        }
        if (host.contains(":") && !host.startsWith("[") && !host.endsWith("]")) {
            return "[" + host + "]";
        }
        return host;
    }

    private boolean isWildcardHost(String host) {
        String value = host.trim();
        return value.equals("0.0.0.0") || value.equals("::") || value.equals("0:0:0:0:0:0:0:0") || value.equals("*");
    }

    private boolean isLoopbackHost(String host) {
        String value = host.trim().toLowerCase(Locale.ROOT);
        return value.equals("localhost") || value.equals("127.0.0.1") || value.startsWith("127.") ||
            value.equals("::1") || value.equals("[::1]") || value.equals("0:0:0:0:0:0:0:1");
    }

    private void safeSendResponse(HttpExchange exchange, int statusCode, String message) {
        try {
            sendResponse(exchange, statusCode, message == null ? "" : message);
        }
        catch (IOException ioe) {
            Msg.error(this, "Failed to send HTTP response", ioe);
        }
    }

    private static class HostPort {
        private final String host;
        private final int port;

        private HostPort(String host, int port) {
            this.host = host;
            this.port = port;
        }
    }

    private static class AuthorizationResult {
        private final boolean allowed;
        private final int statusCode;
        private final String message;

        private AuthorizationResult(boolean allowed, int statusCode, String message) {
            this.allowed = allowed;
            this.statusCode = statusCode;
            this.message = message;
        }

        static AuthorizationResult allow() {
            return new AuthorizationResult(true, 200, null);
        }

        static AuthorizationResult deny(int statusCode, String message) {
            return new AuthorizationResult(false, statusCode, message);
        }
    }

    // ----------------------------------------------------------------------------------
    // Pagination-aware listing methods
    // ----------------------------------------------------------------------------------

    private String getAllFunctionNames(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> names = new ArrayList<>();
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            names.add(f.getName());
        }
        return paginateList(names, offset, limit);
    }

    private String getAllClassNames(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        Set<String> classNames = new HashSet<>();
        for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
            Namespace ns = symbol.getParentNamespace();
            if (ns != null && !ns.isGlobal()) {
                classNames.add(ns.getName());
            }
        }
        // Convert set to list for pagination
        List<String> sorted = new ArrayList<>(classNames);
        Collections.sort(sorted);
        return paginateList(sorted, offset, limit);
    }

    private String listSegments(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            lines.add(String.format("%s: %s - %s", block.getName(), block.getStart(), block.getEnd()));
        }
        return paginateList(lines, offset, limit);
    }

    private String listImports(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        for (Symbol symbol : program.getSymbolTable().getExternalSymbols()) {
            lines.add(symbol.getName() + " -> " + symbol.getAddress());
        }
        return paginateList(lines, offset, limit);
    }

    private String listExports(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        SymbolTable table = program.getSymbolTable();
        SymbolIterator it = table.getAllSymbols(true);

        List<String> lines = new ArrayList<>();
        while (it.hasNext()) {
            Symbol s = it.next();
            // On older Ghidra, "export" is recognized via isExternalEntryPoint()
            if (s.isExternalEntryPoint()) {
                lines.add(s.getName() + " -> " + s.getAddress());
            }
        }
        return paginateList(lines, offset, limit);
    }

    private String listNamespaces(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        Set<String> namespaces = new HashSet<>();
        for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
            Namespace ns = symbol.getParentNamespace();
            if (ns != null && !(ns instanceof GlobalNamespace)) {
                namespaces.add(ns.getName());
            }
        }
        List<String> sorted = new ArrayList<>(namespaces);
        Collections.sort(sorted);
        return paginateList(sorted, offset, limit);
    }

    private String listDefinedData(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            DataIterator it = program.getListing().getDefinedData(block.getStart(), true);
            while (it.hasNext()) {
                Data data = it.next();
                if (block.contains(data.getAddress())) {
                    String label   = data.getLabel() != null ? data.getLabel() : "(unnamed)";
                    String valRepr = data.getDefaultValueRepresentation();
                    lines.add(String.format("%s: %s = %s",
                        data.getAddress(),
                        escapeNonAscii(label),
                        escapeNonAscii(valRepr)
                    ));
                }
            }
        }
        return paginateList(lines, offset, limit);
    }

    private String searchFunctionsByName(String searchTerm, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (searchTerm == null || searchTerm.isEmpty()) return "Search term is required";
    
        List<String> matches = new ArrayList<>();
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            String name = func.getName();
            // simple substring match
            if (name.toLowerCase().contains(searchTerm.toLowerCase())) {
                matches.add(String.format("%s @ %s", name, func.getEntryPoint()));
            }
        }
    
        Collections.sort(matches);
    
        if (matches.isEmpty()) {
            return "No functions matching '" + searchTerm + "'";
        }
        return paginateList(matches, offset, limit);
    }    

    // ----------------------------------------------------------------------------------
    // Logic for rename, decompile, etc.
    // ----------------------------------------------------------------------------------

    private String decompileFunctionByName(String name) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            if (func.getName().equals(name)) {
                DecompileResults result =
                    decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
                if (result != null && result.decompileCompleted()) {
                    return result.getDecompiledFunction().getC();
                } else {
                    return "Decompilation failed";
                }
            }
        }
        return "Function not found";
    }

    private boolean renameFunction(String oldName, String newName) {
        Program program = getCurrentProgram();
        if (program == null) return false;

        AtomicBoolean successFlag = new AtomicBoolean(false);
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Rename function via HTTP");
                try {
                    for (Function func : program.getFunctionManager().getFunctions(true)) {
                        if (func.getName().equals(oldName)) {
                            func.setName(newName, SourceType.USER_DEFINED);
                            successFlag.set(true);
                            break;
                        }
                    }
                }
                catch (Exception e) {
                    Msg.error(this, "Error renaming function", e);
                }
                finally {
                    successFlag.set(program.endTransaction(tx, successFlag.get()));
                }
            });
        }
        catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute rename on Swing thread", e);
        }
        return successFlag.get();
    }

    private void renameDataAtAddress(String addressStr, String newName) {
        Program program = getCurrentProgram();
        if (program == null) return;

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Rename data");
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    Listing listing = program.getListing();
                    Data data = listing.getDefinedDataAt(addr);
                    if (data != null) {
                        SymbolTable symTable = program.getSymbolTable();
                        Symbol symbol = symTable.getPrimarySymbol(addr);
                        if (symbol != null) {
                            symbol.setName(newName, SourceType.USER_DEFINED);
                        } else {
                            symTable.createLabel(addr, newName, SourceType.USER_DEFINED);
                        }
                    }
                }
                catch (Exception e) {
                    Msg.error(this, "Rename data error", e);
                }
                finally {
                    program.endTransaction(tx, true);
                }
            });
        }
        catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute rename data on Swing thread", e);
        }
    }

    private String renameVariableInFunction(String functionName, String oldVarName, String newVarName) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);

        Function func = null;
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            if (f.getName().equals(functionName)) {
                func = f;
                break;
            }
        }

        if (func == null) {
            return "Function not found";
        }

        DecompileResults result = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
        if (result == null || !result.decompileCompleted()) {
            return "Decompilation failed";
        }

        HighFunction highFunction = result.getHighFunction();
        if (highFunction == null) {
            return "Decompilation failed (no high function)";
        }

        LocalSymbolMap localSymbolMap = highFunction.getLocalSymbolMap();
        if (localSymbolMap == null) {
            return "Decompilation failed (no local symbol map)";
        }

        HighSymbol highSymbol = null;
        Iterator<HighSymbol> symbols = localSymbolMap.getSymbols();
        while (symbols.hasNext()) {
            HighSymbol symbol = symbols.next();
            String symbolName = symbol.getName();
            
            if (symbolName.equals(oldVarName)) {
                highSymbol = symbol;
            }
            if (symbolName.equals(newVarName)) {
                return "Error: A variable with name '" + newVarName + "' already exists in this function";
            }
        }

        if (highSymbol == null) {
            return "Variable not found";
        }

        boolean commitRequired = checkFullCommit(highSymbol, highFunction);

        final HighSymbol finalHighSymbol = highSymbol;
        final Function finalFunction = func;
        AtomicBoolean successFlag = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {           
                int tx = program.startTransaction("Rename variable");
                try {
                    if (commitRequired) {
                        HighFunctionDBUtil.commitParamsToDatabase(highFunction, false,
                            ReturnCommitOption.NO_COMMIT, finalFunction.getSignatureSource());
                    }
                    HighFunctionDBUtil.updateDBVariable(
                        finalHighSymbol,
                        newVarName,
                        null,
                        SourceType.USER_DEFINED
                    );
                    successFlag.set(true);
                }
                catch (Exception e) {
                    Msg.error(this, "Failed to rename variable", e);
                }
                finally {
                    successFlag.set(program.endTransaction(tx, true));
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            String errorMsg = "Failed to execute rename on Swing thread: " + e.getMessage();
            Msg.error(this, errorMsg, e);
            return errorMsg;
        }
        return successFlag.get() ? "Variable renamed" : "Failed to rename variable";
    }

    /**
     * Copied from AbstractDecompilerAction.checkFullCommit, it's protected.
	 * Compare the given HighFunction's idea of the prototype with the Function's idea.
	 * Return true if there is a difference. If a specific symbol is being changed,
	 * it can be passed in to check whether or not the prototype is being affected.
	 * @param highSymbol (if not null) is the symbol being modified
	 * @param hfunction is the given HighFunction
	 * @return true if there is a difference (and a full commit is required)
	 */
	protected static boolean checkFullCommit(HighSymbol highSymbol, HighFunction hfunction) {
		if (highSymbol != null && !highSymbol.isParameter()) {
			return false;
		}
		Function function = hfunction.getFunction();
		Parameter[] parameters = function.getParameters();
		LocalSymbolMap localSymbolMap = hfunction.getLocalSymbolMap();
		int numParams = localSymbolMap.getNumParams();
		if (numParams != parameters.length) {
			return true;
		}

		for (int i = 0; i < numParams; i++) {
			HighSymbol param = localSymbolMap.getParamSymbol(i);
			if (param.getCategoryIndex() != i) {
				return true;
			}
			VariableStorage storage = param.getStorage();
			// Don't compare using the equals method so that DynamicVariableStorage can match
			if (0 != storage.compareTo(parameters[i].getVariableStorage())) {
				return true;
			}
		}

		return false;
	}

    // ----------------------------------------------------------------------------------
    // New methods to implement the new functionalities
    // ----------------------------------------------------------------------------------

    /**
     * Get function by address
     */
    private String getFunctionByAddress(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = program.getFunctionManager().getFunctionAt(addr);

            if (func == null) return "No function found at address " + addressStr;

            return String.format("Function: %s at %s\nSignature: %s\nEntry: %s\nBody: %s - %s",
                func.getName(),
                func.getEntryPoint(),
                func.getSignature(),
                func.getEntryPoint(),
                func.getBody().getMinAddress(),
                func.getBody().getMaxAddress());
        } catch (Exception e) {
            return "Error getting function: " + e.getMessage();
        }
    }

    /**
     * Get current address selected in Ghidra GUI
     */
    private String getCurrentAddress() {
        CodeViewerService service = tool.getService(CodeViewerService.class);
        if (service == null) return "Code viewer service not available";

        ProgramLocation location = service.getCurrentLocation();
        return (location != null) ? location.getAddress().toString() : "No current location";
    }

    /**
     * Get current function selected in Ghidra GUI
     */
    private String getCurrentFunction() {
        CodeViewerService service = tool.getService(CodeViewerService.class);
        if (service == null) return "Code viewer service not available";

        ProgramLocation location = service.getCurrentLocation();
        if (location == null) return "No current location";

        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        Function func = program.getFunctionManager().getFunctionContaining(location.getAddress());
        if (func == null) return "No function at current location: " + location.getAddress();

        return String.format("Function: %s at %s\nSignature: %s",
            func.getName(),
            func.getEntryPoint(),
            func.getSignature());
    }

    /**
     * List all functions in the database
     */
    private String listFunctions() {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        StringBuilder result = new StringBuilder();
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            result.append(String.format("%s at %s\n", 
                func.getName(), 
                func.getEntryPoint()));
        }

        return result.toString();
    }

    /**
     * Gets a function at the given address or containing the address
     * @return the function or null if not found
     */
    private Function getFunctionForAddress(Program program, Address addr) {
        Function func = program.getFunctionManager().getFunctionAt(addr);
        if (func == null) {
            func = program.getFunctionManager().getFunctionContaining(addr);
        }
        return func;
    }

    /**
     * Decompile a function at the given address
     */
    private String decompileFunctionByAddress(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = getFunctionForAddress(program, addr);
            if (func == null) return "No function found at or containing address " + addressStr;

            DecompInterface decomp = new DecompInterface();
            decomp.openProgram(program);
            DecompileResults result = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());

            return (result != null && result.decompileCompleted()) 
                ? result.getDecompiledFunction().getC() 
                : "Decompilation failed";
        } catch (Exception e) {
            return "Error decompiling function: " + e.getMessage();
        }
    }

    /**
     * Get assembly code for a function
     */
    private String disassembleFunction(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = getFunctionForAddress(program, addr);
            if (func == null) return "No function found at or containing address " + addressStr;

            StringBuilder result = new StringBuilder();
            Listing listing = program.getListing();
            Address start = func.getEntryPoint();
            Address end = func.getBody().getMaxAddress();

            InstructionIterator instructions = listing.getInstructions(start, true);
            while (instructions.hasNext()) {
                Instruction instr = instructions.next();
                if (instr.getAddress().compareTo(end) > 0) {
                    break; // Stop if we've gone past the end of the function
                }
                String comment = listing.getComment(CodeUnit.EOL_COMMENT, instr.getAddress());
                comment = (comment != null) ? "; " + comment : "";

                result.append(String.format("%s: %s %s\n", 
                    instr.getAddress(), 
                    instr.toString(),
                    comment));
            }

            return result.toString();
        } catch (Exception e) {
            return "Error disassembling function: " + e.getMessage();
        }
    }    

    /**
     * Set a comment using the specified comment type (PRE_COMMENT or EOL_COMMENT)
     */
    private boolean setCommentAtAddress(String addressStr, String comment, int commentType, String transactionName) {
        Program program = getCurrentProgram();
        if (program == null) return false;
        if (addressStr == null || addressStr.isEmpty() || comment == null) return false;

        AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction(transactionName);
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    program.getListing().setComment(addr, commentType, comment);
                    success.set(true);
                } catch (Exception e) {
                    Msg.error(this, "Error setting " + transactionName.toLowerCase(), e);
                } finally {
                    success.set(program.endTransaction(tx, success.get()));
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute " + transactionName.toLowerCase() + " on Swing thread", e);
        }

        return success.get();
    }

    /**
     * Set a comment for a given address in the function pseudocode
     */
    private boolean setDecompilerComment(String addressStr, String comment) {
        return setCommentAtAddress(addressStr, comment, CodeUnit.PRE_COMMENT, "Set decompiler comment");
    }

    /**
     * Set a comment for a given address in the function disassembly
     */
    private boolean setDisassemblyComment(String addressStr, String comment) {
        return setCommentAtAddress(addressStr, comment, CodeUnit.EOL_COMMENT, "Set disassembly comment");
    }

    /**
     * Class to hold the result of a prototype setting operation
     */
    private static class PrototypeResult {
        private final boolean success;
        private final String errorMessage;

        public PrototypeResult(boolean success, String errorMessage) {
            this.success = success;
            this.errorMessage = errorMessage;
        }

        public boolean isSuccess() {
            return success;
        }

        public String getErrorMessage() {
            return errorMessage;
        }
    }

    /**
     * Rename a function by its address
     */
    private boolean renameFunctionByAddress(String functionAddrStr, String newName) {
        Program program = getCurrentProgram();
        if (program == null) return false;
        if (functionAddrStr == null || functionAddrStr.isEmpty() || 
            newName == null || newName.isEmpty()) {
            return false;
        }

        AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {
                performFunctionRename(program, functionAddrStr, newName, success);
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute rename function on Swing thread", e);
        }

        return success.get();
    }

    /**
     * Helper method to perform the actual function rename within a transaction
     */
    private void performFunctionRename(Program program, String functionAddrStr, String newName, AtomicBoolean success) {
        int tx = program.startTransaction("Rename function by address");
        try {
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            Function func = getFunctionForAddress(program, addr);

            if (func == null) {
                Msg.error(this, "Could not find function at address: " + functionAddrStr);
                return;
            }

            func.setName(newName, SourceType.USER_DEFINED);
            success.set(true);
        } catch (Exception e) {
            Msg.error(this, "Error renaming function by address", e);
        } finally {
            program.endTransaction(tx, success.get());
        }
    }

    /**
     * Set a function's prototype with proper error handling using ApplyFunctionSignatureCmd
     */
    private PrototypeResult setFunctionPrototype(String functionAddrStr, String prototype) {
        // Input validation
        Program program = getCurrentProgram();
        if (program == null) return new PrototypeResult(false, "No program loaded");
        if (functionAddrStr == null || functionAddrStr.isEmpty()) {
            return new PrototypeResult(false, "Function address is required");
        }
        if (prototype == null || prototype.isEmpty()) {
            return new PrototypeResult(false, "Function prototype is required");
        }

        final StringBuilder errorMessage = new StringBuilder();
        final AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> 
                applyFunctionPrototype(program, functionAddrStr, prototype, success, errorMessage));
        } catch (InterruptedException | InvocationTargetException e) {
            String msg = "Failed to set function prototype on Swing thread: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        }

        return new PrototypeResult(success.get(), errorMessage.toString());
    }

    /**
     * Helper method that applies the function prototype within a transaction
     */
    private void applyFunctionPrototype(Program program, String functionAddrStr, String prototype, 
                                       AtomicBoolean success, StringBuilder errorMessage) {
        try {
            // Get the address and function
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            Function func = getFunctionForAddress(program, addr);

            if (func == null) {
                String msg = "Could not find function at address: " + functionAddrStr;
                errorMessage.append(msg);
                Msg.error(this, msg);
                return;
            }

            Msg.info(this, "Setting prototype for function " + func.getName() + ": " + prototype);

            // Store original prototype as a comment for reference
            addPrototypeComment(program, func, prototype);

            // Use ApplyFunctionSignatureCmd to parse and apply the signature
            parseFunctionSignatureAndApply(program, addr, prototype, success, errorMessage);

        } catch (Exception e) {
            String msg = "Error setting function prototype: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        }
    }

    /**
     * Add a comment showing the prototype being set
     */
    private void addPrototypeComment(Program program, Function func, String prototype) {
        int txComment = program.startTransaction("Add prototype comment");
        try {
            program.getListing().setComment(
                func.getEntryPoint(), 
                CodeUnit.PLATE_COMMENT, 
                "Setting prototype: " + prototype
            );
        } finally {
            program.endTransaction(txComment, true);
        }
    }

    /**
     * Parse and apply the function signature with error handling
     */
    private void parseFunctionSignatureAndApply(Program program, Address addr, String prototype,
                                              AtomicBoolean success, StringBuilder errorMessage) {
        // Use ApplyFunctionSignatureCmd to parse and apply the signature
        int txProto = program.startTransaction("Set function prototype");
        try {
            // Get data type manager
            DataTypeManager dtm = program.getDataTypeManager();

            // Get data type manager service
            ghidra.app.services.DataTypeManagerService dtms = 
                tool.getService(ghidra.app.services.DataTypeManagerService.class);

            // Create function signature parser
            ghidra.app.util.parser.FunctionSignatureParser parser = 
                new ghidra.app.util.parser.FunctionSignatureParser(dtm, dtms);

            // Parse the prototype into a function signature
            ghidra.program.model.data.FunctionDefinitionDataType sig = parser.parse(null, prototype);

            if (sig == null) {
                String msg = "Failed to parse function prototype";
                errorMessage.append(msg);
                Msg.error(this, msg);
                return;
            }

            // Create and apply the command
            ghidra.app.cmd.function.ApplyFunctionSignatureCmd cmd = 
                new ghidra.app.cmd.function.ApplyFunctionSignatureCmd(
                    addr, sig, SourceType.USER_DEFINED);

            // Apply the command to the program
            boolean cmdResult = cmd.applyTo(program, new ConsoleTaskMonitor());

            if (cmdResult) {
                success.set(true);
                Msg.info(this, "Successfully applied function signature");
            } else {
                String msg = "Command failed: " + cmd.getStatusMsg();
                errorMessage.append(msg);
                Msg.error(this, msg);
            }
        } catch (Exception e) {
            String msg = "Error applying function signature: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        } finally {
            program.endTransaction(txProto, success.get());
        }
    }

    /**
     * Set a local variable's type using HighFunctionDBUtil.updateDBVariable
     */
    private boolean setLocalVariableType(String functionAddrStr, String variableName, String newType) {
        // Input validation
        Program program = getCurrentProgram();
        if (program == null) return false;
        if (functionAddrStr == null || functionAddrStr.isEmpty() || 
            variableName == null || variableName.isEmpty() ||
            newType == null || newType.isEmpty()) {
            return false;
        }

        AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> 
                applyVariableType(program, functionAddrStr, variableName, newType, success));
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute set variable type on Swing thread", e);
        }

        return success.get();
    }

    /**
     * Helper method that performs the actual variable type change
     */
    private void applyVariableType(Program program, String functionAddrStr, 
                                  String variableName, String newType, AtomicBoolean success) {
        try {
            // Find the function
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            Function func = getFunctionForAddress(program, addr);

            if (func == null) {
                Msg.error(this, "Could not find function at address: " + functionAddrStr);
                return;
            }

            DecompileResults results = decompileFunction(func, program);
            if (results == null || !results.decompileCompleted()) {
                return;
            }

            ghidra.program.model.pcode.HighFunction highFunction = results.getHighFunction();
            if (highFunction == null) {
                Msg.error(this, "No high function available");
                return;
            }

            // Find the symbol by name
            HighSymbol symbol = findSymbolByName(highFunction, variableName);
            if (symbol == null) {
                Msg.error(this, "Could not find variable '" + variableName + "' in decompiled function");
                return;
            }

            // Get high variable
            HighVariable highVar = symbol.getHighVariable();
            if (highVar == null) {
                Msg.error(this, "No HighVariable found for symbol: " + variableName);
                return;
            }

            Msg.info(this, "Found high variable for: " + variableName + 
                     " with current type " + highVar.getDataType().getName());

            // Find the data type
            DataTypeManager dtm = program.getDataTypeManager();
            DataType dataType = resolveDataType(dtm, newType);

            if (dataType == null) {
                Msg.error(this, "Could not resolve data type: " + newType);
                return;
            }

            Msg.info(this, "Using data type: " + dataType.getName() + " for variable " + variableName);

            // Apply the type change in a transaction
            updateVariableType(program, symbol, dataType, success);

        } catch (Exception e) {
            Msg.error(this, "Error setting variable type: " + e.getMessage());
        }
    }

    /**
     * Find a high symbol by name in the given high function
     */
    private HighSymbol findSymbolByName(ghidra.program.model.pcode.HighFunction highFunction, String variableName) {
        Iterator<HighSymbol> symbols = highFunction.getLocalSymbolMap().getSymbols();
        while (symbols.hasNext()) {
            HighSymbol s = symbols.next();
            if (s.getName().equals(variableName)) {
                return s;
            }
        }
        return null;
    }

    /**
     * Decompile a function and return the results
     */
    private DecompileResults decompileFunction(Function func, Program program) {
        // Set up decompiler for accessing the decompiled function
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);
        decomp.setSimplificationStyle("decompile"); // Full decompilation

        // Decompile the function
        DecompileResults results = decomp.decompileFunction(func, 60, new ConsoleTaskMonitor());

        if (!results.decompileCompleted()) {
            Msg.error(this, "Could not decompile function: " + results.getErrorMessage());
            return null;
        }

        return results;
    }

    /**
     * Apply the type update in a transaction
     */
    private void updateVariableType(Program program, HighSymbol symbol, DataType dataType, AtomicBoolean success) {
        int tx = program.startTransaction("Set variable type");
        try {
            // Use HighFunctionDBUtil to update the variable with the new type
            HighFunctionDBUtil.updateDBVariable(
                symbol,                // The high symbol to modify
                symbol.getName(),      // Keep original name
                dataType,              // The new data type
                SourceType.USER_DEFINED // Mark as user-defined
            );

            success.set(true);
            Msg.info(this, "Successfully set variable type using HighFunctionDBUtil");
        } catch (Exception e) {
            Msg.error(this, "Error setting variable type: " + e.getMessage());
        } finally {
            program.endTransaction(tx, success.get());
        }
    }

    /**
     * Get all references to a specific address (xref to)
     */
    private String getXrefsTo(String addressStr, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            ReferenceManager refManager = program.getReferenceManager();
            
            ReferenceIterator refIter = refManager.getReferencesTo(addr);
            
            List<String> refs = new ArrayList<>();
            while (refIter.hasNext()) {
                Reference ref = refIter.next();
                Address fromAddr = ref.getFromAddress();
                RefType refType = ref.getReferenceType();
                
                Function fromFunc = program.getFunctionManager().getFunctionContaining(fromAddr);
                String funcInfo = (fromFunc != null) ? " in " + fromFunc.getName() : "";
                
                refs.add(String.format("From %s%s [%s]", fromAddr, funcInfo, refType.getName()));
            }
            
            return paginateList(refs, offset, limit);
        } catch (Exception e) {
            return "Error getting references to address: " + e.getMessage();
        }
    }

    /**
     * Get all references from a specific address (xref from)
     */
    private String getXrefsFrom(String addressStr, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            ReferenceManager refManager = program.getReferenceManager();
            
            Reference[] references = refManager.getReferencesFrom(addr);
            
            List<String> refs = new ArrayList<>();
            for (Reference ref : references) {
                Address toAddr = ref.getToAddress();
                RefType refType = ref.getReferenceType();
                
                String targetInfo = "";
                Function toFunc = program.getFunctionManager().getFunctionAt(toAddr);
                if (toFunc != null) {
                    targetInfo = " to function " + toFunc.getName();
                } else {
                    Data data = program.getListing().getDataAt(toAddr);
                    if (data != null) {
                        targetInfo = " to data " + (data.getLabel() != null ? data.getLabel() : data.getPathName());
                    }
                }
                
                refs.add(String.format("To %s%s [%s]", toAddr, targetInfo, refType.getName()));
            }
            
            return paginateList(refs, offset, limit);
        } catch (Exception e) {
            return "Error getting references from address: " + e.getMessage();
        }
    }

    /**
     * Get all references to a specific function by name
     */
    private String getFunctionXrefs(String functionName, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (functionName == null || functionName.isEmpty()) return "Function name is required";

        try {
            List<String> refs = new ArrayList<>();
            FunctionManager funcManager = program.getFunctionManager();
            for (Function function : funcManager.getFunctions(true)) {
                if (function.getName().equals(functionName)) {
                    Address entryPoint = function.getEntryPoint();
                    ReferenceIterator refIter = program.getReferenceManager().getReferencesTo(entryPoint);
                    
                    while (refIter.hasNext()) {
                        Reference ref = refIter.next();
                        Address fromAddr = ref.getFromAddress();
                        RefType refType = ref.getReferenceType();
                        
                        Function fromFunc = funcManager.getFunctionContaining(fromAddr);
                        String funcInfo = (fromFunc != null) ? " in " + fromFunc.getName() : "";
                        
                        refs.add(String.format("From %s%s [%s]", fromAddr, funcInfo, refType.getName()));
                    }
                }
            }
            
            if (refs.isEmpty()) {
                return "No references found to function: " + functionName;
            }
            
            return paginateList(refs, offset, limit);
        } catch (Exception e) {
            return "Error getting function references: " + e.getMessage();
        }
    }

/**
 * List all defined strings in the program with their addresses
 */
    private String listDefinedStrings(int offset, int limit, String filter) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        DataIterator dataIt = program.getListing().getDefinedData(true);
        
        while (dataIt.hasNext()) {
            Data data = dataIt.next();
            
            if (data != null && isStringData(data)) {
                String value = data.getValue() != null ? data.getValue().toString() : "";
                
                if (filter == null || value.toLowerCase().contains(filter.toLowerCase())) {
                    String escapedValue = escapeString(value);
                    lines.add(String.format("%s: \"%s\"", data.getAddress(), escapedValue));
                }
            }
        }
        
        return paginateList(lines, offset, limit);
    }

    /**
     * Check if the given data is a string type
     */
    private boolean isStringData(Data data) {
        if (data == null) return false;
        
        DataType dt = data.getDataType();
        String typeName = dt.getName().toLowerCase();
        return typeName.contains("string") || typeName.contains("char") || typeName.equals("unicode");
    }

    /**
     * Escape special characters in a string for display
     */
    private String escapeString(String input) {
        if (input == null) return "";
        
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            if (c >= 32 && c < 127) {
                sb.append(c);
            } else if (c == '\n') {
                sb.append("\\n");
            } else if (c == '\r') {
                sb.append("\\r");
            } else if (c == '\t') {
                sb.append("\\t");
            } else {
                sb.append(String.format("\\x%02x", (int)c & 0xFF));
            }
        }
        return sb.toString();
    }

    /**
     * Resolves a data type by name, handling common types and pointer types
     * @param dtm The data type manager
     * @param typeName The type name to resolve
     * @return The resolved DataType, or null if not found
     */
    private DataType resolveDataType(DataTypeManager dtm, String typeName) {
        // First try to find exact match in all categories
        DataType dataType = findDataTypeByNameInAllCategories(dtm, typeName);
        if (dataType != null) {
            Msg.info(this, "Found exact data type match: " + dataType.getPathName());
            return dataType;
        }

        // Check for Windows-style pointer types (PXXX)
        if (typeName.startsWith("P") && typeName.length() > 1) {
            String baseTypeName = typeName.substring(1);

            // Special case for PVOID
            if (baseTypeName.equals("VOID")) {
                return new PointerDataType(dtm.getDataType("/void"));
            }

            // Try to find the base type
            DataType baseType = findDataTypeByNameInAllCategories(dtm, baseTypeName);
            if (baseType != null) {
                return new PointerDataType(baseType);
            }

            Msg.warn(this, "Base type not found for " + typeName + ", defaulting to void*");
            return new PointerDataType(dtm.getDataType("/void"));
        }

        // Handle common built-in types
        switch (typeName.toLowerCase()) {
            case "int":
            case "long":
                return dtm.getDataType("/int");
            case "uint":
            case "unsigned int":
            case "unsigned long":
            case "dword":
                return dtm.getDataType("/uint");
            case "short":
                return dtm.getDataType("/short");
            case "ushort":
            case "unsigned short":
            case "word":
                return dtm.getDataType("/ushort");
            case "char":
            case "byte":
                return dtm.getDataType("/char");
            case "uchar":
            case "unsigned char":
                return dtm.getDataType("/uchar");
            case "longlong":
            case "__int64":
                return dtm.getDataType("/longlong");
            case "ulonglong":
            case "unsigned __int64":
                return dtm.getDataType("/ulonglong");
            case "bool":
            case "boolean":
                return dtm.getDataType("/bool");
            case "void":
                return dtm.getDataType("/void");
            default:
                // Try as a direct path
                DataType directType = dtm.getDataType("/" + typeName);
                if (directType != null) {
                    return directType;
                }

                // Fallback to int if we couldn't find it
                Msg.warn(this, "Unknown type: " + typeName + ", defaulting to int");
                return dtm.getDataType("/int");
        }
    }
    
    /**
     * Find a data type by name in all categories/folders of the data type manager
     * This searches through all categories rather than just the root
     */
    private DataType findDataTypeByNameInAllCategories(DataTypeManager dtm, String typeName) {
        // Try exact match first
        DataType result = searchByNameInAllCategories(dtm, typeName);
        if (result != null) {
            return result;
        }

        // Try lowercase
        return searchByNameInAllCategories(dtm, typeName.toLowerCase());
    }

    /**
     * Helper method to search for a data type by name in all categories
     */
    private DataType searchByNameInAllCategories(DataTypeManager dtm, String name) {
        // Get all data types from the manager
        Iterator<DataType> allTypes = dtm.getAllDataTypes();
        while (allTypes.hasNext()) {
            DataType dt = allTypes.next();
            // Check if the name matches exactly (case-sensitive) 
            if (dt.getName().equals(name)) {
                return dt;
            }
            // For case-insensitive, we want an exact match except for case
            if (dt.getName().equalsIgnoreCase(name)) {
                return dt;
            }
        }
        return null;
    }

    // ----------------------------------------------------------------------------------
    // Utility: parse query params, parse post params, pagination, etc.
    // ----------------------------------------------------------------------------------

    /**
     * Parse query parameters from the URL, e.g. ?offset=10&limit=100
     */
    private Map<String, String> parseQueryParams(HttpExchange exchange) {
        Map<String, String> result = new HashMap<>();
        String query = exchange.getRequestURI().getQuery(); // e.g. offset=10&limit=100
        if (query != null) {
            String[] pairs = query.split("&");
            for (String p : pairs) {
                String[] kv = p.split("=");
                if (kv.length == 2) {
                    // URL decode parameter values
                    try {
                        String key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
                        String value = URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
                        result.put(key, value);
                    } catch (Exception e) {
                        Msg.error(this, "Error decoding URL parameter", e);
                    }
                }
            }
        }
        return result;
    }

    /**
     * Parse post body form params, e.g. oldName=foo&newName=bar
     */
    private Map<String, String> parsePostParams(HttpExchange exchange) throws IOException {
        byte[] body = exchange.getRequestBody().readAllBytes();
        String bodyStr = new String(body, StandardCharsets.UTF_8);
        Map<String, String> params = new HashMap<>();
        for (String pair : bodyStr.split("&")) {
            String[] kv = pair.split("=");
            if (kv.length == 2) {
                // URL decode parameter values
                try {
                    String key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
                    String value = URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
                    params.put(key, value);
                } catch (Exception e) {
                    Msg.error(this, "Error decoding URL parameter", e);
                }
            }
        }
        return params;
    }

    /**
     * Convert a list of strings into one big newline-delimited string, applying offset & limit.
     */
    private String paginateList(List<String> items, int offset, int limit) {
        int start = Math.max(0, offset);
        int end   = Math.min(items.size(), offset + limit);

        if (start >= items.size()) {
            return ""; // no items in range
        }
        List<String> sub = items.subList(start, end);
        return String.join("\n", sub);
    }

    /**
     * Parse an integer from a string, or return defaultValue if null/invalid.
     */
    private int parseIntOrDefault(String val, int defaultValue) {
        if (val == null) return defaultValue;
        try {
            return Integer.parseInt(val);
        }
        catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    /**
     * Escape non-ASCII chars to avoid potential decode issues.
     */
    private String escapeNonAscii(String input) {
        if (input == null) return "";
        StringBuilder sb = new StringBuilder();
        for (char c : input.toCharArray()) {
            if (c >= 32 && c < 127) {
                sb.append(c);
            }
            else {
                sb.append("\\x");
                sb.append(Integer.toHexString(c & 0xFF));
            }
        }
        return sb.toString();
    }

    public Program getCurrentProgram() {
        ProgramManager pm = tool.getService(ProgramManager.class);
        return pm != null ? pm.getCurrentProgram() : null;
    }

    private void sendResponse(HttpExchange exchange, String response) throws IOException {
        sendResponse(exchange, 200, response);
    }

    private void sendResponse(HttpExchange exchange, int statusCode, String response) throws IOException {
        byte[] bytes = response == null ? new byte[0] : response.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
        exchange.sendResponseHeaders(statusCode, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    @Override
    public void dispose() {
        if (server != null) {
            Msg.info(this, "Stopping GhidraMCP HTTP server...");
            server.stop(1); // Stop with a small delay (e.g., 1 second) for connections to finish
            server = null; // Nullify the reference
            Msg.info(this, "GhidraMCP HTTP server stopped.");
        }
        super.dispose();
    }
}
