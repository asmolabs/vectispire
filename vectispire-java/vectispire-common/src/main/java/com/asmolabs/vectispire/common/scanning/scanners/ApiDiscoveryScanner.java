package com.asmolabs.vectispire.common.scanning.scanners;

import com.asmolabs.vectispire.common.domain.apis.ApiContract;
import com.asmolabs.vectispire.common.domain.apis.ApiEndpoint;
import com.asmolabs.vectispire.common.domain.apis.ApiVisibility;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Static discovery of API endpoints and declared contracts in a cloned repository.
 */
public final class ApiDiscoveryScanner {

    private static final ObjectMapper JSON_MAPPER = new ObjectMapper();

    private static final Set<String> IGNORED_DIRS = Set.of(
            ".git", "node_modules", "target", "build", ".gradle", "dist", "vendor",
            ".idea", ".vscode", "test", "tests", "__tests__", "spec", "specs", "fixtures", "testdata");

    public record Result(List<ApiEndpoint> endpoints, List<ApiContract> contracts) {}

    public static Result scan(Path workspaceRoot) {
        if (workspaceRoot == null || !Files.exists(workspaceRoot)) {
            return new Result(List.of(), List.of());
        }

        List<ApiEndpoint> endpoints = new ArrayList<>();
        List<ApiContract> contracts = new ArrayList<>();
        Set<String> publicIngressPaths = new HashSet<>();

        try {
            Files.walkFileTree(workspaceRoot, new SimpleFileVisitor<>() {
                @Override
                public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) {
                    String name = dir.getFileName() != null ? dir.getFileName().toString() : "";
                    if (IGNORED_DIRS.contains(name.toLowerCase())) {
                        return FileVisitResult.SKIP_SUBTREE;
                    }
                    String rel = workspaceRoot.relativize(dir).toString().replace('\\', '/').toLowerCase();
                    if (rel.startsWith("src/test") || rel.contains("/src/test/") || rel.startsWith("test") || rel.contains("/test/")) {
                        return FileVisitResult.SKIP_SUBTREE;
                    }
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                    String name = file.getFileName().toString().toLowerCase();
                    String relativePath = workspaceRoot.relativize(file).toString();

                    if (isTestPath(relativePath)) {
                        return FileVisitResult.CONTINUE;
                    }

                    try {
                        // 1. Contract discovery (OpenAPI / Swagger)
                        if (isOpenApiOrSwagger(name)) {
                            parseContract(file, relativePath, endpoints).ifPresent(contracts::add);
                        }

                        // 2. Kubernetes Ingress / IaC exposure discovery
                        if (name.endsWith(".yaml") || name.endsWith(".yml")) {
                            extractIngressPaths(file, publicIngressPaths);
                        }

                        // 3. Source code endpoint extraction
                        if (name.endsWith(".java")) {
                            extractJavaSpringEndpoints(file, relativePath, endpoints);
                        } else if (name.endsWith(".ts") || name.endsWith(".js")) {
                            extractNodeEndpoints(file, relativePath, endpoints);
                        } else if (name.endsWith(".py")) {
                            extractPythonEndpoints(file, relativePath, endpoints);
                        } else if (name.endsWith(".go")) {
                            extractGoEndpoints(file, relativePath, endpoints);
                        }
                    } catch (Exception ignored) {
                        // Resilient scanner: a single malformed file does not abort the whole discovery
                    }
                    return FileVisitResult.CONTINUE;
                }
            });
        } catch (IOException e) {
            return new Result(List.of(), List.of());
        }

        // Reconcile visibility if Ingress paths were found and deduplicate endpoints
        Set<String> seen = new HashSet<>();
        List<ApiEndpoint> adjusted = new ArrayList<>();
        for (ApiEndpoint ep : endpoints) {
            String key = ep.method() + ":" + ep.path();
            if (seen.add(key)) {
                if (publicIngressPaths.contains(ep.path()) || matchesAnyIngress(ep.path(), publicIngressPaths)) {
                    adjusted.add(new ApiEndpoint(
                            ep.method(), ep.path(), ep.authRequired(), ep.authType(),
                            ApiVisibility.PUBLIC, ep.filePath(), ep.lineNumber(),
                            ep.framework(), ep.operationId(), ep.summary(), ep.tags()));
                } else {
                    adjusted.add(ep);
                }
            }
        }

        return new Result(List.copyOf(adjusted), List.copyOf(contracts));
    }

    private static boolean isOpenApiOrSwagger(String filename) {
        return filename.contains("openapi") || filename.contains("swagger")
                || filename.equals("api-docs.json") || filename.equals("api.json");
    }

    private static java.util.Optional<ApiContract> parseContract(Path file, String relativePath, List<ApiEndpoint> endpoints) {
        try {
            String content = Files.readString(file, StandardCharsets.UTF_8);
            if (file.getFileName().toString().endsWith(".json")) {
                JsonNode root = JSON_MAPPER.readTree(content);
                if (root == null || !root.isObject()) {
                    return java.util.Optional.empty();
                }

                String format = "UNKNOWN";
                if (root.has("openapi")) {
                    format = "OPENAPI_V" + root.get("openapi").asText().charAt(0);
                } else if (root.has("swagger")) {
                    format = "SWAGGER_V2";
                } else {
                    return java.util.Optional.empty();
                }

                String title = "API Spec";
                String version = "1.0.0";
                if (root.has("info")) {
                    JsonNode info = root.get("info");
                    if (info.has("title")) title = info.get("title").asText();
                    if (info.has("version")) version = info.get("version").asText();
                }

                List<String> paths = new ArrayList<>();
                boolean hasGlobalSecurity = root.has("security")
                        || (root.has("components") && root.get("components").has("securitySchemes"))
                        || root.has("securityDefinitions");

                if (root.has("paths") && root.get("paths").isObject()) {
                    JsonNode pathsNode = root.get("paths");
                    Iterator<String> pathNames = pathsNode.fieldNames();
                    while (pathNames.hasNext()) {
                        String path = pathNames.next();
                        paths.add(path);
                        JsonNode pathObj = pathsNode.get(path);
                        if (pathObj != null && pathObj.isObject()) {
                            Iterator<String> methodNames = pathObj.fieldNames();
                            while (methodNames.hasNext()) {
                                String methodKey = methodNames.next().toUpperCase();
                                if (Set.of("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD").contains(methodKey)) {
                                    JsonNode opNode = pathObj.get(methodKey.toLowerCase());
                                    if (opNode == null) opNode = pathObj.get(methodKey);
                                    String summary = (opNode != null && opNode.has("summary")) ? opNode.get("summary").asText() : null;
                                    String opId = (opNode != null && opNode.has("operationId")) ? opNode.get("operationId").asText() : null;
                                    
                                    boolean hasOpSecurity = opNode != null && opNode.has("security");
                                    boolean isOpExplicitPublic = hasOpSecurity && opNode.get("security").isArray() && opNode.get("security").isEmpty();
                                    boolean auth = !isOpExplicitPublic && (hasOpSecurity || hasGlobalSecurity);

                                    endpoints.add(new ApiEndpoint(
                                            methodKey,
                                            path,
                                            auth,
                                            auth ? "OPENAPI_SECURITY" : "NONE",
                                            ApiVisibility.UNKNOWN,
                                            relativePath,
                                            1,
                                            "OPENAPI_SPEC",
                                            opId,
                                            summary,
                                            "OpenAPI"));
                                }
                            }
                        }
                    }
                }
                return java.util.Optional.of(new ApiContract(relativePath, format, title, version, paths.size(), paths));
            } else {
                // YAML parsing without external dependency
                String format = "UNKNOWN";
                if (content.contains("openapi:")) {
                    Matcher m = Pattern.compile("openapi:\\s*[\"']?([0-9]+)").matcher(content);
                    format = m.find() ? "OPENAPI_V" + m.group(1) : "OPENAPI_V3";
                } else if (content.contains("swagger:")) {
                    format = "SWAGGER_V2";
                } else {
                    return java.util.Optional.empty();
                }

                String title = "API Spec";
                Matcher titleMatcher = Pattern.compile("title:\\s*[\"']?([^\"'\r\n]+)[\"']?").matcher(content);
                if (titleMatcher.find()) title = titleMatcher.group(1).trim();

                String version = "1.0.0";
                Matcher verMatcher = Pattern.compile("version:\\s*[\"']?([^\"'\r\n]+)[\"']?").matcher(content);
                if (verMatcher.find()) version = verMatcher.group(1).trim();

                boolean hasGlobalSecurity = content.contains("security:")
                        || content.contains("securitySchemes:")
                        || content.contains("securityDefinitions:")
                        || content.contains("bearerAuth")
                        || content.contains("oauth2")
                        || content.contains("ApiKey")
                        || content.contains("jwt");

                List<String> paths = new ArrayList<>();
                String[] lines = content.split("\n");
                boolean inPaths = false;
                String currentPath = null;
                for (int idx = 0; idx < lines.length; idx++) {
                    String line = lines[idx];
                    if (line.matches("^paths:\\s*.*")) {
                        inPaths = true;
                        continue;
                    }
                    if (inPaths) {
                        if (line.matches("^[a-zA-Z0-9_-]+:\\s*.*") && !line.startsWith(" ")) {
                            inPaths = false;
                            continue;
                        }
                        Matcher pm = Pattern.compile("^\\s{2}(/[^:]+):\\s*").matcher(line);
                        if (pm.find()) {
                            currentPath = pm.group(1).trim();
                            paths.add(currentPath);
                            continue;
                        }
                        if (currentPath != null) {
                            Matcher methodMatcher = Pattern.compile("^\\s{4}(get|post|put|delete|patch|options|head):\\s*").matcher(line);
                            if (methodMatcher.find()) {
                                String method = methodMatcher.group(1).toUpperCase();
                                boolean auth = hasGlobalSecurity && !line.contains("security: []");
                                endpoints.add(new ApiEndpoint(
                                        method,
                                        currentPath,
                                        auth,
                                        auth ? "OPENAPI_SECURITY" : "NONE",
                                        ApiVisibility.UNKNOWN,
                                        relativePath,
                                        idx + 1,
                                        "OPENAPI_SPEC",
                                        null,
                                        null,
                                        "OpenAPI"));
                            }
                        }
                    }
                }

                return java.util.Optional.of(new ApiContract(relativePath, format, title, version, paths.size(), paths));
            }
        } catch (Exception e) {
            return java.util.Optional.empty();
        }
    }

    private static void extractIngressPaths(Path file, Set<String> publicPaths) {
        try {
            String content = Files.readString(file, StandardCharsets.UTF_8);
            if (!content.contains("kind: Ingress") && !content.contains("kind: \"Ingress\"")) {
                return;
            }
            Pattern pathPattern = Pattern.compile("path:\\s*([/a-zA-Z0-9_{}-]+)");
            Matcher matcher = pathPattern.matcher(content);
            while (matcher.find()) {
                publicPaths.add(matcher.group(1).trim());
            }
        } catch (Exception ignored) {}
    }

    private static boolean matchesAnyIngress(String path, Set<String> publicPaths) {
        for (String pub : publicPaths) {
            if (path.equals(pub)) return true;
            String prefix = pub.endsWith("/") ? pub : pub + "/";
            if (path.startsWith(prefix)) return true;
            if (pub.endsWith("/*") || pub.endsWith("/**")) {
                String p = pub.substring(0, pub.indexOf("/*"));
                if (path.startsWith(p)) return true;
            }
        }
        return false;
    }

    private static boolean isTestPath(String relativePath) {
        if (relativePath == null) return false;
        String lower = relativePath.toLowerCase().replace('\\', '/');
        return lower.contains("/src/test/")
                || lower.startsWith("src/test/")
                || lower.contains("/test/")
                || lower.startsWith("test/")
                || lower.contains("/tests/")
                || lower.startsWith("tests/")
                || lower.contains("/__tests__/")
                || lower.contains("/spec/")
                || lower.contains("/specs/")
                || lower.contains("/fixtures/")
                || lower.endsWith("test.java")
                || lower.endsWith("tests.java")
                || lower.endsWith("spec.java")
                || lower.endsWith(".test.ts")
                || lower.endsWith(".spec.ts")
                || lower.endsWith(".test.js")
                || lower.endsWith(".spec.js");
    }

    private static String stripComments(String code) {
        if (code == null) return "";
        StringBuilder sb = new StringBuilder(code.length());
        int len = code.length();
        boolean inBlock = false;
        boolean inLine = false;
        boolean inString = false;
        boolean inChar = false;

        for (int i = 0; i < len; i++) {
            char c = code.charAt(i);
            char next = (i + 1 < len) ? code.charAt(i + 1) : '\0';

            if (inBlock) {
                if (c == '*' && next == '/') {
                    inBlock = false;
                    sb.append("  ");
                    i++;
                } else {
                    sb.append(c == '\n' ? '\n' : ' ');
                }
            } else if (inLine) {
                if (c == '\n') {
                    inLine = false;
                    sb.append('\n');
                } else {
                    sb.append(' ');
                }
            } else if (inString) {
                sb.append(c);
                if (c == '\\' && i + 1 < len) {
                    sb.append(code.charAt(++i));
                } else if (c == '"') {
                    inString = false;
                }
            } else if (inChar) {
                sb.append(c);
                if (c == '\\' && i + 1 < len) {
                    sb.append(code.charAt(++i));
                } else if (c == '\'') {
                    inChar = false;
                }
            } else {
                if (c == '/' && next == '*') {
                    inBlock = true;
                    sb.append("  ");
                    i++;
                } else if (c == '/' && next == '/') {
                    inLine = true;
                    sb.append("  ");
                    i++;
                } else {
                    if (c == '"') inString = true;
                    else if (c == '\'') inChar = true;
                    sb.append(c);
                }
            }
        }
        return sb.toString();
    }

    // Java Spring Boot / JAX-RS Controller Parser
    private static void extractJavaSpringEndpoints(Path file, String relativePath, List<ApiEndpoint> endpoints) throws IOException {
        String rawContent = Files.readString(file, StandardCharsets.UTF_8);
        String content = stripComments(rawContent);

        if (!content.contains("@RestController") && !content.contains("@Controller")
                && !content.contains("@RequestMapping") && !content.contains("@Path")) {
            return;
        }

        String classPrefix = "";
        int classIdx = -1;
        Matcher cm = Pattern.compile("\\b(?:public|protected|private)?\\s*(?:final|abstract|sealed)?\\s*\\b(?:class|interface|record)\\s+([A-Za-z0-9_]+)").matcher(content);
        if (cm.find()) {
            classIdx = cm.start();
        }

        if (classIdx > 0) {
            String header = content.substring(0, classIdx);
            Matcher hm = Pattern.compile("@(?:RequestMapping|Path)\\s*(?:\\(([^)]*)\\))?").matcher(header);
            if (hm.find()) {
                classPrefix = extractPathFromAnnotationParams(hm.group(1));
            }
        }

        boolean classAuthRequired = classIdx > 0 && (
                content.substring(0, classIdx).contains("@PreAuthorize")
                        || content.substring(0, classIdx).contains("@Secured")
                        || content.substring(0, classIdx).contains("@RolesAllowed")
                        || content.substring(0, classIdx).contains("@RequiresAccount")
                        || content.substring(0, classIdx).contains("@RequiresAdministrator")
                        || content.substring(0, classIdx).contains("@RequiresAgentKey")
                        || content.substring(0, classIdx).contains("@RequiresSecurityLead")
        );

        Pattern methodPattern = Pattern.compile("@(GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping|RequestMapping|GET|POST|PUT|DELETE|PATCH)\\b(?:\\s*\\(([^)]*)\\))?");
        Matcher m = methodPattern.matcher(content);

        while (m.find()) {
            if (classIdx > 0 && m.start() < classIdx) {
                continue;
            }

            String annotation = m.group(1);
            String params = m.group(2);
            String subPath = extractPathFromAnnotationParams(params);

            String httpMethod = switch (annotation) {
                case "GetMapping", "GET" -> "GET";
                case "PostMapping", "POST" -> "POST";
                case "PutMapping", "PUT" -> "PUT";
                case "DeleteMapping", "DELETE" -> "DELETE";
                case "PatchMapping", "PATCH" -> "PATCH";
                default -> extractMethodFromRequestMappingParams(params);
            };

            String fullPath = combinePaths(classPrefix, subPath);
            int fullLineNum = getLineNumber(content, m.start());

            int lastBrace = content.lastIndexOf('}', m.start());
            int searchStart = Math.max(lastBrace >= 0 ? lastBrace : (classIdx > 0 ? classIdx : 0), m.start() - 500);
            int nextBrace = content.indexOf('{', m.end());
            int searchEnd = nextBrace > 0 ? Math.min(nextBrace, m.end() + 200) : m.end();
            String methodContext = content.substring(searchStart, searchEnd);

            boolean isExplicitPublic = methodContext.contains("@OpenToAnonymous")
                    || methodContext.contains("@PermitAll")
                    || isKnownPublicPath(fullPath);

            boolean hasMethodAuth = methodContext.contains("@PreAuthorize")
                    || methodContext.contains("@Secured")
                    || methodContext.contains("@RolesAllowed")
                    || methodContext.contains("@RequiresAccount")
                    || methodContext.contains("@RequiresAdministrator")
                    || methodContext.contains("@RequiresAgentKey")
                    || methodContext.contains("@RequiresSecurityLead")
                    || methodContext.contains("@AuthenticationPrincipal")
                    || methodContext.contains("Principal principal")
                    || methodContext.contains("VectispirePrincipal");

            boolean methodAuth = !isExplicitPublic && (classAuthRequired || hasMethodAuth);
            String authType = methodAuth
                    ? (methodContext.contains("@RequiresAgentKey") || fullPath.startsWith("/api/v1/agent") ? "API_KEY" : "SPRING_SECURITY")
                    : "NONE";

            endpoints.add(new ApiEndpoint(
                    httpMethod,
                    fullPath,
                    methodAuth,
                    authType,
                    ApiVisibility.UNKNOWN,
                    relativePath,
                    fullLineNum,
                    "SPRING_BOOT",
                    null,
                    null,
                    "Java/Spring"));
        }
    }

    private static boolean isKnownPublicPath(String path) {
        if (path == null) return false;
        return path.equals("/api/v1/auth/login")
                || path.equals("/api/v1/auth/methods")
                || path.equals("/api/v1/auth/session/exchange")
                || path.startsWith("/actuator/health")
                || path.equals("/api/v1/crypto/public-key.pub")
                || (path.startsWith("/api/v1/scorecards/repositories/") && path.endsWith("/badge.svg"));
    }

    private static String extractPathFromAnnotationParams(String params) {
        if (params == null || params.isBlank()) return "";
        Matcher sm = Pattern.compile("[\"']([^\"']+)[\"']").matcher(params);
        if (sm.find()) {
            return sm.group(1).trim();
        }
        return "";
    }

    private static String extractMethodFromRequestMappingParams(String params) {
        if (params == null) return "ALL";
        if (params.contains("RequestMethod.GET")) return "GET";
        if (params.contains("RequestMethod.POST")) return "POST";
        if (params.contains("RequestMethod.PUT")) return "PUT";
        if (params.contains("RequestMethod.DELETE")) return "DELETE";
        if (params.contains("RequestMethod.PATCH")) return "PATCH";
        return "ALL";
    }

    private static int getLineNumber(String content, int offset) {
        int line = 1;
        for (int i = 0; i < offset && i < content.length(); i++) {
            if (content.charAt(i) == '\n') line++;
        }
        return line;
    }

    // Node (Express / NestJS) Parser
    private static void extractNodeEndpoints(Path file, String relativePath, List<ApiEndpoint> endpoints) throws IOException {
        String content = Files.readString(file, StandardCharsets.UTF_8);
        String[] lines = content.split("\n");

        Pattern expressPattern = Pattern.compile("(?:app|router)\\.(get|post|put|delete|patch)\\s*\\(\\s*['\"`]([^'\"`]+)['\"`]");
        Pattern nestPattern = Pattern.compile("@(Get|Post|Put|Delete|Patch)\\s*\\(\\s*['\"`]?([^'\"`]*)['\"`]?\\s*\\)");

        String nestPrefix = "";
        Pattern nestController = Pattern.compile("@Controller\\s*\\(\\s*['\"`]?([^'\"`]*)['\"`]?\\s*\\)");
        Matcher nestCtrlMatcher = nestController.matcher(content);
        if (nestCtrlMatcher.find()) {
            nestPrefix = nestCtrlMatcher.group(1);
        }

        for (int i = 0; i < lines.length; i++) {
            String line = lines[i];
            Matcher em = expressPattern.matcher(line);
            if (em.find()) {
                String method = em.group(1).toUpperCase();
                String path = em.group(2);
                boolean auth = line.contains("auth") || line.contains("jwt") || line.contains("passport") || line.contains("guard");
                endpoints.add(new ApiEndpoint(
                        method, path, auth, auth ? "JWT/MIDDLEWARE" : "NONE",
                        ApiVisibility.UNKNOWN, relativePath, i + 1, "EXPRESS", null, null, "Node/Express"));
            }

            Matcher nm = nestPattern.matcher(line);
            if (nm.find()) {
                String method = nm.group(1).toUpperCase();
                String path = nm.group(2);
                String fullPath = combinePaths(nestPrefix, path);
                boolean auth = content.contains("@UseGuards") || line.contains("Guard");
                endpoints.add(new ApiEndpoint(
                        method, fullPath, auth, auth ? "NEST_GUARD" : "NONE",
                        ApiVisibility.UNKNOWN, relativePath, i + 1, "NESTJS", null, null, "Node/NestJS"));
            }
        }
    }

    // Python (FastAPI / Flask) Parser
    private static void extractPythonEndpoints(Path file, String relativePath, List<ApiEndpoint> endpoints) throws IOException {
        String content = Files.readString(file, StandardCharsets.UTF_8);
        String[] lines = content.split("\n");

        Pattern fastapiPattern = Pattern.compile("@(?:app|router)\\.(get|post|put|delete|patch)\\s*\\(\\s*['\"`]([^'\"`]+)['\"`]");
        Pattern flaskPattern = Pattern.compile("@app\\.route\\s*\\(\\s*['\"`]([^'\"`]+)['\"`]");

        for (int i = 0; i < lines.length; i++) {
            String line = lines[i];
            Matcher fm = fastapiPattern.matcher(line);
            if (fm.find()) {
                String method = fm.group(1).toUpperCase();
                String path = fm.group(2);
                boolean auth = line.contains("Depends") || line.contains("Security") || line.contains("auth");
                endpoints.add(new ApiEndpoint(
                        method, path, auth, auth ? "FASTAPI_DEPENDS" : "NONE",
                        ApiVisibility.UNKNOWN, relativePath, i + 1, "FASTAPI", null, null, "Python/FastAPI"));
            }

            Matcher flm = flaskPattern.matcher(line);
            if (flm.find()) {
                String path = flm.group(1);
                boolean auth = (i > 0 && lines[i - 1].contains("login_required")) || (i + 1 < lines.length && lines[i + 1].contains("login_required"));
                endpoints.add(new ApiEndpoint(
                        "GET", path, auth, auth ? "FLASK_LOGIN" : "NONE",
                        ApiVisibility.UNKNOWN, relativePath, i + 1, "FLASK", null, null, "Python/Flask"));
            }
        }
    }

    // Go (Gin) Parser
    private static void extractGoEndpoints(Path file, String relativePath, List<ApiEndpoint> endpoints) throws IOException {
        String content = Files.readString(file, StandardCharsets.UTF_8);
        String[] lines = content.split("\n");

        Pattern ginPattern = Pattern.compile("(?:r|router|engine|group|api)\\.(GET|POST|PUT|DELETE|PATCH)\\s*\\(\\s*[\"']([^\"']+)[\"']");

        for (int i = 0; i < lines.length; i++) {
            String line = lines[i];
            Matcher gm = ginPattern.matcher(line);
            if (gm.find()) {
                String method = gm.group(1).toUpperCase();
                String path = gm.group(2);
                boolean auth = line.contains("Auth") || line.contains("JWT") || line.contains("Middleware");
                endpoints.add(new ApiEndpoint(
                        method, path, auth, auth ? "GIN_MIDDLEWARE" : "NONE",
                        ApiVisibility.UNKNOWN, relativePath, i + 1, "GIN", null, null, "Go/Gin"));
            }
        }
    }

    private static String combinePaths(String prefix, String sub) {
        if (prefix == null) prefix = "";
        if (sub == null) sub = "";
        prefix = prefix.trim();
        sub = sub.trim();

        if (prefix.endsWith("/")) prefix = prefix.substring(0, prefix.length() - 1);
        if (sub.startsWith("/")) sub = sub.substring(1);

        String combined = prefix + "/" + sub;
        if (!combined.startsWith("/")) combined = "/" + combined;
        if (combined.length() > 1 && combined.endsWith("/")) {
            combined = combined.substring(0, combined.length() - 1);
        }
        return combined.isEmpty() ? "/" : combined;
    }
}
