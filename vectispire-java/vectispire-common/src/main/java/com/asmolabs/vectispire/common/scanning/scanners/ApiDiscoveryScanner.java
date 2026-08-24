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
            ".git", "node_modules", "target", "build", ".gradle", "dist", "vendor", ".idea", ".vscode");

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
                    if (IGNORED_DIRS.contains(name)) {
                        return FileVisitResult.SKIP_SUBTREE;
                    }
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                    String name = file.getFileName().toString().toLowerCase();
                    String relativePath = workspaceRoot.relativize(file).toString();

                    try {
                        // 1. Contract discovery (OpenAPI / Swagger)
                        if (isOpenApiOrSwagger(name)) {
                            parseContract(file, relativePath).ifPresent(contracts::add);
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

        // Reconcile visibility if Ingress paths were found
        List<ApiEndpoint> adjusted = new ArrayList<>();
        for (ApiEndpoint ep : endpoints) {
            if (publicIngressPaths.contains(ep.path()) || matchesAnyIngress(ep.path(), publicIngressPaths)) {
                adjusted.add(new ApiEndpoint(
                        ep.method(), ep.path(), ep.authRequired(), ep.authType(),
                        ApiVisibility.PUBLIC, ep.filePath(), ep.lineNumber(),
                        ep.framework(), ep.operationId(), ep.summary(), ep.tags()));
            } else {
                adjusted.add(ep);
            }
        }

        return new Result(List.copyOf(adjusted), List.copyOf(contracts));
    }

    private static boolean isOpenApiOrSwagger(String filename) {
        return filename.contains("openapi") || filename.contains("swagger")
                || filename.equals("api-docs.json") || filename.equals("api.json");
    }

    private static java.util.Optional<ApiContract> parseContract(Path file, String relativePath) {
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
                if (root.has("paths") && root.get("paths").isObject()) {
                    Iterator<String> fieldNames = root.get("paths").fieldNames();
                    while (fieldNames.hasNext()) {
                        paths.add(fieldNames.next());
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

                List<String> paths = new ArrayList<>();
                String[] lines = content.split("\n");
                boolean inPaths = false;
                for (String line : lines) {
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
                            paths.add(pm.group(1).trim());
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

    // Java Spring Boot Controller Parser
    private static void extractJavaSpringEndpoints(Path file, String relativePath, List<ApiEndpoint> endpoints) throws IOException {
        String content = Files.readString(file, StandardCharsets.UTF_8);
        if (!content.contains("@RestController") && !content.contains("@Controller")) {
            return;
        }

        String classPrefix = "";
        Pattern classMappingPattern = Pattern.compile("@RequestMapping\\s*\\(\\s*(?:value\\s*=\\s*)?[\"']([^\"']+)[\"']\\s*\\)\\s*(?:public\\s+|private\\s+|protected\\s+)?(?:class|record|interface)");
        Matcher classMatcher = classMappingPattern.matcher(content);
        if (classMatcher.find()) {
            classPrefix = classMatcher.group(1);
        } else {
            int classIdx = content.indexOf("class ");
            if (classIdx > 0) {
                String header = content.substring(0, classIdx);
                Matcher hm = Pattern.compile("@RequestMapping\\s*\\(\\s*(?:value\\s*=\\s*)?[\"']([^\"']+)[\"']").matcher(header);
                if (hm.find()) {
                    classPrefix = hm.group(1);
                }
            }
        }

        int classIdx = content.indexOf("class ");
        boolean classAuthRequired = false;
        if (classIdx > 0) {
            String header = content.substring(0, classIdx);
            classAuthRequired = header.contains("@PreAuthorize") || header.contains("@Secured") || header.contains("@RolesAllowed");
        }

        String[] lines = content.split("\n");
        Pattern methodMappingPattern = Pattern.compile("@(GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping|RequestMapping)\\s*(?:\\(\\s*(?:value\\s*=\\s*|path\\s*=\\s*)?[\"']?([^\"')\\s]*)[\"']?\\s*\\))?");

        int firstClassLine = -1;
        for (int i = 0; i < lines.length; i++) {
            if (lines[i].contains("class ") || lines[i].contains("interface ") || lines[i].contains("record ")) {
                firstClassLine = i;
                break;
            }
        }
        if (firstClassLine < 0) return;

        for (int i = firstClassLine + 1; i < lines.length; i++) {
            String line = lines[i];

            Matcher m = methodMappingPattern.matcher(line);
            if (m.find()) {
                String annotation = m.group(1);
                String subPath = m.group(2) != null ? m.group(2) : "";
                if (subPath.equals("\"\"")) subPath = "";

                String httpMethod = switch (annotation) {
                    case "GetMapping" -> "GET";
                    case "PostMapping" -> "POST";
                    case "PutMapping" -> "PUT";
                    case "DeleteMapping" -> "DELETE";
                    case "PatchMapping" -> "PATCH";
                    default -> "ALL";
                };

                String fullPath = combinePaths(classPrefix, subPath);
                boolean methodAuth = classAuthRequired
                        || (i > 0 && lines[i - 1].contains("@PreAuthorize"))
                        || (i > 1 && lines[i - 2].contains("@PreAuthorize"))
                        || (i + 1 < lines.length && lines[i + 1].contains("@PreAuthorize"));

                endpoints.add(new ApiEndpoint(
                        httpMethod,
                        fullPath,
                        methodAuth,
                        methodAuth ? "SPRING_SECURITY" : "NONE",
                        ApiVisibility.UNKNOWN,
                        relativePath,
                        i + 1,
                        "SPRING_BOOT",
                        null,
                        null,
                        "Java/Spring"));
            }
        }
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
