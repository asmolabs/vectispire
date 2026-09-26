package com.asmolabs.vectispire.common.scanning.scanners;

import com.asmolabs.vectispire.common.scanning.AnalysisBudget;
import com.asmolabs.vectispire.common.scanning.ScannerFailureException;
import com.asmolabs.vectispire.common.scanning.SourceFiles;
import java.util.Locale;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.asmolabs.vectispire.common.domain.apis.ApiContract;
import com.asmolabs.vectispire.common.domain.apis.ApiEndpoint;
import com.asmolabs.vectispire.common.domain.apis.ApiVisibility;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.function.LongSupplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Static discovery of API endpoints and declared contracts in a cloned repository.
 */
public final class ApiDiscoveryScanner {

    private static final Logger log = LoggerFactory.getLogger(ApiDiscoveryScanner.class);

    private static final ObjectMapper JSON_MAPPER = new ObjectMapper();

    private static final Set<String> IGNORED_DIRS = Set.of(
            ".git", "node_modules", "target", "build", ".gradle", "dist", "vendor",
            ".idea", ".vscode", "test", "tests", "__tests__", "spec", "specs", "fixtures", "testdata");

    public record Result(List<ApiEndpoint> endpoints, List<ApiContract> contracts) {}

    /**
     * How long the whole discovery may run before it is abandoned as failed.
     *
     * <p>Each file's patterns are bounded by an {@link AnalysisBudget}; this bounds what no single
     * file decides — the number of files, and the reconciliation of every endpoint against every
     * ingress path, which grows with the product of the two. Five minutes is far beyond what the
     * linear passes take on a large repository, and far short of leaving a worker pinned for the
     * rest of the day. Abandoned means failed, not empty: a partial list would retire the endpoints
     * the discovery did not reach (decision 0007).
     */
    static final Duration DEADLINE = Duration.ofMinutes(5);

    private static final String STEP = "api discovery";

    public static Result scan(Path workspaceRoot) {
        return scan(workspaceRoot, DEADLINE, System::nanoTime);
    }

    static Result scan(Path workspaceRoot, Duration deadline, LongSupplier nanoClock) {
        long giveUpAt = nanoClock.getAsLong() + deadline.toNanos();
        // A root that is not there — a sub-path absent from this checkout — means nothing was
        // looked at. Answering with empty lists said "looked, found no API".
        if (workspaceRoot == null || !Files.isDirectory(workspaceRoot)) {
            throw new java.io.UncheckedIOException(new java.nio.file.NoSuchFileException(
                    String.valueOf(workspaceRoot), null, "no source tree to discover APIs in"));
        }

        List<ApiEndpoint> endpoints = new ArrayList<>();
        List<ApiContract> contracts = new ArrayList<>();
        Set<String> publicIngressPaths = new HashSet<>();

        try {
            Files.walkFileTree(workspaceRoot, new SimpleFileVisitor<>() {
                @Override
                public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) {
                    String name = dir.getFileName() != null ? dir.getFileName().toString() : "";
                    if (IGNORED_DIRS.contains(name.toLowerCase(Locale.ROOT))) {
                        return FileVisitResult.SKIP_SUBTREE;
                    }
                    String rel = workspaceRoot.relativize(dir).toString().replace('\\', '/').toLowerCase(Locale.ROOT);
                    if (rel.startsWith("src/test") || rel.contains("/src/test/") || rel.startsWith("test") || rel.contains("/test/")) {
                        return FileVisitResult.SKIP_SUBTREE;
                    }
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                    requireTime(nanoClock, giveUpAt, deadline);
                    // Links and oversized files are not read: see SourceFiles for what a committed
                    // `a.js -> /dev/zero` did to the process running this walk.
                    if (!SourceFiles.isReadable(attrs)) {
                        return FileVisitResult.CONTINUE;
                    }
                    String name = file.getFileName().toString().toLowerCase(Locale.ROOT);
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
                    } catch (AnalysisBudget.Exhausted pathological) {
                        // At warn: a file whose shape defeats the patterns is either an attempt to
                        // pin the worker or a defect in a pattern, and either is worth reading.
                        log.warn("API discovery skipped {}: {}", relativePath, pathological.getMessage());
                    } catch (Exception unreadable) {
                        // One malformed file does not abort the discovery — it is a property of the
                        // scanned code, not a failure of the scanner — but it is no longer silent.
                        log.debug("API discovery skipped {}: {}", relativePath, unreadable.getMessage());
                    }
                    return FileVisitResult.CONTINUE;
                }
            });
        } catch (IOException unwalkable) {
            // Thrown, not answered with empty lists: empty is "looked and found no API", which
            // replaces the repository's recorded contracts with nothing.
            throw new java.io.UncheckedIOException("The source tree could not be walked for API discovery.", unwalkable);
        }

        // Reconcile visibility if Ingress paths were found and deduplicate endpoints
        Set<String> seen = new HashSet<>();
        List<ApiEndpoint> adjusted = new ArrayList<>();
        for (ApiEndpoint ep : endpoints) {
            requireTime(nanoClock, giveUpAt, deadline);
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

    private static void requireTime(LongSupplier nanoClock, long giveUpAt, Duration deadline) {
        if (nanoClock.getAsLong() - giveUpAt > 0) {
            throw ScannerFailureException.timedOut(STEP, deadline);
        }
    }

    /** Bounded and link-refusing; a file the walk admitted but that changed since is skipped. */
    private static String readSource(Path file) throws IOException {
        return SourceFiles.readText(file).orElseThrow(() -> new IOException("not a readable source file"));
    }

    private static boolean isOpenApiOrSwagger(String filename) {
        return filename.contains("openapi") || filename.contains("swagger")
                || filename.equals("api-docs.json") || filename.equals("api.json");
    }

    private static java.util.Optional<ApiContract> parseContract(Path file, String relativePath, List<ApiEndpoint> endpoints) {
        try {
            String content = readSource(file);
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
                                String methodKey = methodNames.next().toUpperCase(Locale.ROOT);
                                if (Set.of("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD").contains(methodKey)) {
                                    JsonNode opNode = pathObj.get(methodKey.toLowerCase(Locale.ROOT));
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
                AnalysisBudget budget = AnalysisBudget.forContent(content);
                String format = "UNKNOWN";
                if (content.contains("openapi:")) {
                    Matcher m = OPENAPI_VERSION.matcher(budget.guard(content));
                    format = m.find() ? "OPENAPI_V" + m.group(1) : "OPENAPI_V3";
                } else if (content.contains("swagger:")) {
                    format = "SWAGGER_V2";
                } else {
                    return java.util.Optional.empty();
                }

                String title = "API Spec";
                Matcher titleMatcher = YAML_TITLE.matcher(budget.guard(content));
                if (titleMatcher.find()) title = titleMatcher.group(1).trim();

                String version = "1.0.0";
                Matcher verMatcher = YAML_VERSION.matcher(budget.guard(content));
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
                    // A prefix test, where it was `matches("^paths:\\s*.*")`: the two overlapping
                    // quantifiers retried every split of a long run of whitespace, and all the
                    // expression ever decided was the prefix.
                    if (line.startsWith("paths:")) {
                        inPaths = true;
                        continue;
                    }
                    if (inPaths) {
                        if (YAML_TOP_LEVEL_KEY.matcher(budget.guard(line)).lookingAt()) {
                            inPaths = false;
                            continue;
                        }
                        Matcher pm = YAML_PATH.matcher(budget.guard(line));
                        if (pm.find()) {
                            currentPath = pm.group(1).trim();
                            paths.add(currentPath);
                            continue;
                        }
                        if (currentPath != null) {
                            Matcher methodMatcher = YAML_METHOD.matcher(budget.guard(line));
                            if (methodMatcher.find()) {
                                String method = methodMatcher.group(1).toUpperCase(Locale.ROOT);
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
        } catch (Exception unreadable) {
            // A file that looked like a specification and did not parse: said at warn, because it
            // is the one case an operator would want to fix — a contract they believe is inventoried.
            log.warn("API contract {} could not be parsed and is not inventoried: {}", relativePath, unreadable.getMessage());
            return java.util.Optional.empty();
        }
    }

    private static void extractIngressPaths(Path file, Set<String> publicPaths) {
        try {
            String content = readSource(file);
            if (!content.contains("kind: Ingress") && !content.contains("kind: \"Ingress\"")) {
                return;
            }
            Matcher matcher = INGRESS_PATH.matcher(AnalysisBudget.forContent(content).guard(content));
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
        String lower = relativePath.toLowerCase(Locale.ROOT).replace('\\', '/');
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

    /**
     * The first type declaration, whose position splits class-level annotations from methods.
     *
     * <p>The modifiers used to be part of the pattern — two optional words, each followed by an
     * optional run of spaces — and on a file with a long run of spaces and no declaration the
     * engine retried every split of that run from every position: 138 ms for 8,000 spaces,
     * about 36 minutes for a megabyte, on a worker thread with no deadline. The modifiers never
     * changed what was captured, only where the header ended, and the header is only searched
     * for annotations.
     */
    private static final Pattern CLASS_DECLARATION =
            Pattern.compile("\\b(?:class|interface|record)\\s+([A-Za-z0-9_]+)");

    /*
     * Every pattern below reads text of the repository under analysis, so each is written for the
     * input its author would choose rather than the input a controller usually is: no two adjacent
     * quantifiers that can match the same character, possessive where a retry could only re-read
     * what the first attempt read. Each is also handed its file through an AnalysisBudget, which
     * stops the next pattern nobody noticed was super-linear.
     */

    private static final Pattern CLASS_MAPPING = Pattern.compile("@(?:RequestMapping|Path)\\s*+(?:\\(([^)]*+)\\))?");

    /**
     * The route annotation alone; its parameters are delimited by hand in {@link #annotationParams}.
     *
     * <p>They were {@code (?:\s*\(([^)]*)\))?} in the pattern, and on a file with many annotations
     * and no closing parenthesis each one scanned to the end of the file before giving up — a
     * quadratic cost no single quantifier shows.
     */
    private static final Pattern ROUTE_ANNOTATION = Pattern.compile(
            "@(GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping|RequestMapping|GET|POST|PUT|DELETE|PATCH)\\b");

    private static final Pattern QUOTED = Pattern.compile("[\"']([^\"']++)[\"']");

    private static final Pattern OPENAPI_VERSION = Pattern.compile("openapi:\\s*+[\"']?([0-9]+)");
    private static final Pattern YAML_TITLE = Pattern.compile("title:\\s*[\"']?([^\"'\r\n]+)[\"']?");
    private static final Pattern YAML_VERSION = Pattern.compile("version:\\s*[\"']?([^\"'\r\n]+)[\"']?");
    private static final Pattern YAML_TOP_LEVEL_KEY = Pattern.compile("[a-zA-Z0-9_-]++:");
    private static final Pattern YAML_PATH = Pattern.compile("^\\s{2}(/[^:]++):");
    private static final Pattern YAML_METHOD = Pattern.compile("^\\s{4}(get|post|put|delete|patch|options|head):");
    private static final Pattern INGRESS_PATH = Pattern.compile("path:\\s*+([/a-zA-Z0-9_{}-]++)");

    private static final Pattern EXPRESS_ROUTE =
            Pattern.compile("(?:app|router)\\.(get|post|put|delete|patch)\\s*+\\(\\s*+['\"`]([^'\"`]++)['\"`]");

    /**
     * A NestJS route: the annotation, then either nothing or one quoted literal between parentheses.
     *
     * <p>It was {@code \(\s*['"`]?([^'"`]*)['"`]?\s*\)}: the optional quotes let the two runs of
     * whitespace and the unquoted capture all match the same spaces, and a line with a long run of
     * them after {@code @Get(} and no closing parenthesis was retried in every three-way split —
     * cubic, two seconds for 2,000 spaces. The quote is now required to open and to close the
     * literal (a back-reference to the same character), every run is possessive, and an unquoted
     * argument — a constant the discovery could not resolve anyway — is no longer read as a path.
     */
    private static final Pattern NEST_ROUTE =
            Pattern.compile("@(Get|Post|Put|Delete|Patch)\\s*+\\(\\s*+(?:(['\"`])([^'\"`\r\n]*+)\\2)?\\s*+\\)");

    /** The controller's prefix, under the same rule as {@link #NEST_ROUTE}, and read over the whole file. */
    private static final Pattern NEST_CONTROLLER =
            Pattern.compile("@Controller\\s*+\\(\\s*+(?:(['\"`])([^'\"`\r\n]*+)\\1)?\\s*+\\)");

    private static final Pattern FASTAPI_ROUTE =
            Pattern.compile("@(?:app|router)\\.(get|post|put|delete|patch)\\s*+\\(\\s*+['\"`]([^'\"`]++)['\"`]");
    private static final Pattern FLASK_ROUTE = Pattern.compile("@app\\.route\\s*+\\(\\s*+['\"`]([^'\"`]++)['\"`]");
    private static final Pattern GIN_ROUTE =
            Pattern.compile("(?:r|router|engine|group|api)\\.(GET|POST|PUT|DELETE|PATCH)\\s*+\\(\\s*+[\"']([^\"']++)[\"']");

    // Java Spring Boot / JAX-RS Controller Parser
    private static void extractJavaSpringEndpoints(Path file, String relativePath, List<ApiEndpoint> endpoints) throws IOException {
        String rawContent = readSource(file);
        String content = stripComments(rawContent);

        if (!content.contains("@RestController") && !content.contains("@Controller")
                && !content.contains("@RequestMapping") && !content.contains("@Path")) {
            return;
        }
        AnalysisBudget budget = AnalysisBudget.forContent(content);
        CharSequence guarded = budget.guard(content);

        String classPrefix = "";
        int classIdx = -1;
        Matcher cm = CLASS_DECLARATION.matcher(guarded);
        if (cm.find()) {
            classIdx = cm.start();
        }

        if (classIdx > 0) {
            Matcher hm = CLASS_MAPPING.matcher(guarded).region(0, classIdx);
            if (hm.find()) {
                classPrefix = extractPathFromAnnotationParams(hm.group(1), budget);
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

        Matcher m = ROUTE_ANNOTATION.matcher(guarded);
        Neighbourhood around = new Neighbourhood(content);
        int from = 0;

        while (from <= content.length() && m.find(from)) {
            int start = m.start();
            String annotation = m.group(1);
            AnnotationParams annotationParams = around.params(m.end());
            String params = annotationParams.text();
            int end = annotationParams.end();
            from = end;
            if (classIdx > 0 && start < classIdx) {
                continue;
            }

            String subPath = extractPathFromAnnotationParams(params, budget);

            String httpMethod = switch (annotation) {
                case "GetMapping", "GET" -> "GET";
                case "PostMapping", "POST" -> "POST";
                case "PutMapping", "PUT" -> "PUT";
                case "DeleteMapping", "DELETE" -> "DELETE";
                case "PatchMapping", "PATCH" -> "PATCH";
                default -> extractMethodFromRequestMappingParams(params);
            };

            String fullPath = combinePaths(classPrefix, subPath);
            int fullLineNum = around.lineOf(start);

            String methodContext = content.substring(
                    around.contextStart(start, classIdx > 0 ? classIdx : 0), around.contextEnd(end));

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

    private static String extractPathFromAnnotationParams(String params, AnalysisBudget budget) {
        if (params == null || params.isBlank()) return "";
        Matcher sm = QUOTED.matcher(budget.guard(params));
        if (sm.find()) {
            return sm.group(1).trim();
        }
        return "";
    }

    /** An annotation's parameter text, or {@code null} when it has none, and where the annotation ends. */
    private record AnnotationParams(String text, int end) {}

    /**
     * What the Spring parser looks up around each route annotation, each lookup in amortized
     * constant time.
     *
     * <p>They were {@code indexOf}, {@code lastIndexOf} and a count of newlines from the start of the
     * file, once per annotation — linear each, so quadratic over a file of annotations, and the
     * adversarial file is exactly one with thousands of them and none of the characters searched
     * for. The annotations are visited in order, so each search resumes where the previous stopped,
     * and a search that found nothing is not repeated; the results are the ones the unbounded
     * searches gave.
     */
    private static final class Neighbourhood {

        /** How far back and forward a route's annotations and signature are read for its guards. */
        private static final int BEFORE = 500;
        private static final int AFTER = 200;

        private final String content;
        private final int firstClosingBrace;
        private final int lastOpeningBrace;
        /** The next ')' at or after the last searched position; -2 before the first search. */
        private int nextParenthesis = -2;
        private int countedUpTo;
        private int line = 1;

        Neighbourhood(String content) {
            this.content = content;
            this.firstClosingBrace = content.indexOf('}');
            this.lastOpeningBrace = content.lastIndexOf('{');
        }

        /** The parameters of the annotation ending at {@code annotationEnd}: {@code \s*(...)}, or none. */
        AnnotationParams params(int annotationEnd) {
            int cursor = annotationEnd;
            while (cursor < content.length() && isRegexWhitespace(content.charAt(cursor))) {
                cursor++;
            }
            if (cursor >= content.length() || content.charAt(cursor) != '(') {
                return new AnnotationParams(null, annotationEnd);
            }
            // -1 is final: no ')' after an earlier position means none after a later one.
            if (nextParenthesis != -1 && nextParenthesis <= cursor) {
                nextParenthesis = content.indexOf(')', cursor + 1);
            }
            if (nextParenthesis < 0) {
                return new AnnotationParams(null, annotationEnd);
            }
            return new AnnotationParams(content.substring(cursor + 1, nextParenthesis), nextParenthesis + 1);
        }

        /** The 1-based line of an offset; offsets are asked in increasing order. */
        int lineOf(int offset) {
            for (; countedUpTo < offset && countedUpTo < content.length(); countedUpTo++) {
                if (content.charAt(countedUpTo) == '\n') {
                    line++;
                }
            }
            return line;
        }

        /**
         * Where the context read before an annotation starts: the last '}' within {@value #BEFORE}
         * characters, else {@value #BEFORE} characters back — or, when the file has no '}' before the
         * annotation at all, the class declaration if that is nearer.
         */
        int contextStart(int annotationStart, int fallback) {
            int floor = annotationStart - BEFORE;
            for (int i = annotationStart; i >= Math.max(0, floor); i--) {
                if (content.charAt(i) == '}') {
                    return i;
                }
            }
            boolean braceEarlier = firstClosingBrace >= 0 && firstClosingBrace < annotationStart;
            return braceEarlier ? floor : Math.max(fallback, floor);
        }

        /**
         * Where the context read after an annotation ends: the next '{' within {@value #AFTER}
         * characters, else {@value #AFTER} characters on — or the annotation's end when the file has
         * no '{' after it.
         */
        int contextEnd(int annotationEnd) {
            int ceiling = annotationEnd + AFTER;
            for (int i = annotationEnd; i <= ceiling && i < content.length(); i++) {
                if (content.charAt(i) == '{') {
                    return i;
                }
            }
            return lastOpeningBrace > ceiling ? ceiling : annotationEnd;
        }

        /** {@code \s} as {@link Pattern} reads it without flags. */
        private static boolean isRegexWhitespace(char c) {
            return c == ' ' || c == '\t' || c == '\n' || c == 0x0B || c == '\f' || c == '\r';
        }
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

    // Node (Express / NestJS) Parser
    private static void extractNodeEndpoints(Path file, String relativePath, List<ApiEndpoint> endpoints) throws IOException {
        String content = readSource(file);
        String[] lines = content.split("\n");
        AnalysisBudget budget = AnalysisBudget.forContent(content);

        String nestPrefix = "";
        Matcher nestCtrlMatcher = NEST_CONTROLLER.matcher(budget.guard(content));
        if (nestCtrlMatcher.find()) {
            nestPrefix = nestCtrlMatcher.group(2);
        }
        // Once per file: it was asked again for every route, a scan of the whole file each time.
        boolean fileUsesGuards = content.contains("@UseGuards");

        for (int i = 0; i < lines.length; i++) {
            String line = lines[i];
            CharSequence guardedLine = budget.guard(line);
            Matcher em = EXPRESS_ROUTE.matcher(guardedLine);
            if (em.find()) {
                String method = em.group(1).toUpperCase(Locale.ROOT);
                String path = em.group(2);
                boolean auth = line.contains("auth") || line.contains("jwt") || line.contains("passport") || line.contains("guard");
                endpoints.add(new ApiEndpoint(
                        method, path, auth, auth ? "JWT/MIDDLEWARE" : "NONE",
                        ApiVisibility.UNKNOWN, relativePath, i + 1, "EXPRESS", null, null, "Node/Express"));
            }

            Matcher nm = NEST_ROUTE.matcher(guardedLine);
            if (nm.find()) {
                String method = nm.group(1).toUpperCase(Locale.ROOT);
                String path = nm.group(3);
                String fullPath = combinePaths(nestPrefix, path);
                boolean auth = fileUsesGuards || line.contains("Guard");
                endpoints.add(new ApiEndpoint(
                        method, fullPath, auth, auth ? "NEST_GUARD" : "NONE",
                        ApiVisibility.UNKNOWN, relativePath, i + 1, "NESTJS", null, null, "Node/NestJS"));
            }
        }
    }

    // Python (FastAPI / Flask) Parser
    private static void extractPythonEndpoints(Path file, String relativePath, List<ApiEndpoint> endpoints) throws IOException {
        String content = readSource(file);
        String[] lines = content.split("\n");
        AnalysisBudget budget = AnalysisBudget.forContent(content);

        for (int i = 0; i < lines.length; i++) {
            String line = lines[i];
            CharSequence guardedLine = budget.guard(line);
            Matcher fm = FASTAPI_ROUTE.matcher(guardedLine);
            if (fm.find()) {
                String method = fm.group(1).toUpperCase(Locale.ROOT);
                String path = fm.group(2);
                boolean auth = line.contains("Depends") || line.contains("Security") || line.contains("auth");
                endpoints.add(new ApiEndpoint(
                        method, path, auth, auth ? "FASTAPI_DEPENDS" : "NONE",
                        ApiVisibility.UNKNOWN, relativePath, i + 1, "FASTAPI", null, null, "Python/FastAPI"));
            }

            Matcher flm = FLASK_ROUTE.matcher(guardedLine);
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
        String content = readSource(file);
        String[] lines = content.split("\n");
        AnalysisBudget budget = AnalysisBudget.forContent(content);

        for (int i = 0; i < lines.length; i++) {
            String line = lines[i];
            Matcher gm = GIN_ROUTE.matcher(budget.guard(line));
            if (gm.find()) {
                String method = gm.group(1).toUpperCase(Locale.ROOT);
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
