package com.asmolabs.vectispire.common.scanning.scanners;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.apis.ApiContract;
import com.asmolabs.vectispire.common.domain.apis.ApiEndpoint;
import com.asmolabs.vectispire.common.domain.apis.ApiVisibility;
import com.asmolabs.vectispire.common.domain.apis.AttackSurfaceSummary;
import com.asmolabs.vectispire.common.domain.apis.ShadowApiDiff;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ApiDiscoveryScannerTest {

    @Test
    @DisplayName("discovers Spring Boot REST endpoints with annotations and auth")
    void discoversSpringBootEndpoints(@TempDir Path tempDir) throws IOException {
        Path src = tempDir.resolve("src/main/java/com/example/api");
        Files.createDirectories(src);

        String springController = """
                package com.example.api;
                import org.springframework.web.bind.annotation.*;
                import org.springframework.security.access.prepost.PreAuthorize;

                @RestController
                @RequestMapping("/api/v1/users")
                public class UserController {

                    @GetMapping
                    public List<User> listUsers() { return List.of(); }

                    @PreAuthorize("hasRole('ADMIN')")
                    @PostMapping
                    public User createUser(@RequestBody User u) { return u; }

                    @DeleteMapping("/{id}")
                    public void deleteUser(@PathVariable String id) {}
                }
                """;
        Files.writeString(src.resolve("UserController.java"), springController);

        ApiDiscoveryScanner.Result result = ApiDiscoveryScanner.scan(tempDir);
        List<ApiEndpoint> endpoints = result.endpoints();

        assertThat(endpoints).hasSize(3);
        assertThat(endpoints).anySatisfy(ep -> {
            assertThat(ep.method()).isEqualTo("GET");
            assertThat(ep.path()).isEqualTo("/api/v1/users");
            assertThat(ep.authRequired()).isFalse();
            assertThat(ep.framework()).isEqualTo("SPRING_BOOT");
        });
        assertThat(endpoints).anySatisfy(ep -> {
            assertThat(ep.method()).isEqualTo("POST");
            assertThat(ep.path()).isEqualTo("/api/v1/users");
            assertThat(ep.authRequired()).isTrue();
            assertThat(ep.authType()).isEqualTo("SPRING_SECURITY");
        });
        assertThat(endpoints).anySatisfy(ep -> {
            assertThat(ep.method()).isEqualTo("DELETE");
            assertThat(ep.path()).isEqualTo("/api/v1/users/{id}");
        });
    }

    @Test
    @DisplayName("discovers Spring Boot controllers with class-level @RequiresAccount and overrides")
    void discoversRequiresAccountControllers(@TempDir Path tempDir) throws IOException {
        Path src = tempDir.resolve("src/main/java/com/example/api");
        Files.createDirectories(src);

        String springController = """
                package com.example.api;
                import org.springframework.web.bind.annotation.*;
                import com.asmolabs.vectispire.core.access.web.security.RequiresAccount;
                import com.asmolabs.vectispire.core.access.web.security.OpenToAnonymous;

                @RestController
                @RequestMapping("/api/v1/repositories")
                @RequiresAccount
                public class RepositoriesController {

                    @GetMapping
                    public List<String> list() { return List.of(); }

                    @PostMapping("/{id}/scan")
                    public void scan(@PathVariable String id) {}

                    @OpenToAnonymous
                    @GetMapping("/public-status")
                    public String status() { return "OK"; }
                }
                """;
        Files.writeString(src.resolve("RepositoriesController.java"), springController);

        ApiDiscoveryScanner.Result result = ApiDiscoveryScanner.scan(tempDir);
        List<ApiEndpoint> endpoints = result.endpoints();

        assertThat(endpoints).hasSize(3);
        assertThat(endpoints).anySatisfy(ep -> {
            assertThat(ep.method()).isEqualTo("GET");
            assertThat(ep.path()).isEqualTo("/api/v1/repositories");
            assertThat(ep.authRequired()).isTrue();
            assertThat(ep.authType()).isEqualTo("SPRING_SECURITY");
        });
        assertThat(endpoints).anySatisfy(ep -> {
            assertThat(ep.method()).isEqualTo("POST");
            assertThat(ep.path()).isEqualTo("/api/v1/repositories/{id}/scan");
            assertThat(ep.authRequired()).isTrue();
        });
        assertThat(endpoints).anySatisfy(ep -> {
            assertThat(ep.method()).isEqualTo("GET");
            assertThat(ep.path()).isEqualTo("/api/v1/repositories/public-status");
            assertThat(ep.authRequired()).isFalse();
            assertThat(ep.authType()).isEqualTo("NONE");
        });
    }

    @Test
    @DisplayName("discovers Express and NestJS endpoints in TypeScript/JavaScript")
    void discoversNodeEndpoints(@TempDir Path tempDir) throws IOException {
        Path routes = tempDir.resolve("routes");
        Files.createDirectories(routes);

        String expressCode = """
                const express = require('express');
                const router = express.Router();
                router.get('/health', (req, res) => res.send('OK'));
                router.post('/login', authMiddleware, (req, res) => res.json({ token: 'abc' }));
                module.exports = router;
                """;
        Files.writeString(routes.resolve("index.js"), expressCode);

        ApiDiscoveryScanner.Result result = ApiDiscoveryScanner.scan(tempDir);
        List<ApiEndpoint> endpoints = result.endpoints();

        assertThat(endpoints).hasSize(2);
        assertThat(endpoints).anySatisfy(ep -> {
            assertThat(ep.method()).isEqualTo("GET");
            assertThat(ep.path()).isEqualTo("/health");
            assertThat(ep.framework()).isEqualTo("EXPRESS");
            assertThat(ep.isSensitivePath()).isTrue();
        });
        assertThat(endpoints).anySatisfy(ep -> {
            assertThat(ep.method()).isEqualTo("POST");
            assertThat(ep.path()).isEqualTo("/login");
            assertThat(ep.authRequired()).isTrue();
        });
    }

    @Test
    @DisplayName("discovers OpenAPI 3.0 YAML specification contracts")
    void discoversOpenApiContracts(@TempDir Path tempDir) throws IOException {
        String openApiYaml = """
                openapi: 3.0.1
                info:
                  title: Customer API
                  version: 2.1.0
                paths:
                  /api/v1/customers:
                    get:
                      summary: Get customers
                  /api/v1/customers/{id}:
                    get:
                      summary: Get single customer
                """;
        Files.writeString(tempDir.resolve("openapi.yaml"), openApiYaml);

        ApiDiscoveryScanner.Result result = ApiDiscoveryScanner.scan(tempDir);
        List<ApiContract> contracts = result.contracts();

        assertThat(contracts).hasSize(1);
        ApiContract contract = contracts.getFirst();
        assertThat(contract.title()).isEqualTo("Customer API");
        assertThat(contract.version()).isEqualTo("2.1.0");
        assertThat(contract.format()).isEqualTo("OPENAPI_V3");
        assertThat(contract.endpointsCount()).isEqualTo(2);
        assertThat(contract.declaredPaths()).containsExactlyInAnyOrder("/api/v1/customers", "/api/v1/customers/{id}");
    }

    @Test
    @DisplayName("discovers Kubernetes Ingress rules and marks matching endpoints as PUBLIC")
    void discoversKubernetesIngressPublicPaths(@TempDir Path tempDir) throws IOException {
        String ingressYaml = """
                apiVersion: networking.k8s.io/v1
                kind: Ingress
                metadata:
                  name: public-ingress
                spec:
                  rules:
                  - host: api.example.com
                    http:
                      paths:
                      - path: /public/v1
                        pathType: Prefix
                """;
        Files.writeString(tempDir.resolve("ingress.yaml"), ingressYaml);

        String pythonFastApi = """
                from fastapi import FastAPI
                app = FastAPI()
                @app.get("/public/v1/items")
                def items():
                    return []
                @app.get("/internal/health")
                def health():
                    return {}
                """;
        Files.writeString(tempDir.resolve("main.py"), pythonFastApi);

        ApiDiscoveryScanner.Result result = ApiDiscoveryScanner.scan(tempDir);
        List<ApiEndpoint> endpoints = result.endpoints();

        assertThat(endpoints).hasSize(2);
        assertThat(endpoints).anySatisfy(ep -> {
            assertThat(ep.path()).isEqualTo("/public/v1/items");
            assertThat(ep.visibility()).isEqualTo(ApiVisibility.PUBLIC);
        });
        assertThat(endpoints).anySatisfy(ep -> {
            assertThat(ep.path()).isEqualTo("/internal/health");
            assertThat(ep.visibility()).isEqualTo(ApiVisibility.UNKNOWN);
        });
    }

    @Test
    @DisplayName("computes Shadow APIs and Attack Surface metrics accurately")
    void computesShadowApisAndAttackSurface() {
        ApiEndpoint documentedEp = new ApiEndpoint(
                "GET", "/users/{id}", true, "BEARER", ApiVisibility.PUBLIC, "UserController.java", 12, "SPRING_BOOT", null, null, null);
        ApiEndpoint shadowEp = new ApiEndpoint(
                "POST", "/internal/admin/reset", false, "NONE", ApiVisibility.PUBLIC, "AdminController.java", 25, "SPRING_BOOT", null, null, null);

        ApiContract contract = new ApiContract("openapi.json", "OPENAPI_V3", "Core API", "1.0", 2, List.of("/users/{id}", "/legacy/billing"));

        ShadowApiDiff diff = ShadowApiDiff.compute(List.of(documentedEp, shadowEp), List.of(contract));

        assertThat(diff.documentedEndpoints()).containsExactly(documentedEp);
        assertThat(diff.shadowEndpoints()).containsExactly(shadowEp);
        assertThat(diff.zombieEndpoints()).containsExactly("/legacy/billing");

        AttackSurfaceSummary summary = AttackSurfaceSummary.from(List.of(documentedEp, shadowEp), diff);
        assertThat(summary.totalEndpoints()).isEqualTo(2);
        assertThat(summary.publicEndpoints()).isEqualTo(2);
        assertThat(summary.unauthenticatedEndpoints()).isEqualTo(1);
        assertThat(summary.shadowEndpoints()).isEqualTo(1);
        assertThat(summary.sensitiveUnprotectedEndpoints()).isEqualTo(1);
    }

    @Test
    @DisplayName("a tree that cannot be walked is a failure, not an API-free repository")
    void anUnwalkableTreeThrows(@TempDir Path tempDir) {
        // It answered with empty lists, which the inventory reads as "no contracts here" and
        // records by replacing the ones it had (decision 0007).
        Path missing = tempDir.resolve("does-not-exist");

        org.assertj.core.api.Assertions.assertThatThrownBy(() -> ApiDiscoveryScanner.scan(missing))
                .isInstanceOf(java.io.UncheckedIOException.class);
    }

    @Test
    @DisplayName("a file linked from outside the tree, or too large, is not read")
    void linksAndOversizedFilesAreSkipped(@TempDir Path tempDir) throws IOException {
        // A committed `a.js -> /dev/zero` took the process down: readString never reached EOF, and
        // the OutOfMemoryError escaped every catch. A route in a file reached through a link, or in
        // a file past the bound, is therefore not discovered — and the walk finishes.
        Path tree = Files.createDirectory(tempDir.resolve("tree"));
        Path outside = Files.writeString(tempDir.resolve("outside.js"), "app.get('/from-the-host', h);");
        Files.createSymbolicLink(tree.resolve("linked.js"), outside);
        Files.writeString(tree.resolve("big.js"),
                "app.get('/too-large', h);" + " ".repeat((int) com.asmolabs.vectispire.common.scanning.SourceFiles.MAX_BYTES));
        Files.writeString(tree.resolve("ok.js"), "app.get('/ordinary', h);");

        List<String> paths = ApiDiscoveryScanner.scan(tree).endpoints().stream().map(ApiEndpoint::path).toList();

        assertThat(paths).contains("/ordinary").doesNotContain("/from-the-host", "/too-large");
    }

    @Test
    @DisplayName("a controller with a long run of spaces and no class declaration is read in linear time")
    void theClassHeaderSearchIsLinear(@TempDir Path tempDir) throws IOException {
        // Two optional modifiers each followed by an optional run of spaces: 8,000 spaces took
        // 138 ms, a megabyte about 36 minutes, on a worker thread with no deadline.
        Files.writeString(tempDir.resolve("Evil.java"), "@RestController\n" + " ".repeat(1_000_000));

        long started = System.nanoTime();
        ApiDiscoveryScanner.scan(tempDir);
        assertThat((System.nanoTime() - started) / 1_000_000).as("milliseconds").isLessThan(2_000);
    }

    @Test
    @DisplayName("a NestJS controller prefix is found past an unclosed @Controller( followed by a long run of spaces")
    void theNestControllerPrefixDoesNotBacktrack(@TempDir Path tempDir) throws IOException {
        // Three quantifiers that could all match the same spaces: 2,000 of them took two seconds,
        // growing with the cube. The real prefix below is only reached once the first occurrence
        // has failed — within the file's analysis budget, or the file is skipped.
        Files.writeString(tempDir.resolve("users.controller.ts"),
                "@Controller(" + " ".repeat(20_000) + "x\n"
                        + "@Controller('api')\n"
                        + "export class UsersController {\n"
                        + "  @Get('users') list() {}\n"
                        + "}\n");

        List<String> paths = withinSeconds(() -> ApiDiscoveryScanner.scan(tempDir)).endpoints().stream()
                .map(ApiEndpoint::path).toList();

        assertThat(paths).containsExactly("/api/users");
    }

    @Test
    @DisplayName("a NestJS route is found on a line after one holding @Get( and a long run of spaces")
    void theNestRouteDoesNotBacktrack(@TempDir Path tempDir) throws IOException {
        Files.writeString(tempDir.resolve("items.controller.ts"),
                "@Controller('shop')\n"
                        + "export class ItemsController {\n"
                        + "  @Get(" + " ".repeat(20_000) + "\n"
                        + "  @Post('items') create() {}\n"
                        + "}\n");

        List<ApiEndpoint> endpoints = withinSeconds(() -> ApiDiscoveryScanner.scan(tempDir)).endpoints();

        assertThat(endpoints).extracting(ApiEndpoint::method, ApiEndpoint::path)
                .containsExactly(org.assertj.core.groups.Tuple.tuple("POST", "/shop/items"));
    }

    @Test
    @DisplayName("NestJS routes keep their literal: quoted in any of the three quote styles, or none at all")
    void nestRoutesKeepTheirShape(@TempDir Path tempDir) throws IOException {
        Files.writeString(tempDir.resolve("orders.controller.ts"), """
                @Controller( "orders" )
                export class OrdersController {
                  @Get() list() {}
                  @Get(':id') one() {}
                  @Put(`:id`) update() {}
                  @Delete( ":id" ) remove() {}
                }
                """);

        List<ApiEndpoint> endpoints = ApiDiscoveryScanner.scan(tempDir).endpoints();

        assertThat(endpoints).extracting(ApiEndpoint::method, ApiEndpoint::path).containsExactlyInAnyOrder(
                org.assertj.core.groups.Tuple.tuple("GET", "/orders"),
                org.assertj.core.groups.Tuple.tuple("GET", "/orders/:id"),
                org.assertj.core.groups.Tuple.tuple("PUT", "/orders/:id"),
                org.assertj.core.groups.Tuple.tuple("DELETE", "/orders/:id"));
    }

    @Test
    @DisplayName("a Spring controller of many annotations and no closing parenthesis is read in linear time")
    void routeAnnotationsWithoutClosingParenthesesAreLinear(@TempDir Path tempDir) throws IOException {
        // Each annotation's parameters scanned to the end of the file before giving up, and each
        // route searched the whole file backwards for a brace and counted its line from the start:
        // three quadratic costs, none of them visible in a single quantifier.
        // The shortest route annotation, as many as the size bound admits: the unbounded searches
        // are vectorized and fast per character, so only the number of them shows.
        Files.writeString(tempDir.resolve("Evil.java"),
                "@RestController\nclass Evil {\n" + "@GET(".repeat(400_000));

        List<ApiEndpoint> endpoints = withinSeconds(() -> ApiDiscoveryScanner.scan(tempDir)).endpoints();

        assertThat(endpoints).extracting(ApiEndpoint::method, ApiEndpoint::path)
                .containsExactly(org.assertj.core.groups.Tuple.tuple("GET", "/"));
    }

    @Test
    @DisplayName("Spring routes keep their line numbers and the guards read around them")
    void springRoutesKeepTheirContext(@TempDir Path tempDir) throws IOException {
        Files.writeString(tempDir.resolve("Accounts.java"), """
                @RestController
                @RequestMapping(value = "/accounts", produces = "application/json")
                class Accounts {
                    @GetMapping
                    List<String> list() { return List.of(); }

                    @PreAuthorize("hasRole('ADMIN')")
                    @PostMapping(path = "/{id}/lock", consumes = MediaType.of("x"))
                    void lock() {}

                    @RequestMapping(value = "/legacy", method = RequestMethod.PUT)
                    void legacy(Principal principal) {}
                }
                """);

        List<ApiEndpoint> endpoints = ApiDiscoveryScanner.scan(tempDir).endpoints();

        assertThat(endpoints).extracting(
                        ApiEndpoint::method, ApiEndpoint::path, ApiEndpoint::lineNumber, ApiEndpoint::authRequired)
                .containsExactlyInAnyOrder(
                        org.assertj.core.groups.Tuple.tuple("GET", "/accounts", 4, false),
                        org.assertj.core.groups.Tuple.tuple("POST", "/accounts/{id}/lock", 8, true),
                        org.assertj.core.groups.Tuple.tuple("PUT", "/accounts/legacy", 11, true));
    }

    @Test
    @DisplayName("an OpenAPI document whose lines end in a long run of spaces and a separator is read in linear time")
    void yamlLinesAreReadInLinearTime(@TempDir Path tempDir) throws IOException {
        // `matches("^paths:\\s*.*")` retried every split of the run between its two quantifiers
        // when the line held a character `.` does not match.
        String run = " ".repeat(150_000) + "\u2028x";
        Files.writeString(tempDir.resolve("openapi.yaml"),
                "openapi: 3.0.0\n"
                        + "paths:" + run + "\n"
                        + "  /items:\n"
                        + "    get:\n"
                        + "components:" + run + "\n");

        List<ApiContract> contracts = withinSeconds(() -> ApiDiscoveryScanner.scan(tempDir)).contracts();

        assertThat(contracts).singleElement().satisfies(contract ->
                assertThat(contract.declaredPaths()).containsExactly("/items"));
    }

    @Test
    @DisplayName("a discovery past its deadline fails rather than answering with what it had reached")
    void aDiscoveryPastItsDeadlineFails(@TempDir Path tempDir) throws IOException {
        // Failed, not partial: a partial list retires every endpoint the walk did not reach. A file
        // with no route, so that only the walk's own check can see the time is up.
        Files.writeString(tempDir.resolve("README.txt"), "nothing to discover");

        org.assertj.core.api.Assertions.assertThatThrownBy(
                        () -> ApiDiscoveryScanner.scan(tempDir, java.time.Duration.ofSeconds(1), clockAdvancingAfter(0)))
                .isInstanceOf(com.asmolabs.vectispire.common.scanning.ScannerFailureException.class);
    }

    @Test
    @DisplayName("the deadline is also held while endpoints are reconciled with the ingress paths")
    void theReconciliationHoldsTheDeadline(@TempDir Path tempDir) throws IOException {
        // The walk reads one file and checks the clock once; the reconciliation of its two
        // endpoints is where the time runs out.
        Files.writeString(tempDir.resolve("a.py"), "@app.get('/one')\n@app.get('/two')\n");

        org.assertj.core.api.Assertions.assertThatThrownBy(
                        () -> ApiDiscoveryScanner.scan(tempDir, java.time.Duration.ofSeconds(1), clockAdvancingAfter(2)))
                .isInstanceOf(com.asmolabs.vectispire.common.scanning.ScannerFailureException.class);
        assertThat(ApiDiscoveryScanner.scan(tempDir, java.time.Duration.ofSeconds(1), clockAdvancingAfter(10)).endpoints())
                .hasSize(2);
    }

    /** A clock that stands still for its first {@code readings} readings after the start, then jumps an hour. */
    private static java.util.function.LongSupplier clockAdvancingAfter(int readings) {
        int[] read = {-1};
        return () -> ++read[0] > readings ? java.time.Duration.ofHours(1).toNanos() : 0L;
    }

    private static <T> T withinSeconds(org.junit.jupiter.api.function.ThrowingSupplier<T> body) {
        return org.junit.jupiter.api.Assertions.assertTimeoutPreemptively(java.time.Duration.ofSeconds(10), body);
    }
}
