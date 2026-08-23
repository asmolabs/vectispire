package com.asmolabs.zanshin.common.scanning.scanners;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.zanshin.common.domain.apis.ApiContract;
import com.asmolabs.zanshin.common.domain.apis.ApiEndpoint;
import com.asmolabs.zanshin.common.domain.apis.ApiVisibility;
import com.asmolabs.zanshin.common.domain.apis.AttackSurfaceSummary;
import com.asmolabs.zanshin.common.domain.apis.ShadowApiDiff;
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
}
