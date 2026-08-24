package com.asmolabs.vectispire.core.api.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.servers.Server;
import io.swagger.v3.oas.models.tags.Tag;
import java.util.List;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * OpenAPI 3.0 (Swagger) Specification configuration for Vectispire REST APIs.
 */
@Configuration
public class OpenApiConfiguration {

    public static final String BEARER_AUTH = "BearerAuth";
    public static final String AGENT_KEY_AUTH = "AgentKeyAuth";
    public static final String API_KEY_AUTH = "ApiKeyAuth";

    @Bean
    public OpenAPI vectispireOpenApi() {
        return new OpenAPI()
                .info(new Info()
                        .title("Vectispire Control Plane REST API")
                        .version("4.1.0")
                        .description("Automated supply-chain security, SBOM analysis, vulnerability triage, attack surface inventory, and compliance governance platform.")
                        .contact(new Contact()
                                .name("Asmolabs Security Team")
                                .url("https://github.com/asmolabs/vectispire"))
                        .license(new License()
                                .name("Apache-2.0")
                                .url("https://www.apache.org/licenses/LICENSE-2.0.html")))
                .servers(List.of(
                        new Server().url("/").description("Current Vectispire Instance")))
                .tags(List.of(
                        new Tag().name("Authentication").description("Sign-in, token exchange, MFA, SSO and session management"),
                        new Tag().name("Attack Surface").description("Discovered API endpoints, declared contracts (OpenAPI/Swagger) and shadow APIs"),
                        new Tag().name("Repositories").description("Target repository inventory, Git synchronization and scan triggers"),
                        new Tag().name("Scans").description("Security scan lifecycle, pipeline execution and status reporting"),
                        new Tag().name("Issues & Vulnerabilities").description("Security findings, triage workflow, risk assessment and remediation"),
                        new Tag().name("Compliance").description("Regulatory conformity frameworks (NIS2, ISO 27001, CRA, SOC2, PCI-DSS)"),
                        new Tag().name("Scorecards").description("Posture grades, security scorecards and SVG badges"),
                        new Tag().name("Containers").description("Container image registry tracking, digest verification and scanning"),
                        new Tag().name("SBOM & VEX").description("Software Bill of Materials (CycloneDX, SPDX), CSAF and OpenVEX documents"),
                        new Tag().name("Agents").description("Remote scanner agents protocol, tasks dispatching and heartbeat"),
                        new Tag().name("Administration").description("Users, teams, RBAC roles, SSH keys, audit logging and system settings")
                ))
                .components(new Components()
                        .addSecuritySchemes(BEARER_AUTH, new SecurityScheme()
                                .name(BEARER_AUTH)
                                .type(SecurityScheme.Type.HTTP)
                                .scheme("bearer")
                                .bearerFormat("JWT")
                                .description("JWT Session Bearer token obtained via /api/v1/auth/login"))
                        .addSecuritySchemes(AGENT_KEY_AUTH, new SecurityScheme()
                                .name("X-Agent-Key")
                                .type(SecurityScheme.Type.APIKEY)
                                .in(SecurityScheme.In.HEADER)
                                .description("Pre-shared authentication key for remote scanning agents"))
                        .addSecuritySchemes(API_KEY_AUTH, new SecurityScheme()
                                .name("X-API-Key")
                                .type(SecurityScheme.Type.APIKEY)
                                .in(SecurityScheme.In.HEADER)
                                .description("Programmatic API Key for CI/CD and automation integrations")))
                .addSecurityItem(new SecurityRequirement().addList(BEARER_AUTH));
    }
}
