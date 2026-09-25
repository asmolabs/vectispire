package com.asmolabs.vectispire.core.api.config;

import com.asmolabs.vectispire.core.services.ProductVersion;
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
    public static final String API_KEY_AUTH = "ApiKeyAuth";

    /**
     * @param version the product's, as every exported document states it. It was "4.1.0" — a
     *     number that matched no release of Vectispire and read, to a client generating from this
     *     document, as the version of the API it was talking to. The API has no version of its own
     *     beyond the {@code /api/v1} prefix, so the document carries the build's; a release that
     *     bumps it regenerates {@code openapi.json}, which {@code ClientContractSpecTest} asks for.
     */
    @Bean
    public OpenAPI vectispireOpenApi(ProductVersion version) {
        return new OpenAPI()
                .info(new Info()
                        .title("Vectispire Control Plane REST API")
                        // Required by OpenAPI, so "unknown" rather than absent — reached only by a
                        // build without build-info, and saying so rather than guessing.
                        .version(version.get() == null ? "unknown" : version.get())
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
                                .description("An opaque token: a session from /api/v1/auth/login, an integration API key"
                                        + " (zsk_…, acting for the account that issued it, on the routes that accept a key),"
                                        + " or an agent's key on the agent routes."))
                        .addSecuritySchemes(API_KEY_AUTH, new SecurityScheme()
                                .name("X-API-Key")
                                .type(SecurityScheme.Type.APIKEY)
                                .in(SecurityScheme.In.HEADER)
                                .description("The same integration API key, for clients that cannot set Authorization."
                                        + " Read only when Authorization is absent, and never for a session.")))
                .addSecurityItem(new SecurityRequirement().addList(BEARER_AUTH));
    }
}
