package com.asmolabs.vectispire.core.plugins;

import com.asmolabs.vectispire.common.domain.apikeys.ApiKeyScope;
import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import com.asmolabs.vectispire.common.domain.errors.NotFoundException;
import com.asmolabs.vectispire.common.domain.sarif.SarifReport;
import com.asmolabs.vectispire.common.domain.text.BoundedText;
import com.asmolabs.vectispire.core.access.ApiKeyAdministrationService;
import com.asmolabs.vectispire.core.audit.AuditLogService;
import com.asmolabs.vectispire.core.audit.RequestActor;
import com.asmolabs.vectispire.core.plugins.persistence.SarifSourceEntity;
import com.asmolabs.vectispire.core.plugins.persistence.SarifSourceRepository;
import com.asmolabs.vectispire.core.targets.SolutionAdministrationService;
import com.asmolabs.vectispire.core.targets.TargetCatalog;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * The declared internal sources of SARIF — who may deposit findings, from which integration, for
 * what, and from which tools.
 *
 * <h2>Why declaring a source is the governor's</h2>
 *
 * <p>The policy is "SARIF from inside the organisation only": an on-premise SonarQube, the team's own
 * CI — a tool that already had the code — and never a hosted service the code would have been handed
 * to. Nothing in a SARIF file can prove where it was made. What the platform can hold is a
 * <em>declaration</em> — this key belongs to this internal producer, for this project, delivering these
 * tools — made by the one role that sets the rules others play by ({@code Role.governsPlatform}), and
 * audited. The key carries the {@code sarif_import} scope so a pipeline can present it; the declaration
 * is what makes presenting it mean anything. The limits of that are written in decision 0017.
 *
 * <h2>What a declaration binds</h2>
 *
 * <ul>
 *   <li><b>one integration key</b>, which must hold {@code sarif_import} and an active account, and
 *       names the source — one key, one source, so a caller never says which source it is;
 *   <li><b>one scope</b>, a project or a repository, never the estate: the key's own visibility is
 *       intersected with it at each import;
 *   <li><b>the tools</b> it may deliver, compared with each run's {@code tool.driver.name}: a CI key
 *       declared for Semgrep cannot start depositing a report that calls itself something else.
 * </ul>
 */
@Service
public class SarifSourceService {

    static final int MAX_SLUG = 40;
    static final int MAX_NAME = 100;
    static final int MAX_TOOLS = 20;

    private final SarifSourceRepository sources;
    private final ApiKeyAdministrationService apiKeys;
    private final SolutionAdministrationService projects;
    private final TargetCatalog targets;
    private final AuditLogService audit;
    private final TransactionTemplate transactions;
    private final Clock clock;

    public SarifSourceService(
            SarifSourceRepository sources,
            ApiKeyAdministrationService apiKeys,
            SolutionAdministrationService projects,
            TargetCatalog targets,
            AuditLogService audit,
            TransactionTemplate transactions,
            Clock clock) {
        this.sources = sources;
        this.apiKeys = apiKeys;
        this.projects = projects;
        this.targets = targets;
        this.audit = audit;
        this.transactions = transactions;
        this.clock = clock;
    }

    /**
     * @param projectId and {@code repositoryId}: exactly one
     * @param tools the SARIF tool names the source may deliver — required with {@code sarif}, refused
     *     without it
     * @param kinds {@code sarif}, {@code coverage}, {@code test_report}; {@code null} is SARIF alone
     */
    public record Declaration(
            String slug, String name, UUID apiKeyId, Long projectId, Long repositoryId, List<String> tools,
            List<String> kinds) {}

    public List<SarifSourceView> list() {
        List<SarifSourceEntity> rows = sources.findAllByOrderBySlugAsc();
        Map<UUID, String> keyNames = apiKeys.names(rows.stream().map(SarifSourceEntity::getApiKeyId).toList());
        return rows.stream().map(row -> SarifSourceView.of(row, keyNames.get(row.getApiKeyId()))).toList();
    }

    /** Declares a source, or refuses it with a reason the governor can act on. */
    public SarifSourceView declare(Declaration declaration, RequestActor actor) {
        if (declaration == null) {
            throw new InvalidInputException("A source declaration is required.");
        }
        String slug = requireSlug(declaration.slug());
        String name = BoundedText.required(declaration.name(), MAX_NAME, "The source's name");
        Set<SourceKind> kinds = SourceKind.parseAll(declaration.kinds());
        String tools = String.join(",", requireTools(declaration.tools(), kinds.contains(SourceKind.SARIF)));
        String scope = requireScope(declaration.projectId(), declaration.repositoryId());
        UUID keyId = requireImportKey(declaration.apiKeyId(), kinds);

        SarifSourceEntity saved = transactions.execute(status -> {
            if (sources.existsBySlug(slug)) {
                throw new PluginConflictException("A SARIF source \"" + slug + "\" is already declared.");
            }
            if (sources.existsByApiKeyId(keyId)) {
                throw new PluginConflictException("This key is already declared for another source: one key, one source.");
            }
            SarifSourceEntity source = new SarifSourceEntity();
            source.setSlug(slug);
            source.setName(name);
            source.setApiKeyId(keyId);
            source.setProjectId(declaration.projectId());
            source.setRepositoryId(declaration.repositoryId());
            source.setTools(tools);
            source.setKinds(SourceKind.stored(kinds));
            source.setEnabled(true);
            source.setCreatedAt(clock.instant());
            source.setCreatedBy(actor == null || actor.username() == null ? "unknown" : actor.username());
            return sources.save(source);
        });

        audit.record(actor.entry(AuditOperation.SARIF_SOURCE_CHANGED, slug,
                "Source \"" + slug + "\" declared for " + scope + ", key " + keyId + ", delivering "
                        + SourceKind.stored(kinds) + (tools.isEmpty() ? "" : ", tools " + tools) + "."));
        return view(saved);
    }

    /** Suspends or resumes a source; its key is refused while it is disabled. Repeating records nothing. */
    public SarifSourceView setEnabled(long id, boolean enabled, RequestActor actor) {
        record Changed(SarifSourceEntity source, boolean changed) {}
        Changed result = transactions.execute(status -> {
            SarifSourceEntity source = require(id);
            if (source.getEnabled() == enabled) {
                return new Changed(source, false);
            }
            source.setEnabled(enabled);
            return new Changed(sources.save(source), true);
        });
        if (result.changed()) {
            audit.record(actor.entry(AuditOperation.SARIF_SOURCE_CHANGED, result.source().getSlug(),
                    "SARIF source \"" + result.source().getSlug() + "\" " + (enabled ? "enabled" : "disabled") + "."));
        }
        return view(result.source());
    }

    /**
     * Removes a declaration; its key imports nothing any more. The issues it imported stay, and keep
     * naming it: the slug is their provenance.
     *
     * <p><b>A slug declared again continues the same backlog</b> — it is in the imported issues' tool
     * key. That is what rotating a source's key needs (one key, one source: declare the slug again with
     * the new key), and it is why the slug should name the producer, not the key.
     */
    public void delete(long id, RequestActor actor) {
        SarifSourceEntity source = transactions.execute(status -> {
            SarifSourceEntity found = require(id);
            sources.delete(found);
            return found;
        });
        audit.record(actor.entry(AuditOperation.SARIF_SOURCE_CHANGED, source.getSlug(),
                "SARIF source \"" + source.getSlug() + "\" removed; its key imports nothing any more."));
    }

    private SarifSourceView view(SarifSourceEntity source) {
        return SarifSourceView.of(source, apiKeys.names(List.of(source.getApiKeyId())).get(source.getApiKeyId()));
    }

    private SarifSourceEntity require(long id) {
        return sources.findById(id).orElseThrow(() -> new NotFoundException("No SARIF source " + id + "."));
    }

    /**
     * The key a source uploads with: an integration key — an account, not an agent — holding the scope
     * of every kind it is declared for ({@code sarif_import} for SARIF, {@code report_import} for
     * coverage and test reports), and not expired. Refused otherwise, before anything is written: a
     * kind declared for a key that cannot present it would be a declaration that never works.
     */
    private UUID requireImportKey(UUID keyId, Set<SourceKind> kinds) {
        if (keyId == null) {
            throw new InvalidInputException("A source names the integration key it uploads with.");
        }
        ApiKeyAdministrationService.KeyView key = apiKeys.key(keyId)
                .orElseThrow(() -> new InvalidInputException("No API key " + keyId + "."));
        for (SourceKind kind : kinds) {
            if (!key.scopes().contains(kind.scope().wireName())) {
                throw new InvalidInputException("The key \"" + key.name() + "\" does not hold the "
                        + kind.scope().wireName() + " scope a " + kind.wireName() + " source uploads with; issue one "
                        + "that does.");
            }
        }
        if (key.scopes().contains(ApiKeyScope.AGENT.wireName()) || key.owner() == null) {
            throw new InvalidInputException("The key \"" + key.name() + "\" acts for no active account; a source "
                    + "uploads with an integration key issued by an account.");
        }
        if (key.expired()) {
            throw new InvalidInputException("The key \"" + key.name() + "\" has expired.");
        }
        return keyId;
    }

    /** Exactly one scope, and one that exists — described for the audit entry. */
    private String requireScope(Long projectId, Long repositoryId) {
        if ((projectId == null) == (repositoryId == null)) {
            throw new InvalidInputException("A source delivers for exactly one project or one repository — never the "
                    + "whole estate, and not both.");
        }
        if (projectId != null) {
            SolutionAdministrationService.ProjectView project = projects.project(projectId)
                    .orElseThrow(() -> new NotFoundException("No project " + projectId + "."));
            return "project \"" + project.name() + "\" (" + projectId + ")";
        }
        targets.repository(repositoryId)
                .orElseThrow(() -> new NotFoundException("No repository " + repositoryId + "."));
        return "repository " + repositoryId;
    }

    /**
     * The tool names, compared as the import compares them: stripped and lowercased. Required of a
     * SARIF source, refused of one that delivers no SARIF — they would read as a permission nothing
     * uses.
     */
    static List<String> requireTools(List<String> tools, boolean sarif) {
        if (!sarif) {
            if (tools != null && tools.stream().anyMatch(tool -> tool != null && !tool.isBlank())) {
                throw new InvalidInputException("Tools are the SARIF tools a source delivers; a source that "
                        + "delivers no SARIF declares none.");
            }
            return List.of();
        }
        if (tools == null || tools.isEmpty()) {
            throw new InvalidInputException("A source declares the tools it delivers — each run's tool.driver.name.");
        }
        if (tools.size() > MAX_TOOLS) {
            throw new InvalidInputException("A source declares at most " + MAX_TOOLS + " tools.");
        }
        List<String> normalized = new ArrayList<>();
        for (String tool : tools) {
            String value = tool == null ? "" : tool.strip().toLowerCase(Locale.ROOT);
            if (value.isEmpty() || value.length() > SarifReport.MAX_TOOL_NAME || value.contains(",")
                    || value.chars().anyMatch(Character::isISOControl)) {
                throw new InvalidInputException("A tool name is 1 to " + SarifReport.MAX_TOOL_NAME
                        + " characters, with no comma and no control character.");
            }
            if (!normalized.contains(value)) {
                normalized.add(value);
            }
        }
        return normalized;
    }

    /** Lowercase letters, digits and inner hyphens — the slug enters every imported issue's tool key. */
    static String requireSlug(String slug) {
        String value = slug == null ? "" : slug.strip();
        boolean valid = value.length() >= 2 && value.length() <= MAX_SLUG;
        for (int i = 0; valid && i < value.length(); i++) {
            char c = value.charAt(i);
            boolean alphanumeric = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
            valid = alphanumeric || (c == '-' && i > 0 && i < value.length() - 1);
        }
        if (!valid) {
            throw new InvalidInputException("A source's slug is 2 to " + MAX_SLUG + " lowercase letters, digits and "
                    + "inner hyphens: it names every issue the source imports, and is never renamed.");
        }
        return value;
    }
}
