package com.asmolabs.vectispire.core.plugins;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.crypto.Digests;
import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import com.asmolabs.vectispire.common.domain.errors.NotFoundException;
import com.asmolabs.vectispire.common.domain.plugins.Language;
import com.asmolabs.vectispire.common.domain.plugins.PluginManifest;
import com.asmolabs.vectispire.common.domain.plugins.PluginRef;
import com.asmolabs.vectispire.common.domain.plugins.PluginSignature;
import com.asmolabs.vectispire.core.audit.AuditLogService;
import com.asmolabs.vectispire.core.audit.RequestActor;
import com.asmolabs.vectispire.core.plugins.persistence.PluginActivationEntity;
import com.asmolabs.vectispire.core.plugins.persistence.PluginActivationRepository;
import com.asmolabs.vectispire.core.plugins.persistence.PluginEntity;
import com.asmolabs.vectispire.core.plugins.persistence.PluginManifestEntity;
import com.asmolabs.vectispire.core.plugins.persistence.PluginManifestRepository;
import com.asmolabs.vectispire.core.plugins.persistence.PluginRepository;
import com.asmolabs.vectispire.core.targets.SolutionAdministrationService;
import com.asmolabs.vectispire.core.targets.TargetCatalog;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * The plugin registry, the activations per project, and the manifests a scan runs.
 *
 * <h2>Who decides what</h2>
 *
 * <ul>
 *   <li><b>Registering and changing a plugin is the platform governor's</b> — the routes carry
 *       {@code @RequiresPlatformGovernor}. A plugin is third-party code that will read the source of
 *       every project it is switched on for; deciding that such code may exist on the platform is a
 *       rule everybody else plays by, which is exactly what {@code Role.governsPlatform} is for.
 *   <li><b>Switching it on for a project is governance work</b> — {@code @RequiresSecurityLead},
 *       the roles that {@code canWriteGovernance} and see the whole estate: the same decision as
 *       activating a rule set, scoped to one project. Nothing is on by default, and a repository in
 *       no project runs no plugin.
 * </ul>
 *
 * <p><b>Every change is audited after its transaction commits</b> — the audit log opens its own, and
 * on SQLite would wait on this one's file lock — and signals {@code PLUGIN_CHANGED} to the SIEM.
 *
 * <p><b>No delete.</b> A plugin's id is in every one of its issues' fingerprints; deleting it and
 * registering other code under the same id would hand that code the old triage. A plugin that should
 * stop is disabled; one registered by mistake keeps its id retired.
 */
@Service
public class PluginService {

    private final PluginRepository plugins;
    private final PluginManifestRepository manifests;
    private final PluginActivationRepository activations;
    private final SolutionAdministrationService projects;
    private final TargetCatalog targets;
    private final AuditLogService audit;
    private final TransactionTemplate transactions;
    private final ObjectMapper json;
    private final Clock clock;

    public PluginService(
            PluginRepository plugins,
            PluginManifestRepository manifests,
            PluginActivationRepository activations,
            SolutionAdministrationService projects,
            TargetCatalog targets,
            AuditLogService audit,
            TransactionTemplate transactions,
            ObjectMapper json,
            Clock clock) {
        this.plugins = plugins;
        this.manifests = manifests;
        this.activations = activations;
        this.projects = projects;
        this.targets = targets;
        this.audit = audit;
        this.transactions = transactions;
        this.json = json;
        this.clock = clock;
    }

    public List<PluginView> list() {
        return plugins.findAllByOrderByIdAsc().stream().map(this::view).toList();
    }

    public PluginView get(String id) {
        return view(require(id));
    }

    /**
     * Registers a plugin under a new id.
     *
     * @throws com.asmolabs.vectispire.common.domain.plugins.InvalidPluginException a manifest refused (400)
     * @throws PluginConflictException an id already registered (409) — ids are never reused
     */
    public PluginView register(PluginManifest requested, RequestActor actor) {
        PluginManifest manifest = requireManifest(requested).validated();
        Instant now = clock.instant();

        PluginEntity saved = transactions.execute(status -> {
            if (plugins.existsById(manifest.id())) {
                throw new PluginConflictException("A plugin with id \"" + manifest.id() + "\" is already registered; "
                        + "an id is never reused, since it names every issue the plugin ever opened.");
            }
            storeManifest(manifest, now);
            PluginEntity plugin = new PluginEntity();
            plugin.setId(manifest.id());
            plugin.setName(manifest.name());
            plugin.setManifestDigest(manifest.digest());
            plugin.setEnabled(true);
            plugin.setCreatedAt(now);
            plugin.setCreatedBy(actorName(actor));
            plugin.setUpdatedAt(now);
            plugin.setUpdatedBy(actorName(actor));
            return plugins.save(plugin);
        });

        audit.record(actor.entry(AuditOperation.PLUGIN_REGISTERED, manifest.id(),
                "Plugin \"" + manifest.id() + "\" registered: " + summary(manifest)));
        return view(saved);
    }

    /**
     * Gives a plugin a new manifest under the same id — a new image digest keeps the id, and with it
     * every issue's identity and triage. The same manifest again changes nothing and records nothing.
     */
    public PluginView update(String id, PluginManifest requested, RequestActor actor) {
        PluginManifest manifest = requireManifest(requested).validated();
        if (!manifest.id().equals(id)) {
            throw new InvalidInputException("The manifest's id \"" + manifest.id() + "\" is not the plugin's \"" + id
                    + "\": an id is never changed, since it names every issue the plugin ever opened.");
        }
        Instant now = clock.instant();
        record Updated(PluginEntity plugin, String previousDigest) {}

        Updated updated = transactions.execute(status -> {
            PluginEntity plugin = require(id);
            String previous = plugin.getManifestDigest();
            if (previous.equals(manifest.digest())) {
                return new Updated(plugin, null);
            }
            storeManifest(manifest, now);
            plugin.setName(manifest.name());
            plugin.setManifestDigest(manifest.digest());
            plugin.setUpdatedAt(now);
            plugin.setUpdatedBy(actorName(actor));
            return new Updated(plugins.save(plugin), previous);
        });

        if (updated.previousDigest() != null) {
            audit.record(actor.entry(AuditOperation.PLUGIN_UPDATED, id,
                    "Plugin \"" + id + "\" updated from manifest " + shortDigest(updated.previousDigest()) + ": "
                            + summary(manifest)));
        }
        return view(updated.plugin());
    }

    /** Disables or enables a plugin; its activations are kept either way. Repeating it records nothing. */
    public PluginView setEnabled(String id, boolean enabled, RequestActor actor) {
        record Changed(PluginEntity plugin, boolean changed) {}
        Changed result = transactions.execute(status -> {
            PluginEntity plugin = require(id);
            if (plugin.getEnabled() == enabled) {
                return new Changed(plugin, false);
            }
            plugin.setEnabled(enabled);
            plugin.setUpdatedAt(clock.instant());
            plugin.setUpdatedBy(actorName(actor));
            return new Changed(plugins.save(plugin), true);
        });
        if (result.changed()) {
            audit.record(actor.entry(AuditOperation.PLUGIN_ENABLED_CHANGED, id,
                    "Plugin \"" + id + "\" " + (enabled ? "enabled" : "disabled")
                            + ": its activations " + (enabled ? "run again" : "stop") + " from the next scan."));
        }
        return view(result.plugin());
    }

    // ------------------------------------------------------------------ activations

    /** The plugins switched on for a project; 404 for a project that does not exist. */
    public List<PluginActivationView> activations(long projectId) {
        requireProject(projectId);
        return labelled(activations.findByProjectIdOrderByPluginIdAsc(projectId));
    }

    /** The projects a plugin is switched on for; 404 for a plugin that does not exist. */
    public List<PluginActivationView> activationsOf(String pluginId) {
        require(pluginId);
        return labelled(activations.findByPluginIdOrderByProjectIdAsc(pluginId));
    }

    /** The rows with their projects' names, read in one batched lookup rather than one per row. */
    private List<PluginActivationView> labelled(List<PluginActivationEntity> rows) {
        Map<Long, SolutionAdministrationService.ProjectLabel> labels =
                projects.projectLabels(rows.stream().map(PluginActivationEntity::getProjectId).toList());
        return rows.stream().map(row -> PluginActivationView.of(row, labels.get(row.getProjectId()))).toList();
    }

    /**
     * Switches a plugin on for a project. Repeating it changes nothing and records nothing. A disabled
     * plugin may be activated: it runs once it is enabled.
     */
    public PluginActivationView activate(long projectId, String pluginId, RequestActor actor) {
        SolutionAdministrationService.ProjectView project = requireProject(projectId);
        record Activated(PluginActivationEntity activation, boolean created) {}
        Activated result = transactions.execute(status -> {
            require(pluginId);
            Optional<PluginActivationEntity> existing = activations.findByPluginIdAndProjectId(pluginId, projectId);
            if (existing.isPresent()) {
                return new Activated(existing.get(), false);
            }
            PluginActivationEntity activation = new PluginActivationEntity();
            activation.setPluginId(pluginId);
            activation.setProjectId(projectId);
            activation.setActivatedAt(clock.instant());
            activation.setActivatedBy(actorName(actor));
            return new Activated(activations.save(activation), true);
        });
        if (result.created()) {
            audit.record(actor.entry(AuditOperation.PLUGIN_ACTIVATED, pluginId + "@" + projectId,
                    "Plugin \"" + pluginId + "\" switched on for project \"" + project.name() + "\" (" + projectId
                            + "): it reads that project's repositories from the next scan."));
        }
        return PluginActivationView.of(result.activation(), projects.projectLabels(List.of(projectId)).get(projectId));
    }

    /** Switches it off; 404 when it was not on. The plugin's issues stay, as they would for a failure. */
    public void deactivate(long projectId, String pluginId, RequestActor actor) {
        SolutionAdministrationService.ProjectView project = requireProject(projectId);
        transactions.executeWithoutResult(status -> {
            PluginActivationEntity activation = activations.findByPluginIdAndProjectId(pluginId, projectId)
                    .orElseThrow(() -> new NotFoundException(
                            "Plugin \"" + pluginId + "\" is not switched on for project " + projectId + "."));
            activations.delete(activation);
        });
        audit.record(actor.entry(AuditOperation.PLUGIN_DEACTIVATED, pluginId + "@" + projectId,
                "Plugin \"" + pluginId + "\" switched off for project \"" + project.name() + "\" (" + projectId
                        + "); its open issues are left as they are."));
    }

    // ------------------------------------------------------------------ for scans

    /** The references a scan of this repository runs — see {@code ScanPlugins.forRepository}. */
    public List<PluginRef> forRepository(long repositoryId) {
        Long projectId = targets.repository(repositoryId).map(repository -> repository.projectId()).orElse(null);
        if (projectId == null) {
            return List.of();
        }
        return plugins.enabledForProject(projectId).stream()
                .map(plugin -> new PluginRef(plugin.getId(), plugin.getManifestDigest()))
                .toList();
    }

    /**
     * The manifest a reference names, whether or not it is still the plugin's current one: a task
     * queued before an update names the older one, and must get exactly that.
     *
     * <p>Read back through the digest: a row whose content no longer hashes to its key — edited in the
     * database — answers nothing, and the executor reports the plugin absent rather than running it.
     */
    public Optional<PluginManifest> manifest(PluginRef reference) {
        if (reference == null || reference.id() == null || reference.digest() == null) {
            return Optional.empty();
        }
        return manifests.findByDigestAndPluginId(reference.digest(), reference.id())
                .map(this::parse)
                .filter(manifest -> manifest.digest().equals(reference.digest()));
    }

    // ------------------------------------------------------------------ internals

    private void storeManifest(PluginManifest manifest, Instant now) {
        if (manifests.existsById(manifest.digest())) {
            // A plugin set back to a manifest it had before: the row exists, and is never rewritten.
            return;
        }
        PluginManifestEntity row = new PluginManifestEntity();
        row.setDigest(manifest.digest());
        row.setPluginId(manifest.id());
        try {
            row.setManifest(json.writeValueAsString(manifest));
        } catch (JsonProcessingException unwritable) {
            throw new IllegalStateException("The manifest could not be written.", unwritable);
        }
        row.setCreatedAt(now);
        manifests.save(row);
    }

    private PluginManifest parse(PluginManifestEntity row) {
        try {
            return json.readValue(row.getManifest(), PluginManifest.class);
        } catch (JsonProcessingException unreadable) {
            throw new IllegalStateException("Stored manifest " + row.getDigest() + " is unreadable.", unreadable);
        }
    }

    private PluginView view(PluginEntity plugin) {
        PluginManifest manifest = manifests.findById(plugin.getManifestDigest()).map(this::parse).orElse(null);
        return new PluginView(plugin.getId(), plugin.getName(), manifest, plugin.getManifestDigest(), plugin.getEnabled(),
                plugin.getCreatedAt(), plugin.getCreatedBy(), plugin.getUpdatedAt(), plugin.getUpdatedBy());
    }

    private PluginEntity require(String id) {
        return plugins.findById(id == null ? "" : id)
                .orElseThrow(() -> new NotFoundException("No plugin \"" + id + "\" is registered."));
    }

    private SolutionAdministrationService.ProjectView requireProject(long projectId) {
        return projects.project(projectId)
                .orElseThrow(() -> new NotFoundException("No project " + projectId + "."));
    }

    private static PluginManifest requireManifest(PluginManifest manifest) {
        if (manifest == null) {
            throw new InvalidInputException("A plugin manifest is required.");
        }
        return manifest;
    }

    /**
     * What the audit entry says about a manifest. The digest first: the column holds 255 characters,
     * and whatever a long justification pushes past them, the digest finds the whole manifest again.
     */
    private static String summary(PluginManifest manifest) {
        return "manifest " + shortDigest(manifest.digest())
                + ", network " + (manifest.network() ? "OPEN" : "none")
                + ", image " + manifest.image()
                + ", languages " + manifest.languages().stream().map(Language::wireName).collect(Collectors.joining(","))
                + (manifest.network() ? ", network justified as: " + manifest.networkJustification() : "")
                + ", " + signer(manifest.signature()) + ".";
    }

    /** Who the image must be signed by, as the audit reads it — a key by its fingerprint, not its PEM. */
    private static String signer(PluginSignature signature) {
        if (signature == null) {
            return "no signer declared (trusted by digest alone)";
        }
        return switch (signature.form()) {
            case KEYLESS -> "signed keyless by " + signature.identity() + " via " + signature.issuer();
            case KEY -> "signed by key sha256:" + shortDigest(Digests.sha256Hex(signature.publicKey()));
        };
    }

    private static String shortDigest(String digest) {
        return digest == null ? "none" : digest.substring(0, Math.min(12, digest.length()));
    }

    private static String actorName(RequestActor actor) {
        return actor == null || actor.username() == null ? "unknown" : actor.username();
    }
}
