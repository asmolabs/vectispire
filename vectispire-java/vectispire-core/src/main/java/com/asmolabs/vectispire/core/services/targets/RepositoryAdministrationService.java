package com.asmolabs.vectispire.core.services.targets;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.agents.AgentLabels;
import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.targets.AssetTier;
import com.asmolabs.vectispire.common.domain.targets.GitHostAllowlist;
import com.asmolabs.vectispire.common.domain.targets.RepositorySubPath;
import com.asmolabs.vectispire.common.domain.targets.RepositoryUrl;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.common.domain.text.BoundedText;
import com.asmolabs.vectispire.core.access.RowVisibility;
import com.asmolabs.vectispire.core.audit.AuditLogService;
import com.asmolabs.vectispire.core.audit.RequestActor;
import com.asmolabs.vectispire.core.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.repositories.GitRepositories;
import com.asmolabs.vectispire.core.repositories.GitTokens;
import com.asmolabs.vectispire.core.repositories.SshKeys;
import com.asmolabs.vectispire.core.services.shared.TargetNaming;
import com.asmolabs.vectispire.core.services.targets.TargetScans.LatestScan;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.UUID;
import org.springframework.stereotype.Service;

/**
 * The repositories under watch: listing them within an allowance, and changing the inventory.
 *
 * <p><b>No transaction of its own, on purpose.</b> Each write is one {@code save}, which carries
 * the repository's own transaction; the route this was lifted from never opened a wider one, and
 * wrapping the lookup and the save together here would change what a concurrent edit sees. It is
 * also what lets each write be audited here, straight after it: the audit entry opens its own
 * transaction, and inside an outer one it would wait on its parent's lock on SQLite, where the
 * lock is the file.
 */
@Service
public class RepositoryAdministrationService {

    private final GitRepositories repositories;
    private final TargetScans scans;
    private final TargetBacklog backlog;
    private final TargetDeletionService targetDeletion;
    private final AuditLogService audit;
    private final GitTokens gitTokens;
    private final SshKeys sshKeys;
    private final GitHostAllowlist allowedHosts;
    private final TargetNaming naming;

    /**
     * The width of {@code url}, {@code branch}, {@code name} and {@code required_agent_label}, and of
     * the image columns next door. Past it the database refused the row at the write, as a 500.
     */
    static final int COLUMN_LENGTH = 255;

    public RepositoryAdministrationService(
            GitRepositories repositories,
            TargetScans scans,
            TargetBacklog backlog,
            TargetDeletionService targetDeletion,
            AuditLogService audit,
            GitTokens gitTokens,
            SshKeys sshKeys,
            GitHostAllowlist allowedHosts,
            TargetNaming naming) {
        this.repositories = repositories;
        this.scans = scans;
        this.backlog = backlog;
        this.targetDeletion = targetDeletion;
        this.audit = audit;
        this.gitTokens = gitTokens;
        this.sshKeys = sshKeys;
        this.allowedHosts = allowedHosts;
        this.naming = naming;
    }

    /**
     * A repository as the inventory shows it: the row, its latest scan, what waits on it, and the
     * project it is filed in.
     *
     * @param projectName {@code Solution / Project}, or null for a repository in no project
     */
    public record Listed(RepositoryView repository, Optional<LatestScan> latestScan, long openIssues, String projectName) {}

    /**
     * What an operator asked for, field by field.
     *
     * <p>Strings rather than typed values for the reason the route gives: on update, {@code null}
     * is "leave alone" and the empty string is "clear", and a typed field could not say both.
     */
    public record Changes(
            String url,
            String branch,
            String name,
            String subPath,
            Integer scanIntervalMinutes,
            String scanCron,
            String requiredAgentLabel,
            String sshKeyId,
            String tier,
            String httpsTokenId) {

        /** The shape callers had before HTTPS tokens: no token change. */
        public Changes(
                String url,
                String branch,
                String name,
                String subPath,
                Integer scanIntervalMinutes,
                String scanCron,
                String requiredAgentLabel,
                String sshKeyId,
                String tier) {
            this(url, branch, name, subPath, scanIntervalMinutes, scanCron, requiredAgentLabel, sshKeyId, tier, null);
        }
    }

    public record Triggered(RepositoryView repository, TargetScans.Queued scan) {}

    /** Every repository the allowance permits, with each one's latest scan and open issue count. */
    public List<Listed> list(Visibility allowed) {
        Map<Long, LatestScan> latest = scans.latestPerRepository();
        Map<Long, Long> open = backlog.openPerRepository();

        List<RepositoryEntity> visible = repositories.findAll().stream()
                .filter(repository -> allowed.permits(new ScanTarget.Repository(repository.getId())))
                .toList();
        // Named for the visible rows only, in one pass: a project's name is shown only beside a
        // repository the reader already sees, so the list reveals no project the tree would not.
        Map<Long, String> projectNames = naming.projectNames(visible.stream()
                .map(RepositoryEntity::getProjectId)
                .filter(java.util.Objects::nonNull)
                .collect(java.util.stream.Collectors.toSet()));
        return visible.stream()
                .map(repository -> new Listed(
                        RepositoryView.of(repository),
                        Optional.ofNullable(latest.get(repository.getId())),
                        open.getOrDefault(repository.getId(), 0L),
                        repository.getProjectId() == null ? null : projectNames.get(repository.getProjectId())))
                .toList();
    }

    /**
     * One row of {@link #list}, read the same way.
     *
     * <p>Through the list rather than by id so that what a create or an update answers is
     * exactly the row the inventory will show — latest scan and count included — and so that the
     * allowance decides it the same way.
     */
    public Optional<Listed> listed(Visibility allowed, long id) {
        return list(allowed).stream()
                .filter(listed -> listed.repository().id().equals(id))
                .findFirst();
    }

    public RepositoryView create(Changes changes, RequestActor actor) {
        String url = BoundedText.within(trim(changes.url()), COLUMN_LENGTH, "The repository URL");
        // Validated **here and not only at scan time**: an unvalidated URL reaching a git clone
        // is arbitrary code execution, not a typo.
        RepositoryUrl.validate(url).ifPresent(message -> {
            throw new IllegalArgumentException(message);
        });
        refuseCredentialInUrl(url);
        refuseUnlistedHost(url);

        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl(url);
        repository.setBranch(branch(changes.branch()));
        repository.setName(BoundedText.optional(changes.name(), COLUMN_LENGTH, "The repository name"));
        // Checked like the URL, and for the same reason: it is resolved against a clone on the
        // scanning host — see RepositorySubPath.
        repository.setSubPath(optional(RepositorySubPath.normalize(changes.subPath())));
        repository.setScanIntervalMinutes(changes.scanIntervalMinutes());
        // Validated at the entry point: discovering that an expression was rejected by watching
        // scans *not* happen is the expensive way.
        repository.setScanCron(validatedCron(changes.scanCron()));
        repository.setRequiredAgentLabel(requiredLabel(changes.requiredAgentLabel()));
        repository.setSshKeyId(sshKeyId(changes.sshKeyId()));
        repository.setHttpsTokenId(credentialId(changes.httpsTokenId(), "HTTPS token"));
        repository.setTier(AssetTier.fromInput(changes.tier()).name());
        requireMatchingCredential(repository);

        RepositoryEntity saved = repositories.save(repository);
        audit.record(actor.entry(
                AuditOperation.SETTING_UPDATED, String.valueOf(saved.getId()), "Repository added: " + RepositoryUrl.redact(saved.getUrl())));
        return RepositoryView.of(saved);
    }

    /**
     * Applies what was sent and leaves the rest.
     *
     * <p><b>Absent means unchanged, not cleared</b> — see the route for why that convention and
     * not its opposite.
     *
     * <p>The absent row is refused before the allowance is consulted, each in its own words,
     * because that is the order and the wording this route has always answered with.
     *
     * <p>The audit entry names the previous URL as well, redacted, for the reason the route gives.
     */
    public RepositoryView update(long id, Changes changes, Visibility allowed, RequestActor actor) {
        // Absent and hidden refused in one sentence: the absent row used to say "No repository
        // with id 7." and the hidden one "Target not found.", which told them apart.
        RepositoryEntity repository =
                RowVisibility.requireVisible(repositories.findById(id), new ScanTarget.Repository(id), allowed);

        String previousUrl = repository.getUrl();
        // The list sends the URL masked; a form saved without touching it sends the mask back,
        // which must leave the stored URL — credential included — as it was.
        if (changes.url() != null && !RepositoryUrl.isMaskedFormOf(trim(changes.url()), previousUrl)) {
            String url = BoundedText.within(trim(changes.url()), COLUMN_LENGTH, "The repository URL");
            // Validated on update exactly as on create: an unvalidated URL reaching a git clone
            // is arbitrary code execution, and a row edited later is no safer than a row added.
            RepositoryUrl.validate(url).ifPresent(message -> {
                throw new IllegalArgumentException(message);
            });
            refuseCredentialInUrl(url);
            refuseUnlistedHost(url);
            repository.setUrl(url);
        }
        if (changes.branch() != null) {
            repository.setBranch(branch(changes.branch()));
        }
        if (changes.name() != null) {
            repository.setName(BoundedText.optional(changes.name(), COLUMN_LENGTH, "The repository name"));
        }
        if (changes.subPath() != null) {
            repository.setSubPath(optional(RepositorySubPath.normalize(changes.subPath())));
        }
        if (changes.scanIntervalMinutes() != null) {
            repository.setScanIntervalMinutes(changes.scanIntervalMinutes());
        }
        if (changes.scanCron() != null) {
            repository.setScanCron(validatedCron(changes.scanCron()));
        }
        if (changes.requiredAgentLabel() != null) {
            repository.setRequiredAgentLabel(requiredLabel(changes.requiredAgentLabel()));
        }
        if (changes.sshKeyId() != null) {
            repository.setSshKeyId(sshKeyId(changes.sshKeyId()));
        }
        if (changes.httpsTokenId() != null) {
            repository.setHttpsTokenId(credentialId(changes.httpsTokenId(), "HTTPS token"));
        }
        // Checked whenever what the credential is paired with changes. Not on an unrelated edit of
        // a row that predates the rule — renaming it must not fail over a pairing nobody touched.
        if (!repository.getUrl().equals(previousUrl) || changes.sshKeyId() != null || changes.httpsTokenId() != null) {
            requireMatchingCredential(repository);
        }
        if (changes.tier() != null) {
            repository.setTier(AssetTier.fromInput(changes.tier()).name());
        }

        RepositoryEntity saved = repositories.save(repository);
        String moved = saved.getUrl().equals(previousUrl) ? "" : " (was " + RepositoryUrl.redact(previousUrl) + ")";
        audit.record(actor.entry(
                AuditOperation.SETTING_UPDATED,
                String.valueOf(saved.getId()),
                "Repository updated: " + RepositoryUrl.redact(saved.getUrl()) + moved));
        return RepositoryView.of(saved);
    }

    /**
     * @param allowed what the caller may see. Only administrators reach this route, whose
     *     visibility is everything — but an integration key acting for one is narrowed to its
     *     target, and without this check a key restricted to one repository scanned any other.
     */
    public Triggered trigger(long id, Visibility allowed, RequestActor actor) {
        RepositoryEntity repository =
                RowVisibility.requireVisible(repositories.findById(id), new ScanTarget.Repository(id), allowed);
        RepositoryView view = RepositoryView.of(repository);
        TargetScans.Queued scan = scans.queue(view);
        audit.record(actor.entry(
                AuditOperation.SCAN_TRIGGERED, String.valueOf(scan.id()), "Scan requested: " + RepositoryUrl.redact(repository.getUrl())));
        return new Triggered(view, scan);
    }

    /** Deletes the repository and everything hanging off it. */
    public void delete(long id, RequestActor actor) {
        RepositoryEntity repository = repositories.findById(id)
                .orElseThrow(() -> new NoSuchElementException("Repository not found."));
        targetDeletion.deleteRepository(id);
        audit.record(actor.entry(
                AuditOperation.SETTING_UPDATED, String.valueOf(id), "Repository deleted: " + RepositoryUrl.redact(repository.getUrl())));
    }

    /**
     * A valid cron expression, {@code null}, or a 400 the operator can read.
     *
     * <p>A 400 and not a 500: the expression came from the user, and the message carries the
     * expected format.
     */
    static String validatedCron(String expression) {
        String trimmed = trim(expression);
        if (trimmed.isEmpty()) {
            return null;
        }
        if (!CronExpressions.isValid(trimmed)) {
            throw new IllegalArgumentException(
                    "Unusable cron expression: \"" + trimmed + "\". Expected five fields, for example "
                            + "\"0 2 * * *\" (every day at 02:00) or \"0 */6 * * *\" (every six hours).");
        }
        return trimmed;
    }

    static String trim(String value) {
        return value == null ? "" : value.trim();
    }

    static String optional(String value) {
        String trimmed = trim(value);
        return trimmed.isEmpty() ? null : trimmed;
    }

    /**
     * A credential in the URL is refused for new URLs (decision 0022).
     *
     * <p>It was the only way to clone a private repository over HTTPS, and it stored the token in
     * the clear in this row and handed it to every agent. A URL already stored that way keeps
     * working — refusing it on upgrade would stop its scans silently — but none is added.
     */
    private void refuseUnlistedHost(String url) {
        if (!allowedHosts.permits(url)) {
            throw new IllegalArgumentException(allowedHosts.refusal(url));
        }
    }

    private static void refuseCredentialInUrl(String url) {
        if (RepositoryUrl.carriesCredential(url)) {
            throw new IllegalArgumentException("The URL carries a credential. Remove it from the URL and attach an "
                    + "HTTPS token instead: it is stored encrypted and sent only to its own host.");
        }
    }

    /**
     * One credential, of the kind the URL uses, and for a token the token's own host.
     *
     * <p>The host rule is what makes the token safe to attach at all: without it, pointing a
     * repository's URL at another server would send that server the forge's token (decision 0022).
     */
    private void requireMatchingCredential(RepositoryEntity repository) {
        UUID tokenId = repository.getHttpsTokenId();
        if (tokenId != null && repository.getSshKeyId() != null) {
            throw new IllegalArgumentException("A repository uses an SSH key or an HTTPS token, not both.");
        }
        if (tokenId != null) {
            if (!RepositoryUrl.isHttps(repository.getUrl())) {
                throw new IllegalArgumentException("An HTTPS token only works with an https:// URL.");
            }
            String host = gitTokens.findById(tokenId)
                    .orElseThrow(() -> new IllegalArgumentException("No HTTPS token with id " + tokenId + "."))
                    .getHost();
            if (!RepositoryUrl.hasHost(repository.getUrl(), host)) {
                throw new IllegalArgumentException("This token is issued for " + host
                        + " and would be sent to no other host; the URL names another one.");
            }
        }
        if (repository.getSshKeyId() != null && RepositoryUrl.isHttps(repository.getUrl())) {
            throw new IllegalArgumentException(
                    "An SSH key is not used over HTTPS. Use an ssh:// or git@ URL, or attach an HTTPS token.");
        }
    }

    private static UUID credentialId(String value, String what) {
        String trimmed = trim(value);
        if (trimmed.isEmpty()) {
            return null;
        }
        try {
            return UUID.fromString(trimmed);
        } catch (IllegalArgumentException malformed) {
            throw new IllegalArgumentException("\"" + trimmed + "\" is not a valid " + what + " identifier.");
        }
    }

    /**
     * Reads the deployment key the form named, where blank means "no key".
     *
     * <p>Rejecting a malformed identifier here rather than storing it matters: a repository
     * pointing at a key that does not exist falls back to the host's own SSH and fails at clone
     * time with "requires authentication" — an error that names neither the wrong identifier nor
     * this form. The 400 arrives while the operator is still looking at the field.
     *
     * <p><b>A well-formed identifier of no key is refused too</b>, as the HTTPS token's is. Only the
     * shape used to be checked, and the foreign key then refused the row at the write: a 500 for a
     * key deleted in another tab, and the message a constraint name.
     */
    private UUID sshKeyId(String value) {
        String trimmed = trim(value);
        if (trimmed.isEmpty()) {
            return null;
        }
        UUID id;
        try {
            id = UUID.fromString(trimmed);
        } catch (IllegalArgumentException malformed) {
            throw new IllegalArgumentException("\"" + trimmed + "\" is not a valid SSH key identifier.");
        }
        if (!sshKeys.existsById(id)) {
            throw new IllegalArgumentException("No SSH key with id " + id + ".");
        }
        return id;
    }

    /** Blank is {@code main}, the default the clone falls back to; anything else must fit its column. */
    private static String branch(String value) {
        String branch = BoundedText.optional(value, COLUMN_LENGTH, "The branch");
        return branch == null ? "main" : branch;
    }

    /**
     * Normalized on entry: without it, "Production" here and "production" on the agent would never
     * meet, and the scan would wait for an agent that is present. Bounded after normalization,
     * because that is the value stored.
     */
    static String requiredLabel(String value) {
        return AgentLabels.normalizeRequirement(value)
                .map(label -> BoundedText.within(label, COLUMN_LENGTH, "The required agent label"))
                .orElse(null);
    }
}
