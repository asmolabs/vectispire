package com.asmolabs.vectispire.core.services;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.rules.RuleCatalogue;
import com.asmolabs.vectispire.common.domain.rules.RuleSet.TriageImpact;
import com.asmolabs.vectispire.common.domain.rules.RuleSet.UploadedFile;
import com.asmolabs.vectispire.core.persistence.SemgrepRuleSetEntity;
import com.asmolabs.vectispire.core.repositories.RuleSetSummary;
import com.asmolabs.vectispire.core.services.audit.AuditLogService;
import com.asmolabs.vectispire.core.services.audit.RequestActor;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;
import org.springframework.stereotype.Service;

/**
 * The decisions behind the rule set routes that {@link RuleSetService} does not already make:
 * importing the upstream catalogue under an accepted licence, reading a set's impact, and
 * auditing every change to what the scanner looks for.
 *
 * <p><b>Audited, because changing the rule set is the same class of decision as changing a gate
 * policy.</b> The entries are written here, after {@link RuleSetService} has committed: its writes
 * are {@code @Transactional}, and an audit entry — its own transaction — written inside one would
 * wait on the parent's lock on SQLite, where the lock is the file. This class opens no transaction
 * of its own, which is what keeps the two apart.
 */
@Service
public class RuleSetAdministrationService {

    private final RuleSetService ruleSets;
    private final RuleCatalogueFetcher fetcher;
    private final AuditLogService audit;

    public RuleSetAdministrationService(RuleSetService ruleSets, RuleCatalogueFetcher fetcher, AuditLogService audit) {
        this.ruleSets = ruleSets;
        this.fetcher = fetcher;
        this.audit = audit;
    }

    /**
     * The listing as the route answers it.
     *
     * <p><b>Declared here rather than in the controller</b> because its element is the
     * repositories' projection, and a controller naming that type reaches the data layer by the
     * back door. The simple name is the OpenAPI schema's name, so it must not change.
     */
    public record RuleSetListing(List<RuleSetSummary> ruleSets) {}

    public RuleSetListing list() {
        return new RuleSetListing(ruleSets.list());
    }

    /** What activating this set would cost, or a 404 for a set that does not exist. */
    public TriageImpact impact(long id) {
        return ruleSets.impactOf(
                ruleSets.byId(id).orElseThrow(() -> new NoSuchElementException("No rule set with id " + id + ".")));
    }

    /** Stores an upload, attributed to the actor. Does not activate it. */
    public SemgrepRuleSetEntity upload(List<UploadedFile> files, String name, RequestActor actor) {
        SemgrepRuleSetEntity stored = ruleSets.store(files == null ? List.of() : files, name, actor.username());

        audit.record(actor.entry(
                AuditOperation.RULE_SET_UPLOADED,
                String.valueOf(stored.getId()),
                "Rule set \"" + stored.getName() + "\" uploaded: " + stored.getFileCount() + " files, "
                        + stored.getRuleCount() + " rules."));
        return stored;
    }

    /**
     * Fetches the chosen languages at the commit the caller read, and stores them. Does not
     * activate.
     *
     * <p><b>The acceptance is bound to a licence, not to a checkbox</b>: the digest the caller
     * echoes back must match the one just fetched, or "accepted" would mean "clicked a button next
     * to some text at some point".
     *
     * <p>The audit entry carries the tag, the commit and that digest, so that "which terms did we
     * agree to, and who agreed" has an answer a year from now. The languages are sorted, so the
     * same selection always reads the same in the log.
     */
    public SemgrepRuleSetEntity importCatalogue(
            String commit, List<String> requestedLanguages, String licenceSha256, RequestActor actor) {

        RuleCatalogue.requireCommit(commit);
        RuleCatalogueFetcher.Fetched fetched = fetcher.fetch();

        // **Both must still match.** The upstream is a moving branch, so between reading the
        // licence and accepting it the head can advance. Refusing is the only honest answer: an
        // acceptance that silently applied to a different commit would be worth nothing, and
        // this is the one place where "it probably did not change" is not good enough.
        if (!fetched.commit().equalsIgnoreCase(commit)) {
            throw new IllegalArgumentException(
                    "The upstream moved between the preview and this request: you read " + commit
                            + ", it is now " + fetched.commit() + ". Read the catalogue again.");
        }
        if (!fetched.licenceSha256().equals(licenceSha256)) {
            throw new IllegalArgumentException(
                    "The licence changed between the preview and this request. Read it again before accepting: "
                            + "what you agreed to is not what this commit carries.");
        }

        Set<String> languages = requestedLanguages == null ? Set.of() : Set.copyOf(requestedLanguages);
        List<UploadedFile> files = RuleCatalogue.select(fetched.contents(), languages);

        SemgrepRuleSetEntity stored =
                ruleSets.store(files, RuleCatalogue.nameFor(fetched.commit(), languages), actor.username());

        SortedSet<String> sorted = new TreeSet<>(languages);
        audit.record(actor.entry(
                AuditOperation.RULE_SET_UPLOADED,
                String.valueOf(stored.getId()),
                "Fetched " + RuleCatalogue.UPSTREAM + " at commit " + fetched.commit() + ", languages " + String.join(", ", sorted) + ": "
                        + stored.getRuleCount() + " rules. Licence " + RuleCatalogue.LICENCE
                        + " accepted, sha256 " + fetched.licenceSha256() + "."));
        return stored;
    }

    /**
     * Activates a set, recording the impact the operator was shown.
     *
     * @param note what the screen showed when they confirmed — what makes "why did four hundred
     *     issues close that afternoon" answerable six months later
     */
    public SemgrepRuleSetEntity activate(long id, String note, RequestActor actor) {
        SemgrepRuleSetEntity activated = ruleSets.activate(id, note);

        audit.record(actor.entry(
                AuditOperation.RULE_SET_ACTIVATED,
                String.valueOf(activated.getId()),
                "Rule set \"" + activated.getName() + "\" activated. "
                        + (activated.getActivationNote() == null ? "No impact recorded." : activated.getActivationNote())));
        return activated;
    }

    /** Returns to the bundled rules alone. Audited like an activation: it changes coverage. */
    public void deactivate(RequestActor actor) {
        ruleSets.deactivateAll();
        audit.record(actor.entry(
                AuditOperation.RULE_SET_DEACTIVATED,
                "all",
                "Uploaded rule sets deactivated; scans fall back to the bundled rules."));
    }
}
