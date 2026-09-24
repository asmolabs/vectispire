package com.asmolabs.vectispire.core.services;

import com.asmolabs.vectispire.common.domain.rules.RuleCatalogue;
import com.asmolabs.vectispire.common.domain.rules.RuleSet.TriageImpact;
import com.asmolabs.vectispire.common.domain.rules.RuleSet.UploadedFile;
import com.asmolabs.vectispire.core.persistence.SemgrepRuleSetEntity;
import com.asmolabs.vectispire.core.repositories.RuleSetSummary;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;
import org.springframework.stereotype.Service;

/**
 * The decisions behind the rule set routes that {@link RuleSetService} does not already make:
 * importing the upstream catalogue under an accepted licence, and reading a set's impact.
 */
@Service
public class RuleSetAdministrationService {

    private final RuleSetService ruleSets;
    private final RuleCatalogueFetcher fetcher;

    public RuleSetAdministrationService(RuleSetService ruleSets, RuleCatalogueFetcher fetcher) {
        this.ruleSets = ruleSets;
        this.fetcher = fetcher;
    }

    /**
     * The listing as the route answers it.
     *
     * <p><b>Declared here rather than in the controller</b> because its element is the
     * repositories' projection, and a controller naming that type reaches the data layer by the
     * back door. The simple name is the OpenAPI schema's name, so it must not change.
     */
    public record RuleSetListing(List<RuleSetSummary> ruleSets) {}

    /**
     * What an import stored, and the terms it was stored under — what the audit entry must name.
     *
     * @param languages sorted, so that the same selection always reads the same in the log
     */
    public record CatalogueImport(
            SemgrepRuleSetEntity stored, String commit, SortedSet<String> languages, String licenceSha256) {}

    public RuleSetListing list() {
        return new RuleSetListing(ruleSets.list());
    }

    /** What activating this set would cost, or a 404 for a set that does not exist. */
    public TriageImpact impact(long id) {
        return ruleSets.impactOf(
                ruleSets.byId(id).orElseThrow(() -> new NoSuchElementException("No rule set with id " + id + ".")));
    }

    /**
     * Fetches the chosen languages at the commit the caller read, and stores them. Does not
     * activate.
     *
     * <p><b>The acceptance is bound to a licence, not to a checkbox</b>: the digest the caller
     * echoes back must match the one just fetched, or "accepted" would mean "clicked a button next
     * to some text at some point".
     */
    public CatalogueImport importCatalogue(
            String commit, List<String> requestedLanguages, String licenceSha256, String actor) {

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
                ruleSets.store(files, RuleCatalogue.nameFor(fetched.commit(), languages), actor);
        return new CatalogueImport(stored, fetched.commit(), new TreeSet<>(languages), fetched.licenceSha256());
    }
}
