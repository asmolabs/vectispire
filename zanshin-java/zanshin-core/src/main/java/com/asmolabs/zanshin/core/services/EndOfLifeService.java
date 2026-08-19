package com.asmolabs.zanshin.core.services;

import com.asmolabs.zanshin.common.domain.eol.LifeCycle;
import com.asmolabs.zanshin.common.domain.eol.LifeCycle.Candidate;
import com.asmolabs.zanshin.common.domain.eol.LifeCycle.Product;
import com.asmolabs.zanshin.common.domain.eol.LifeCycle.Release;
import com.asmolabs.zanshin.common.domain.issues.FindingType;
import com.asmolabs.zanshin.common.domain.net.OutboundPolicy;
import com.asmolabs.zanshin.common.domain.sbom.Sbom;
import com.asmolabs.zanshin.common.domain.settings.Setting;
import com.asmolabs.zanshin.core.persistence.FindingEntity;
import com.asmolabs.zanshin.core.persistence.ScanEntity;
import com.fasterxml.jackson.databind.JsonNode;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * Detecting platforms whose support has ended.
 *
 * <p><b>A whole class of risk carries no CVE at all</b>: a runtime out of support will not
 * receive a fix for the <em>next</em> vulnerability, whatever it turns out to be. Nothing in
 * the scan chain saw it — an image built on an expired distribution returned the same clean
 * bill of health as a supported one, right up to the day a critical advisory appeared with no
 * fix behind it.
 *
 * <p>Two matching paths, because the answer lives in two places in a Syft SBOM:
 *
 * <ol>
 *   <li><b>The distribution</b>, read from the {@code distro} block. The most valuable check
 *       for an image, and the one no package lookup would find: it is the base image's
 *       operating system, not a package inside it.
 *   <li><b>The packages</b>, matched by purl against the catalog's index.
 * </ol>
 *
 * <p><b>The coverage is partly deliberate, and saying so matters</b>: endoflife.date tracks
 * products — languages, runtimes, frameworks, databases, distributions — not every library. An
 * image of a hundred and thirty packages will match a handful. That is the right scope: "end of
 * life" is a property of a platform, and a library's risk is already the vulnerability
 * scanners' answer.
 */
@Service
public class EndOfLifeService implements ScanIngestor.EndOfLifeSource {

    private static final Logger log = LoggerFactory.getLogger(EndOfLifeService.class);

    private static final String API_ROOT = "https://endoflife.date/api/v1";
    private static final String PURL_IDENTIFIERS_URL = API_ROOT + "/identifiers/purl/";
    private static final String SOURCE = "endoflife.date";
    private static final Duration CACHE_TTL = Duration.ofHours(24);

    private final SettingsService settings;
    private final OutboundJson outbound;
    private final Clock clock;

    private Map<String, String> purlIndex;
    private Instant purlIndexFetchedAt = Instant.EPOCH;
    private final Map<String, Cached<Product>> products = new HashMap<>();

    public EndOfLifeService(SettingsService settings, OutboundJson outbound, Clock clock) {
        this.settings = settings;
        this.outbound = outbound;
        this.clock = clock;
    }

    private record Cached<T>(T value, Instant fetchedAt) {}

    @Override
    public boolean isEnabled() {
        return settings.isEnabled(Setting.EOL_ENABLED);
    }

    /** The warning window, in days before the end of support. */
    public Duration warningWindow() {
        int days = settings.asInt(Setting.EOL_WARN_DAYS);
        return days >= 0 ? Duration.ofDays(days) : LifeCycle.DEFAULT_WARNING_WINDOW;
    }

    /**
     * One finding per expired product cycle — or one about to expire.
     *
     * <p>Returns an empty list on any failure, network included: this step runs inside a scan
     * that has already produced results, and the alternative is failing a scan over an optional
     * catalog.
     */
    @Override
    public List<FindingEntity> findings(ScanEntity scan, JsonNode sbomDocument) {
        try {
            Sbom sbom = new Sbom(sbomDocument);
            Duration window = warningWindow();
            LocalDate today = LifeCycle.today(clock.instant());

            List<FindingEntity> findings = new ArrayList<>();
            Set<String> seen = new HashSet<>();

            for (Candidate candidate : candidates(sbom)) {
                Optional<Product> product = product(candidate.product());
                if (product.isEmpty()) {
                    continue;
                }
                Optional<Release> release = LifeCycle.matchRelease(product.get(), candidate.version());
                if (release.isEmpty()) {
                    continue;
                }

                // **Deduplicated on the cycle, not on the version**: an image can list the same
                // runtime as a distribution *and* as a package, as "3.9" and "3.9.1", while the
                // finding is about the cycle in both cases.
                if (!seen.add(candidate.product() + " " + release.get().name())) {
                    continue;
                }

                LifeCycle.assess(release.get(), today, window)
                        .ifPresent(verdict -> findings.add(
                                finding(scan, candidate, release.get(), product.get(), verdict.severity().wireName())));
            }

            if (!findings.isEmpty()) {
                log.info("End of life: {} cycle(s) reported.", findings.size());
            }
            return List.copyOf(findings);
        } catch (RuntimeException failed) {
            log.warn("End-of-life detection failed — step skipped: {}", failed.getMessage());
            return List.of();
        }
    }

    /**
     * The finding's prose.
     *
     * <p>Carried through ingestion's descriptions map, the same one that carries CVE
     * descriptions — an end-of-life finding with no sentence would display an identifier alone.
     */
    @Override
    public String describe(FindingEntity finding) {
        return finding.getPackageName() + " " + finding.getPackageVersion()
                + " belongs to a cycle whose security support has ended or is about to. No fix will be published "
                + "for this component's next vulnerability, whatever it turns out to be.";
    }

    private FindingEntity finding(ScanEntity scan, Candidate candidate, Release release, Product product, String severity) {
        // **Stable from one patch of a cycle to the next**, because the date applies to the
        // cycle: "python 3.9" reaches end of life, not "python 3.9.18". The fingerprint is built
        // on this, so the issue keeps its history and its triage when the patch moves.
        String identifier = "EOL-" + candidate.product() + "-" + release.name();
        Optional<String> recommended = LifeCycle.recommendedVersion(product);

        FindingEntity finding = new FindingEntity();
        finding.setScanId(scan.getId());
        finding.setType(FindingType.EOL.wireName());
        finding.setSeverity(severity);
        finding.setIdentifier(identifier);
        finding.setPackageName(candidate.label());
        finding.setPackageVersion(candidate.version());
        finding.setPurl(candidate.purl());
        finding.setSource(SOURCE);
        finding.setLink("https://endoflife.date/" + candidate.product());
        finding.setFixVersions(recommended.orElse(null));
        finding.setFixState(recommended.isPresent() ? "fixed" : "unknown");
        finding.setCreatedAt(clock.instant());
        finding.setIsKev(false);
        return finding;
    }

    private List<Candidate> candidates(Sbom sbom) {
        List<Candidate> found = new ArrayList<>();

        sbom.distro().ifPresent(distro -> {
            // A distribution's identifier already *is* the product name in most cases (`rhel`,
            // `alpine`, `debian`): asking for it directly costs less than downloading the
            // product list to check, and a 404 is an answer in itself.
            if (product(distro.id()).isPresent()) {
                found.add(new Candidate(distro.id(), distro.version(), distro.label(), null));
            }
        });

        found.addAll(LifeCycle.packageCandidates(sbom, identifierIndex()));
        return found;
    }

    private Map<String, String> identifierIndex() {
        if (purlIndex != null && Duration.between(purlIndexFetchedAt, clock.instant()).compareTo(CACHE_TTL) < 0) {
            return purlIndex;
        }

        Map<String, String> index = safeFetch(PURL_IDENTIFIERS_URL, "end-of-life index")
                .map(LifeCycle::parseIdentifierIndex)
                .orElseGet(Map::of);
        // Cached **even when empty**, so a catalog outage is retried on the next cache cycle
        // rather than on every scan.
        purlIndex = index;
        purlIndexFetchedAt = clock.instant();
        log.info("End-of-life index: {} purl match(es).", index.size());
        return index;
    }

    private Optional<Product> product(String name) {
        Cached<Product> cached = products.get(name);
        if (cached != null && Duration.between(cached.fetchedAt(), clock.instant()).compareTo(CACHE_TTL) < 0) {
            return Optional.ofNullable(cached.value());
        }

        String url = API_ROOT + "/products/" + URLEncoder.encode(name, StandardCharsets.UTF_8) + "/";
        Product product = safeFetch(url, "end-of-life product " + name)
                .flatMap(LifeCycle::parseProduct)
                .orElse(null);
        // Cached including the absence: an unknown product must not be asked for again on every
        // package of every scan.
        products.put(name, new Cached<>(product, clock.instant()));
        return Optional.ofNullable(product);
    }

    /**
     * A call whose failure costs only its own answer.
     *
     * <p>Caught here rather than around the loop: one unreachable product must not lose the
     * cycles already matched. A partial result beats none, and the missing products are seen
     * again on the next scan.
     */
    private Optional<JsonNode> safeFetch(String url, String label) {
        try {
            return outbound.get(url, OutboundPolicy.PUBLIC_ONLY, label);
        } catch (RuntimeException unavailable) {
            log.warn("End-of-life lookup failed for {}: {}", url, unavailable.getMessage());
            return Optional.empty();
        }
    }
}
