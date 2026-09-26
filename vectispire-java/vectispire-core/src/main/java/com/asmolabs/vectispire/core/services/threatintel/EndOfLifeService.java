package com.asmolabs.vectispire.core.services.threatintel;

import com.asmolabs.vectispire.common.domain.eol.LifeCycle;
import com.asmolabs.vectispire.common.domain.eol.LifeCycle.Candidate;
import com.asmolabs.vectispire.common.domain.eol.LifeCycle.Product;
import com.asmolabs.vectispire.common.domain.eol.LifeCycle.Release;
import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.net.OutboundPolicy;
import com.asmolabs.vectispire.common.domain.sbom.Sbom;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.core.persistence.FindingEntity;
import com.asmolabs.vectispire.core.persistence.ScanEntity;
import com.asmolabs.vectispire.core.services.outbound.OutboundJson;
import com.asmolabs.vectispire.core.services.scanning.ScanIngestor;
import com.asmolabs.vectispire.core.services.shared.SettingsService;
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
import java.util.concurrent.ConcurrentHashMap;
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

    /**
     * <b>Both caches are reached from more than one thread, so both are published safely.</b>
     *
     * <p>This is a singleton, and it is called from {@code ScanIngestor} — which runs on the
     * scan worker's threads and on the request thread that accepts a remote agent's results.
     * Two scans finishing at once is the ordinary case, not the exotic one.
     *
     * <p>The index was two plain fields, read as a pair and written as a pair. Even made
     * {@code volatile} they could be read torn — a fresh map beside a stale timestamp, or the
     * reverse — so they are one immutable {@link Cached} in one {@code volatile} field instead:
     * a reader sees both halves of a refresh or neither.
     *
     * <p>The product cache was a plain {@link HashMap} mutated by those same threads. That does
     * not cost a stale read, which would be harmless here; it corrupts the table, and a
     * concurrent resize is the classic way to spin a worker thread at 100% forever.
     *
     * <p><b>No lock around the fetch, deliberately.</b> Two threads may look the same product up
     * at once and both call out for it. That costs one redundant HTTP call and stores the same
     * answer twice; serialising every lookup would put a network round trip on the critical
     * path of every other scan being ingested.
     */
    private volatile Cached<Map<String, String>> purlIndex = new Cached<>(null, Instant.EPOCH);

    private final Map<String, Cached<Product>> products = new ConcurrentHashMap<>();

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
     * <p><b>Absent on any failure, never empty</b> (decision 0007). It returned an empty list,
     * and the ingestion had already declared the type scanned: an outage of the catalog read as
     * "no end-of-life platform here" and resolved every end-of-life issue of the target, with
     * their triage. A partial pass is absent too — a product whose lookup failed would otherwise
     * see its issue resolved while the neighbours' were kept. The scan itself still completes;
     * only this step is reported as not having run, and the backlog is left alone.
     */
    @Override
    public Optional<List<FindingEntity>> findings(ScanEntity scan, JsonNode sbomDocument) {
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
            return Optional.of(List.copyOf(findings));
        } catch (RuntimeException failed) {
            log.warn("End-of-life detection failed — step skipped, backlog left as it was: {}", failed.getMessage());
            return Optional.empty();
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
        // Read once into a local: re-reading the field would be re-reading a value another
        // thread may have replaced between the check and the return.
        Cached<Map<String, String>> cached = purlIndex;
        if (cached.value() != null
                && Duration.between(cached.fetchedAt(), clock.instant()).compareTo(CACHE_TTL) < 0) {
            return cached.value();
        }

        Map<String, String> index = outbound.get(PURL_IDENTIFIERS_URL, OutboundPolicy.PUBLIC_ONLY, "end-of-life index")
                .map(LifeCycle::parseIdentifierIndex)
                .orElseGet(Map::of);
        // **Only an answer is cached, never an outage.** A failure used to be cached as an empty
        // index for the whole TTL, so a single unreachable minute blinded the step for a day —
        // and, while the step still returned an empty list, resolved every end-of-life issue on
        // each scan of that day. A failure now propagates and makes the step absent; the next
        // scan asks again, which during an outage costs one refused request per scan.
        purlIndex = new Cached<>(index, clock.instant());
        log.info("End-of-life index: {} purl match(es).", index.size());
        return index;
    }

    private Optional<Product> product(String name) {
        Cached<Product> cached = products.get(name);
        if (cached != null && Duration.between(cached.fetchedAt(), clock.instant()).compareTo(CACHE_TTL) < 0) {
            return Optional.ofNullable(cached.value());
        }

        String url = API_ROOT + "/products/" + URLEncoder.encode(name, StandardCharsets.UTF_8) + "/";
        Product product = outbound.get(url, OutboundPolicy.PUBLIC_ONLY, "end-of-life product " + name)
                .flatMap(LifeCycle::parseProduct)
                .orElse(null);
        // Cached including the absence: an unknown product — a 404, which is an answer — must not
        // be asked for again on every package of every scan. A failure raises before this line
        // and is not cached.
        products.put(name, new Cached<>(product, clock.instant()));
        return Optional.ofNullable(product);
    }
}
