package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.core.persistence.IssueEntity;
import com.asmolabs.vectispire.core.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.repositories.GitRepositories;
import com.asmolabs.vectispire.core.repositories.Issues;
import jakarta.persistence.EntityManagerFactory;
import java.lang.reflect.Parameter;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import org.hibernate.SessionFactory;
import org.hibernate.stat.Statistics;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ValueConstants;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

/**
 * No GET route's cost may follow the size of the estate — the rule, not a list of four names.
 *
 * <p><b>Why this replaces an enumeration.</b> {@code ReadCostRoutesTest} pinned four routes by name.
 * They were the four an audit had measured, and the pin covers exactly those: a later sweep of the
 * whole GET surface found <b>three more</b> — {@code /epss/priorities} (which was also an N+1, one
 * threat-intel query per open issue), {@code /scorecards/global} and {@code /attack-paths/overview}
 * — none of which any test could have caught. Twice running, an audit scored what it had not
 * measured. A rule that walks the surface catches the next one; a list catches the last one.
 *
 * <p><b>The route table comes from Spring, not from a literal.</b> Asking
 * {@link RequestMappingHandlerMapping} for the mappings means a route added tomorrow is swept
 * tomorrow, and — the reason it matters more than convenience — that a route <em>renamed</em>
 * cannot quietly drop out of the sweep the way a hardcoded path would.
 *
 * <p><b>This replaces {@code ReadCostRoutesTest} rather than joining it.</b> That file pinned
 * {@code /dashboard}, {@code /dashboard/trends}, {@code /dashboard/posture-analytics} and
 * {@code /compliance/summary} — the four an audit had measured — with the same fixture and the
 * same counter. Everything it asserted is asserted here, over every route rather than four, so
 * keeping both would be two copies of one rule, and the stale copy is the one that stops being
 * updated. Its history is kept above because it is the reason this exists.
 *
 * <p><b>What is swept and what cannot be.</b> Only GET routes with no path variable and no
 * required query parameter can be called blind. The rest are listed by
 * {@link #everyCallableGetRouteIsSwept()} rather than passed over in silence: a route this test
 * cannot reach is <em>unmeasured</em>, which is not the same as sound, and saying so is the whole
 * difference between this file and a green tick.
 */
@DisplayName("no page's cost follows the size of the estate")
class ReadCostSweepTest extends ApiTestBase {

    /** The counters are off in the shipped configuration, and are the whole instrument here. */
    @DynamicPropertySource
    static void statistics(DynamicPropertyRegistry registry) {
        registry.add("spring.jpa.properties.hibernate.generate_statistics", () -> "true");
    }

    @Autowired
    private GitRepositories repositories;

    @Autowired
    private Issues issues;

    @Autowired
    private EntityManagerFactory entityManagerFactory;

    /**
     * Qualified by name: Actuator contributes a second {@code RequestMappingHandlerMapping} for
     * its own endpoints, and this sweep is about the application's routes.
     */
    @Autowired
    @Qualifier("requestMappingHandlerMapping")
    private RequestMappingHandlerMapping handlerMapping;

    private static final int SMALL = 20;
    private static final int LARGE = 220;

    /**
     * How much a route may grow between a 20-issue estate and a 220-issue one.
     *
     * <p>Not a ceiling on the count — a number like that gets chosen to pass. This is a ceiling on
     * the <em>slope</em>, which is the property that actually broke. A bounded read sits at 0; the
     * paginated backlog moves by about 35 because a page of 20 issues is genuinely 20 more rows,
     * and that is legitimate. A whole-table read moves by 200.
     */
    private static final int MAX_GROWTH = 60;

    /**
     * Routes whose read is allowed to follow the estate, with the reason for each.
     *
     * <p><b>The distinction this list encodes.</b> A read that follows the estate is a defect when
     * the <em>answer</em> does not: {@code /api/v1/dashboard} returned a fixed-size posture summary
     * while materialising a row per issue, and that is what this test exists to catch. It is not a
     * defect when the answer follows the estate too — a document export carries one entry per
     * issue by definition, and reading n rows to write n statements is the job rather than the
     * bug.
     *
     * <p><b>This excuses a growing number of entities, never a growing number of queries.</b> A
     * document that names every issue still reads them in one query; a lookup per row is a defect
     * whatever the response contains, so the query check below consults no exemption list at all.
     *
     * <p>Every entry is a claim a reader can check — the shape
     * {@code RouteScopingTest.NAMES_NO_TARGET} uses, for the same reason: a list that grows
     * whenever the test goes red ends up exempting the next defect. <b>Adding to it should feel
     * like an argument, because it is one.</b>
     *
     * <p><b>What these four are still exposed to, and this test does not measure.</b> An export
     * whose read is legitimately O(n) still builds the whole document in memory before writing a
     * byte. That is a different question from the one here — the memory profile of a download
     * rather than the cost of a page — and streaming them is worth its own pass. Named so it is
     * not mistaken for settled.
     */
    private static final Map<String, String> MAY_GROW = Map.of(
            "/api/v1/vex/aggregate.json",
                    "an OpenVEX document carries one statement per issue: the answer is the estate",
            "/api/v1/cyclonedx/aggregate.json",
                    "a CycloneDX aggregate carries one vulnerability entry per issue, by format",
            "/api/v1/csaf/aggregate.json",
                    "a CSAF advisory set carries one entry per issue, by format",
            "/api/v1/compliance/evidence-bundle.zip",
                    "the evidence bundle is the whole record by definition — audit log included, "
                            + "which is why it is the one export reserved to a security lead");

    /**
     * Callable GET routes that still cannot be measured, with the reason for each.
     *
     * <p>Separate from {@link #MAY_GROW} on purpose: those are routes whose cost is argued to be
     * allowed to grow, these are routes whose cost <b>is not known at all</b>. Conflating the two
     * would let "we never measured it" read as "we decided it was fine".
     */
    private static final Map<String, String> CANNOT_ANSWER_AN_ADMINISTRATOR = Map.of(
            // Authenticated by an agent key rather than a session, so an administrator's token is
            // the wrong credential and 401 is the correct answer. Its cost is bounded by the queue
            // rather than by the estate — one job, or none.
            "/api/v1/agent/jobs", "the agent protocol, authenticated by agent key and not by session",

            // Answers 404 until two scans exist to diff. Seeding a second scan here would make the
            // fixture about SBOM lineage rather than about read cost.
            "/api/v1/sbom/diff/latest", "404 until the fixture holds two scans to compare");

    @Test
    @DisplayName("a GET route's entity loads do not follow the number of issues")
    void noGetRouteLoadsTheEstate() throws Exception {
        List<String> routes = callableGetRoutes();
        long target = repository("https://example.invalid/sweep.git");
        String admin = asAdmin();

        seed(target, 0, SMALL);
        Map<String, Cost> small = measure(routes, admin);

        seed(target, SMALL, LARGE);
        Map<String, Cost> large = measure(routes, admin);

        List<String> growing = new ArrayList<>();
        for (String route : routes) {
            Cost before = small.get(route);
            Cost after = large.get(route);

            // **Two counters, because they are two different defects.** Entities that follow the
            // estate are one query returning every row; queries that follow it are a lookup inside
            // a loop. The EPSS ranking was both at once, and a sweep that watched only the first
            // would have gone green on the half of it that was fixed.
            if (!MAY_GROW.containsKey(route) && after.entities() - before.entities() > MAX_GROWTH) {
                growing.add("%s loaded %d entities at %d issues against %d at %d (+%d)".formatted(
                        route, after.entities(), LARGE, before.entities(), SMALL,
                        after.entities() - before.entities()));
            }
            if (after.queries() - before.queries() > MAX_GROWTH) {
                growing.add(("%s issued %d queries at %d issues against %d at %d (+%d) — a lookup "
                        + "inside a loop, which no MAY_GROW entry excuses").formatted(
                        route, after.queries(), LARGE, before.queries(), SMALL,
                        after.queries() - before.queries()));
            }
        }

        // A sweep that swept nothing passes forever — the failure mode this project has shipped
        // three times. If the route table stops answering, that is the bug, not a clean run.
        assertThat(routes)
                .as("no GET routes were callable: the handler mapping or the filter below is "
                        + "wrong, and a sweep that inspects nothing passes forever")
                .hasSizeGreaterThan(25);

        assertThat(growing)
                .as("these routes answer by materialising a row per issue, so their cost is the "
                        + "size of the deployment rather than the size of the answer. Project the "
                        + "columns the response actually needs (see IssueRows), batch any per-item "
                        + "lookup, or bound what the response returns — and if the read genuinely "
                        + "has to follow the estate, add it to MAY_GROW with the reason")
                .isEmpty();
    }

    /**
     * The GET routes this sweep cannot call, named so that "unmeasured" never reads as "sound".
     *
     * <p>This does not fail on them. It fails if the <em>reason</em> they are unreachable stops
     * being "needs an argument we cannot invent" — that is, if the callable set collapses.
     */
    @Test
    @DisplayName("the routes the sweep cannot reach are named rather than passed over")
    void everyCallableGetRouteIsSwept() {
        Set<String> all = new TreeSet<>();
        Set<String> callable = new TreeSet<>(callableGetRoutes());

        for (Map.Entry<RequestMappingInfo, HandlerMethod> entry : handlerMapping.getHandlerMethods().entrySet()) {
            if (isGet(entry.getKey())) {
                all.addAll(patternsOf(entry.getKey()));
            }
        }

        Set<String> unreachable = new TreeSet<>(all);
        unreachable.removeAll(callable);

        // Printed, not asserted on by name: the list is documentation for whoever reads a run, and
        // pinning its contents would turn every new parameterised route into a failure here.
        System.out.println("read-cost sweep: " + callable.size() + " of " + all.size()
                + " GET routes callable blind; unmeasured because they need an argument:");
        unreachable.forEach(route -> System.out.println("  - " + route));

        assertThat(callable)
                .as("the sweep can no longer call any route, so noGetRouteLoadsTheEstate is "
                        + "measuring nothing")
                .isNotEmpty();
    }

    /**
     * GET routes that can be called with no argument at all.
     *
     * <p>A path variable has no value this test could invent that would mean anything, and a
     * required query parameter answers 400 — which loads nothing and would pass the assertion
     * above forever. Both are excluded here rather than tolerated there.
     */
    private List<String> callableGetRoutes() {
        Set<String> routes = new LinkedHashSet<>();

        for (Map.Entry<RequestMappingInfo, HandlerMethod> entry : handlerMapping.getHandlerMethods().entrySet()) {
            RequestMappingInfo info = entry.getKey();
            if (!isGet(info) || requiresAQueryParameter(entry.getValue())) {
                continue;
            }
            for (String pattern : patternsOf(info)) {
                if (pattern.startsWith("/api/")
                        && !pattern.contains("{")
                        && !CANNOT_ANSWER_AN_ADMINISTRATOR.containsKey(pattern)) {
                    routes.add(pattern);
                }
            }
        }
        return List.copyOf(routes);
    }

    private static boolean isGet(RequestMappingInfo info) {
        return info.getMethodsCondition().getMethods().contains(RequestMethod.GET);
    }

    private static Set<String> patternsOf(RequestMappingInfo info) {
        return info.getPathPatternsCondition() != null
                ? info.getPathPatternsCondition().getPatternValues()
                : Set.of();
    }

    private static boolean requiresAQueryParameter(HandlerMethod handler) {
        for (Parameter parameter : handler.getMethod().getParameters()) {
            RequestParam annotation = parameter.getAnnotation(RequestParam.class);
            if (annotation != null
                    && annotation.required()
                    && ValueConstants.DEFAULT_NONE.equals(annotation.defaultValue())) {
                return true;
            }
        }
        return false;
    }

    /** Entities materialised and queries issued, for one route. */
    private record Cost(long entities, long queries) {}

    private Map<String, Cost> measure(List<String> routes, String token) throws Exception {
        Map<String, Cost> loads = new java.util.LinkedHashMap<>();
        for (String route : routes) {
            Statistics statistics = entityManagerFactory.unwrap(SessionFactory.class).getStatistics();
            statistics.clear();
            int status = mvc.perform(authenticated(get(route), token)).andReturn().getResponse().getStatus();
            // A route that answers anything but 200 loaded nothing, and counting that as a cheap
            // read is how a renamed route passes this test forever.
            // A route that answers anything but 200 loaded nothing, and counting that as a cheap
            // read is how a renamed route passes this test forever.
            assertThat(status)
                    .as("%s answered %d, so its cost was not measured — a non-200 loads nothing "
                            + "and would satisfy the growth assertion whatever the route does. If "
                            + "it cannot answer 200 to an administrator on an empty fixture, add "
                            + "it to CANNOT_ANSWER_AN_ADMINISTRATOR with the reason", route, status)
                    .isEqualTo(200);
            loads.put(route, new Cost(statistics.getEntityLoadCount(), statistics.getQueryExecutionCount()));
        }
        return loads;
    }

    private long repository(String url) {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl(url);
        repository.setBranch("main");
        return repositories.save(repository).getId();
    }

    private void seed(long repoId, int from, int to) {
        for (int index = from; index < to; index++) {
            IssueEntity issue = new IssueEntity();
            issue.setRepoId(repoId);
            issue.setFingerprint("sweep-" + repoId + "-" + index);
            issue.setType(FindingType.VULNERABILITY.wireName());
            issue.setIdentifier("CVE-SWEEP-" + index);
            issue.setSeverity(Severity.HIGH.wireName());
            // Half resolved, so the resolved-only reads have something to average and the open
            // ones something to count: a fixture that is all one state hides half the queries.
            issue.setState(index % 4 == 0 ? IssueState.RESOLVED.wireName() : IssueState.OPEN.wireName());
            issue.setTriageStatus(TriageStatus.UNDER_REVIEW.wireName());
            issue.setFirstSeenAt(Instant.now().minusSeconds(86_400L * 30));
            issue.setLastSeenAt(Instant.now());
            issue.setResolvedAt(index % 4 == 0 ? Instant.now().minusSeconds(86_400L * 5) : null);
            issue.setTimesSeen(1);
            issues.save(issue);
        }
    }
}
