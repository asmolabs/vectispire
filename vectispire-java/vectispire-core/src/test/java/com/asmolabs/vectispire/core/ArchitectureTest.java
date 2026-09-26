package com.asmolabs.vectispire.core;

import static com.tngtech.archunit.library.Architectures.layeredArchitecture;

import com.asmolabs.vectispire.core.services.audit.AuditLogQueryService;
import com.asmolabs.vectispire.core.services.audit.AuditLogService;
import com.asmolabs.vectispire.core.services.issues.IssueDecisionService;
import com.asmolabs.vectispire.core.services.siem.SiemEvents;
import com.asmolabs.vectispire.core.services.tickets.TicketService;
import com.tngtech.archunit.base.DescribedPredicate;
import com.tngtech.archunit.core.domain.Dependency;
import com.tngtech.archunit.core.domain.JavaClass;
import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.lang.ArchCondition;
import com.tngtech.archunit.lang.ConditionEvents;
import com.tngtech.archunit.lang.SimpleConditionEvent;
import com.tngtech.archunit.lang.syntax.ArchRuleDefinition;
import com.tngtech.archunit.library.dependencies.SliceRule;
import com.tngtech.archunit.library.dependencies.SlicesRuleDefinition;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The layer rule, checked.
 *
 * <p>The module split already carries the part that matters most: {@code vectispire-agent} does
 * not depend on {@code vectispire-core}, so a driver is not on its classpath and the violation
 * fails to compile rather than failing review. What one module cannot express is the rule
 * <em>inside</em> {@code vectispire-core}, and that is what this file is for.
 *
 * <p>It exists because an architecture rule written in a document is not a rule: it is true
 * the day it is written and false six months later. The NestJS tree learned that, and its
 * {@code architecture.spec.ts} is this file's direct ancestor.
 *
 * <h2>Why {@code common.domain} is pure</h2>
 *
 * It carries the calculations that <em>decide</em>: an issue's fingerprint, the gate verdict,
 * the audit integrity chain, the export formats. They touch neither database nor network nor
 * Spring. Three consequences:
 *
 * <ol>
 *   <li>they are exhaustively testable, the only way to check rules whose failure raises no
 *       exception but destroys triage instead;
 *   <li>the same calculation serves the API, the scheduler and the UI — the verdict displayed
 *       <em>is</em> the one the gate returns, not a second one resembling it;
 *   <li>they survive a change of ORM or framework, which is exactly the event this code is
 *       living through.
 * </ol>
 */
@DisplayName("the layer rule")
class ArchitectureTest {

    private static final String ROOT = "com.asmolabs.vectispire";

    private static JavaClasses classes;

    @BeforeAll
    static void importClasses() {
        classes = new ClassFileImporter()
                .withImportOption(ImportOption.Predefined.DO_NOT_INCLUDE_TESTS)
                .importPackages(ROOT);
    }

    @Test
    @DisplayName("finds classes to check at all")
    void findsSomethingToCheck() {
        // A wrong package name would make every rule below pass without checking
        // anything. That is the failure mode of an architecture suite, so it is asserted
        // first — and against the domain specifically, since that is the package the rules
        // care most about and the one a typo would silently empty.
        org.assertj.core.api.Assertions.assertThat(classes).isNotEmpty();
        org.assertj.core.api.Assertions
                .assertThat(classes.stream()
                        .anyMatch(c -> c.getPackageName().startsWith(ROOT + ".common.domain")))
                .as("the domain package must be on the classpath and populated")
                .isTrue();
    }

    @Test
    @DisplayName("no layer reaches a layer above it")
    void layersOnlyReachDownwards() {
        layeredArchitecture()
                .consideringOnlyDependenciesInAnyPackage(ROOT + "..")
                .layer("domain").definedBy(ROOT + ".common.domain..")
                .layer("scanning").definedBy(ROOT + ".common.scanning..")
                .layer("persistence").definedBy(ROOT + ".core.persistence..")
                .layer("repositories").definedBy(ROOT + ".core.repositories..")
                .layer("services").definedBy(ROOT + ".core.services..")
                .layer("api").definedBy(ROOT + ".core.api..")

                // Read downwards: who is allowed to see me.
                .whereLayer("api").mayNotBeAccessedByAnyLayer()
                .whereLayer("services").mayOnlyBeAccessedByLayers("api")
                // Not `api`: a controller maps HTTP, a service reads, decides and writes. Thirty-three
                // controllers reached repositories directly when this line still allowed it; they
                // were moved behind services on 2026-09-24, under a ratchet that shrank to nothing.
                .whereLayer("repositories").mayOnlyBeAccessedByLayers("services")
                .whereLayer("persistence").mayOnlyBeAccessedByLayers("repositories", "services", "api")
                .whereLayer("scanning").mayOnlyBeAccessedByLayers("services", "api")
                // No optional layers and no empty-should escape any more: every layer is
                // populated, so an empty one is now a package that was renamed or deleted — and
                // this rule going quiet is exactly how that would go unnoticed.
                .check(classes);
    }

    /**
     * The domains of {@code core.services} that every other domain may use: the two helpers left
     * without a domain, the deployment's settings, the door out, encryption, the audit writer and
     * the outbox relay (decision 0026).
     */
    private static final Set<String> FOUNDATION = Set.of("shared", "settings", "outbound", "crypto", "audit", "outbox");

    /**
     * What each domain may use besides itself — and, above the foundation, besides the foundation.
     *
     * <p>This is the table of decision 0026, and it is the code as it stood when the flat package
     * was split: every line is a dependency that existed. Adding one is a decision to take in the
     * review that needs it, not a line to append until the build is green — the flat package is
     * what "append until green" produced. {@code platform} is absent on purpose: it holds the
     * composition roots, may use any domain, and nothing may use it.
     */
    private static final Map<String, Set<String>> MAY_USE = Map.ofEntries(
            Map.entry("shared", Set.of()),
            Map.entry("settings", Set.of()),
            Map.entry("outbound", Set.of()),
            Map.entry("crypto", Set.of("outbound")),
            Map.entry("audit", Set.of()),
            Map.entry("outbox", Set.of()),
            Map.entry("access", Set.of()),
            Map.entry("siem", Set.of()),
            Map.entry("rules", Set.of()),
            Map.entry("inventory", Set.of()),
            Map.entry("ai", Set.of("access")),
            Map.entry("issues", Set.of("access")),
            Map.entry("tickets", Set.of("access", "issues")),
            Map.entry("scanning", Set.of("access", "inventory", "issues", "rules")),
            Map.entry("agents", Set.of("access", "scanning")),
            Map.entry("targets", Set.of("access", "scanning")),
            Map.entry("threatintel", Set.of("scanning", "siem")),
            Map.entry("gate", Set.of("issues", "rules", "siem")),
            Map.entry("notifications", Set.of("issues", "scanning")),
            Map.entry("exports", Set.of("gate", "issues")),
            Map.entry("posture", Set.of("access", "gate", "inventory", "issues", "notifications")),
            Map.entry("compliance",
                    Set.of("access", "ai", "exports", "gate", "inventory", "issues", "posture", "rules")));

    private static final String PLATFORM = "platform";

    /**
     * A dependency that points against the table and closes a cycle, kept because breaking it is
     * more than a package move — each says why, and what would remove it.
     */
    private record KnownCycle(Class<?> origin, Class<?> target, String reason) {}

    /**
     * <b>A list that only shrinks.</b> Two entries on 2026-09-26, both between domains whose
     * classes sit where the future modules would own them (decision 0026); placing a class in the
     * wrong domain to make a cycle disappear would have hidden it rather than removed it.
     * {@link #knownCyclesAreStillThere} fails the day one of them goes, so the entry leaves with it.
     */
    private static final List<KnownCycle> KNOWN_CYCLES = List.of(
            new KnownCycle(AuditLogQueryService.class, SiemEvents.class,
                    "verifying the chain publishes AUDIT_CHAIN_BROKEN, while the SIEM listens to the audit"
                            + " log it verifies; an application event the SIEM subscribes to would remove it"),
            new KnownCycle(IssueDecisionService.class, TicketService.class,
                    "attaching a ticket validates the reference against the configured tracker, while the"
                            + " tracker's webhook and sweep transition issues; the validation belongs to tickets"));

    private static String servicesDomain(String domain) {
        return ROOT + ".core.services." + domain + "..";
    }

    /** The domain a class belongs to, or empty outside {@code core.services}. */
    private static Optional<String> domainOf(JavaClass type) {
        String prefix = ROOT + ".core.services.";
        String name = type.getPackageName();
        if (!name.startsWith(prefix)) {
            return Optional.empty();
        }
        String rest = name.substring(prefix.length());
        int dot = rest.indexOf('.');
        return Optional.of(dot < 0 ? rest : rest.substring(0, dot));
    }

    /** The class itself, its nested classes and its lambdas' holders — what a source file owns. */
    private static boolean ownedBy(JavaClass type, Class<?> owner) {
        return type.getName().equals(owner.getName()) || type.getName().startsWith(owner.getName() + "$");
    }

    private static boolean isKnownCycle(Dependency dependency) {
        return KNOWN_CYCLES.stream().anyMatch(known -> ownedBy(dependency.getOriginClass(), known.origin())
                && ownedBy(dependency.getTargetClass(), known.target()));
    }

    private static boolean mayUse(String from, String to) {
        return MAY_USE.getOrDefault(from, Set.of()).contains(to)
                || (!FOUNDATION.contains(from) && FOUNDATION.contains(to));
    }

    @Test
    @DisplayName("every service lives in a known domain")
    void everyServiceLivesInAKnownDomain() {
        // Without this the table below could be bypassed by a class dropped back into the flat
        // package, or into a new sub-package nobody listed: the dependency rule only constrains the
        // domains it names.
        Stream<String> domains = Stream.concat(MAY_USE.keySet().stream(), Stream.of(PLATFORM));
        ArchRuleDefinition.classes()
                .that().resideInAPackage(ROOT + ".core.services..")
                .should().resideInAnyPackage(domains.map(ArchitectureTest::servicesDomain).toArray(String[]::new))
                .check(classes);
    }

    @Test
    @DisplayName("the service domains form no cycle but the ones recorded")
    void serviceDomainsFormNoCycle() {
        // A cycle between two domains makes them one domain with two names: neither can be read,
        // tested or changed without the other.
        SliceRule rule = SlicesRuleDefinition.slices()
                .matching(ROOT + ".core.services.(*)..")
                .should().beFreeOfCycles();
        for (KnownCycle known : KNOWN_CYCLES) {
            rule = rule.ignoreDependency(
                    DescribedPredicate.describe(known.origin().getSimpleName(), type -> ownedBy(type, known.origin())),
                    DescribedPredicate.describe(known.target().getSimpleName(), type -> ownedBy(type, known.target())));
        }
        rule.check(classes);
    }

    @Test
    @DisplayName("a recorded cycle is still a cycle, or it leaves the list")
    void knownCyclesAreStillThere() {
        for (KnownCycle known : KNOWN_CYCLES) {
            boolean present = classes.stream()
                    .filter(type -> ownedBy(type, known.origin()))
                    .flatMap(type -> type.getDirectDependenciesFromSelf().stream())
                    .anyMatch(dependency -> ownedBy(dependency.getTargetClass(), known.target()));
            org.assertj.core.api.Assertions.assertThat(present)
                    .as("%s no longer depends on %s: remove it from KNOWN_CYCLES",
                            known.origin().getSimpleName(), known.target().getSimpleName())
                    .isTrue();
        }
    }

    @Test
    @DisplayName("a service domain uses only the domains it is allowed")
    void serviceDomainsDependOnlyWhereAllowed() {
        // Acyclic is not enough: a new dependency pointing the wrong way can be acyclic today and
        // close a cycle with the next one. The table fixes the direction.
        ArchCondition<JavaClass> useOnlyAllowedDomains =
                new ArchCondition<>("use only the domains decision 0026 allows") {
                    @Override
                    public void check(JavaClass type, ConditionEvents events) {
                        // A class outside any domain is the previous rule's to report.
                        String from = domainOf(type).orElse(PLATFORM);
                        if (from.equals(PLATFORM)) {
                            return;
                        }
                        for (Dependency dependency : type.getDirectDependenciesFromSelf()) {
                            Optional<String> to = domainOf(dependency.getTargetClass());
                            if (to.isEmpty() || to.get().equals(from) || mayUse(from, to.get())
                                    || isKnownCycle(dependency)) {
                                continue;
                            }
                            events.add(SimpleConditionEvent.violated(dependency, dependency.getDescription()
                                    + " — services." + from + " may not use services." + to.get()));
                        }
                    }
                };
        ArchRuleDefinition.classes()
                .that().resideInAPackage(ROOT + ".core.services..")
                .should(useOnlyAllowedDomains)
                .check(classes);
    }

    @Test
    @DisplayName("the api layer opens no transaction: a transaction is a decision, and decisions are the services'")
    void apiOpensNoTransaction() {
        // The layering above keeps `api` out of the repositories; this keeps it out of the
        // transaction boundary, which is the other half of "a controller maps HTTP". Three
        // controllers held a `TransactionTemplate` or `@Transactional` before the move.
        ArchRuleDefinition.noClasses()
                .that().resideInAPackage(ROOT + ".core.api..")
                .should().dependOnClassesThat()
                .haveFullyQualifiedName("org.springframework.transaction.support.TransactionTemplate")
                .orShould().dependOnClassesThat()
                .haveFullyQualifiedName("org.springframework.transaction.annotation.Transactional")
                .check(classes);
    }

    @Test
    @DisplayName("no controller writes the audit log: the service that performs an action records it")
    void controllersWriteNoAuditEntry() {
        // An entry written by the route is an entry the next caller of the same service does not
        // write — a second route, a scheduled job — and whether it is written before or after the
        // commit becomes each controller's own guess. Ten controllers still held `AuditLogService`
        // when this was added. `api.security` is left out on purpose: the filter chain audits what
        // happens before any controller runs — a refused bearer token, a denied route, a
        // single-sign-on callback — events that belong to no service method the entry could move to.
        // Named by class literal, not by string: the class moved package once, and a string naming
        // where it used to be would have left this rule checking nothing.
        ArchRuleDefinition.noClasses()
                .that().resideInAPackage(ROOT + ".core.api..")
                .and().resideOutsideOfPackage(ROOT + ".core.api.security..")
                .should().dependOnClassesThat()
                .haveFullyQualifiedName(AuditLogService.class.getName())
                .orShould().dependOnClassesThat()
                .haveFullyQualifiedName(AuditLogService.Record.class.getName())
                .check(classes);
    }

    @Test
    @DisplayName("the domain depends on no framework and no driver")
    void domainIsPure() {
        // A pure calculation importing Hibernate stops being testable without a database;
        // one importing Spring stops being reusable outside the server. Both are how a
        // domain layer quietly becomes a service layer.
        ArchRuleDefinition.noClasses()
                .that().resideInAPackage(ROOT + ".common.domain..")
                .should().dependOnClassesThat()
                .resideInAnyPackage(
                        "org.springframework..",
                        "jakarta.persistence..",
                        "org.hibernate..",
                        "java.sql..",
                        "javax.sql..",
                        "org.flywaydb..",
                        "liquibase..",
                        // The scanning half of `vectispire-common` needs a Docker client; the
                        // domain half must never. A calculation that reached the daemon would
                        // stop being testable without one, which is the property the whole
                        // layer exists for.
                        "com.github.dockerjava..")
                .check(classes);
    }

    @Test
    @DisplayName("only the repositories speak SQL")
    void onlyRepositoriesReachTheDatabase() {
        ArchRuleDefinition.noClasses()
                .that().resideInAnyPackage(ROOT + ".core.services..", ROOT + ".core.api..")
                .should().dependOnClassesThat()
                .resideInAnyPackage("java.sql..", "javax.sql..", "org.hibernate..")
                .check(classes);
    }

    @Test
    @DisplayName("an outbound call goes through the door that validates and pins")
    void onlyTheOutboundDoorSpeaksHttpOutwards() {
        // **The rule the guard cannot enforce for itself.** `OutboundUrlGuard` refuses a URL
        // resolving to link-local or, for the model review, to anything public — and none of
        // that happens if a seventh caller builds its own client and calls a setting straight.
        // Nothing about such a call looks wrong: it works perfectly, right up to the redirect
        // or the rebind. The three classes named below are the only ones allowed to hold a
        // client, and each one validates first.
        //
        // `03-security.md` claimed this rule existed for as long as it did not: it described
        // the NestJS suite, which was not carried over. Written down now, in the place that
        // fails.
        ArchRuleDefinition.noClasses()
                .that().resideInAPackage(ROOT + ".core..")
                // Matched on the full name rather than the simple one, so a nested or
                // anonymous class counts as its owner: the resolver inside `PinnedHttpSender`
                // is an anonymous `DnsResolver`, whose simple name is empty, and a simple-name
                // exclusion silently failed to cover it.
                .and().haveNameNotMatching(".*\\.(PinnedHttpSender|OutboundPost|OutboundJson)(\\$.*)?")
                .should().dependOnClassesThat()
                .resideInAnyPackage("java.net.http..", "org.apache.hc..")
                .check(classes);
    }

    @Test
    @DisplayName("a raw socket is opened by the syslog sender alone, to the address the guard pinned")
    void onlySyslogSenderOpensSockets() {
        // The HTTP rule above says nothing about `java.net.Socket`: a second class opening one
        // would reach the metadata endpoint or the Docker proxy with no guard in the way, and
        // would look like a perfectly ordinary TCP client in review.
        ArchRuleDefinition.noClasses()
                .that().resideInAPackage(ROOT + ".core..")
                .and().haveNameNotMatching(".*\\.SyslogSender(\\$.*)?")
                .should().dependOnClassesThat()
                .haveFullyQualifiedName("java.net.Socket")
                .orShould().dependOnClassesThat().haveFullyQualifiedName("java.net.DatagramSocket")
                .orShould().dependOnClassesThat().haveFullyQualifiedName("java.nio.channels.SocketChannel")
                .orShould().dependOnClassesThat().haveFullyQualifiedName("java.nio.channels.DatagramChannel")
                .orShould().dependOnClassesThat().resideInAPackage("javax.net..")
                .check(classes);
    }

    @Test
    @DisplayName("an entity describes a table and nothing else")
    void persistenceHasNoWebOrService() {
        // Dependency injection is not an entity's business, and neither is HTTP.
        ArchRuleDefinition.noClasses()
                .that().resideInAPackage(ROOT + ".core.persistence..")
                .should().dependOnClassesThat()
                .resideInAnyPackage("org.springframework.web..", "jakarta.servlet..")
                .check(classes);
    }

    @Test
    @DisplayName("case is folded without the host's locale")
    void caseIsFoldedWithoutTheHostLocale() {
        // `toUpperCase()` folds with the JVM's default locale. On a host set to Turkish, "i" becomes
        // "İ": a severity, a scope, an HTTP method or a framework name stops matching the constant
        // it was compared with, and a path lower-cased into a fingerprint changes with the machine
        // that scanned it. Forty-seven calls did it; `Locale.ROOT` is the only spelling allowed.
        ArchRuleDefinition.noClasses()
                .should().callMethod(String.class, "toUpperCase")
                .orShould().callMethod(String.class, "toLowerCase")
                .check(classes);
    }
}
