package com.asmolabs.vectispire.core;

import static com.tngtech.archunit.library.Architectures.layeredArchitecture;

import com.asmolabs.vectispire.core.audit.AuditLogService;
import com.tngtech.archunit.base.DescribedPredicate;
import com.tngtech.archunit.core.domain.JavaClass;
import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.lang.ArchCondition;
import com.tngtech.archunit.lang.ConditionEvents;
import com.tngtech.archunit.lang.SimpleConditionEvent;
import com.tngtech.archunit.lang.syntax.ArchRuleDefinition;
import java.util.List;
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
 * <h2>One packaging, one set of layers</h2>
 *
 * The control plane is packaged by vertical module (decisions 0028 and 0029): a domain is {@code
 * core.<domain>}, its API at the root, its controllers in {@code web}, its implementation in {@code
 * internal}, its entities and repositories in {@code persistence}. The layers are the same six they
 * were when the packages were the layers — {@code core.api}, {@code core.services}, {@code
 * core.repositories}, {@code core.persistence}, emptied by step 5 of the migration — read now as the
 * same place in every module. Outside the modules there is {@code core.config}, the datasource and
 * the engines' setup, which belongs to no domain.
 *
 * <h2>Inside a module, not between modules</h2>
 *
 * What crosses between modules is Spring Modulith's to verify since step 6 (decision 0030, {@code
 * ModularityTest}): no cycle, nothing reached but a module's root or a named interface, nothing used
 * that the module's {@code package-info} does not list. The rules that did the same here — the cycle
 * rule, {@code modulesMeetAtTheirApi}, the {@code MAY_USE} table — were retired with it, so that one
 * boundary has one authority. What stays is what Modulith cannot express, because it reads a module
 * whole: the layers inside every module, the places a class may sit, what a controller, an entity or a
 * repository may touch, and the few libraries a single class may hold.
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

    private static final String CORE = ROOT + ".core";

    /**
     * The vertical modules — {@code core.<domain>} with {@code web}, {@code internal} and {@code
     * persistence} beneath it (decision 0028). The foundation moved first (step 3 of the migration to
     * Spring Modulith), then the leaf and middle domains (step 4), then the core domains and what was
     * left of the composition roots (step 5, decision 0029): {@code shared} was emptied, {@code
     * maintenance} is the port the periodic jobs are contributed through, and {@code platform} is the
     * shell — the settings screen, the foundation's routes and the API-wide web configuration.
     */
    private static final List<String> MODULES = List.of(
            // Step 3: the foundation.
            "settings", "outbound", "crypto", "audit", "outbox", "reporting",
            // Step 4: the leaf and middle domains, in an order where none reaches a module still to come
            // through anything but the layered packages.
            "siem", "rules", "ai", "threatintel", "tickets", "agents", "notifications", "exports", "gate",
            "inventory", "posture", "compliance", "access",
            // Step 5: the core domains, bottom-up — each only once what it uses was a module — then the
            // periodic jobs' port and the shell that composes several domains for one screen.
            "targets", "scanning", "issues", "maintenance", "platform");

    /**
     * The top-level packages that are no module's. Only {@code config} since step 5: the datasource,
     * the per-engine setup and the migration placeholders serve every module and decide nothing any
     * domain owns. {@code api}, {@code services}, {@code repositories} and {@code persistence} were
     * emptied, and a class put back into one of them fails {@link #everyClassHasAPlace}.
     */
    private static final Set<String> OUTSIDE_MODULES = Set.of("config");

    private static JavaClasses classes;

    @BeforeAll
    static void importClasses() {
        classes = new ClassFileImporter()
                .withImportOption(ImportOption.Predefined.DO_NOT_INCLUDE_TESTS)
                .importPackages(ROOT);
    }

    /** The packages each module keeps for one layer, {@code suffixes} under its root. */
    private static String[] layer(String... suffixes) {
        return MODULES.stream()
                .flatMap(module -> Stream.of(suffixes).map(suffix -> CORE + "." + module + suffix))
                .toArray(String[]::new);
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
        // And every module listed must hold classes in each of the places the rules below read: a
        // module whose name is misspelt here would otherwise be a module no rule applies to.
        for (String module : MODULES) {
            org.assertj.core.api.Assertions
                    .assertThat(classes.stream().anyMatch(c -> c.getPackageName().equals(CORE + "." + module)))
                    .as("module %s has no class at its root: its name in MODULES or its package is wrong", module)
                    .isTrue();
        }
    }

    @Test
    @DisplayName("no layer reaches a layer above it")
    void layersOnlyReachDownwards() {
        layeredArchitecture()
                .consideringOnlyDependenciesInAnyPackage(ROOT + "..")
                .layer("domain").definedBy(ROOT + ".common.domain..")
                .layer("scanning").definedBy(ROOT + ".common.scanning..")
                // A module keeps its entities and its repositories together in `persistence`; they
                // form one layer here, below its services, and `entitiesReachNoRepository` keeps the
                // order between the two that `core.persistence` and `core.repositories` showed until
                // step 5 emptied them.
                .layer("persistence").definedBy(layer(".persistence.."))
                // A module's root is its API and `internal` its implementation: both are the service
                // layer, which the layered packaging calls `services`.
                .layer("services").definedBy(layer("", ".internal.."))
                .layer("api").definedBy(layer(".web.."))

                // Read downwards: who is allowed to see me.
                .whereLayer("api").mayNotBeAccessedByAnyLayer()
                .whereLayer("services").mayOnlyBeAccessedByLayers("api")
                // Not `api`: a controller maps HTTP, a service reads, decides and writes. Thirty-three
                // controllers reached repositories directly when a line here still allowed it; they
                // were moved behind services on 2026-09-24, under a ratchet that shrank to nothing,
                // and since 2026-09-26 no controller names an entity either — see
                // apiNeverTouchesPersistence below.
                .whereLayer("persistence").mayOnlyBeAccessedByLayers("services")
                .whereLayer("scanning").mayOnlyBeAccessedByLayers("services", "api")
                // No optional layers and no empty-should escape any more: every layer is
                // populated, so an empty one is now a package that was renamed or deleted — and
                // this rule going quiet is exactly how that would go unnoticed.
                .check(classes);
    }

    @Test
    @DisplayName("every package of the control plane is a module's, or config")
    void everyClassHasAPlace() {
        // The layer rule constrains the packages it names and nothing else: a class dropped into
        // `core.audit.helpers`, into a new top-level `core.reports`, or back into `core.services`,
        // would belong to no layer and be checked by nothing. So the places are closed: a module's
        // four, or `core.config`.
        ArchCondition<JavaClass> haveAPlace = new ArchCondition<>("sit in a module's root, web, internal or "
                + "persistence package, or in core.config") {
            @Override
            public void check(JavaClass type, ConditionEvents events) {
                String rest = type.getPackageName().substring(CORE.length() + 1);
                String top = rest.contains(".") ? rest.substring(0, rest.indexOf('.')) : rest;
                if (OUTSIDE_MODULES.contains(top)) {
                    return;
                }
                if (MODULES.contains(top)) {
                    String below = rest.substring(top.length());
                    if (below.isEmpty() || Stream.of(".web", ".internal", ".persistence")
                            .anyMatch(place -> below.equals(place) || below.startsWith(place + "."))) {
                        return;
                    }
                }
                events.add(SimpleConditionEvent.violated(type, type.getName() + " is in no module place and not "
                        + "in config: " + type.getPackageName()));
            }
        };
        ArchRuleDefinition.classes()
                .that().resideInAPackage(CORE + "..")
                .and().resideOutsideOfPackage(CORE)
                .should(haveAPlace)
                .check(classes);
    }

    /*
     * Between modules, Spring Modulith is the authority since step 6 (decision 0030): `ModularityTest`
     * runs `ApplicationModules.verify()`, which fails the build on a cycle between modules (what
     * `domainsFormNoCycle` and its `KNOWN_CYCLES` checked), on a reach into another module's internals —
     * anything but its root package or a named interface (`modulesMeetAtTheirApi`) — and on a dependency
     * the origin's `package-info` does not list in `@ApplicationModule(allowedDependencies = …)` (the
     * `MAY_USE` table and `domainsDependOnlyWhereAllowed`). The table's reasons moved with its lines, into
     * each module's `package-info`. What Modulith cannot say about a module is below: it reads a module
     * whole, so the layers inside one are this file's, and so is the one line of the table that was about
     * a layer rather than a module.
     */

    /**
     * The modules whose service layer never used {@code access}, although their routes do — every route
     * needs the principal and its marker, and a route naming a target resolves a {@code Visibility}. The
     * table said so with a clause, "any module's {@code web} may use {@code access}", which a module's
     * list of allowed dependencies cannot: it is one list for the whole module. So a module whose routes
     * call {@code VisibilityService} lists {@code access}, and this set keeps its services, its
     * implementation and its entities off it. {@code gate} is here on purpose: its register was purged
     * through a port {@code access} declared until step 5, and that coupling is what this line keeps
     * gone.
     */
    private static final Set<String> ACCESS_FOR_ROUTES_ONLY =
            Set.of("siem", "rules", "inventory", "threatintel", "gate", "exports");

    @Test
    @DisplayName("a module that uses access for its routes uses it nowhere else")
    void accessForRoutesOnly() {
        // `access` uses nothing above the foundation, so no line of this set could close a cycle; what it
        // keeps is the direction the domains were given. A service deciding on who the caller is, or what
        // they may see, is a service of a module that lists `access` for it, in the review that needs it.
        for (String module : ACCESS_FOR_ROUTES_ONLY) {
            ArchRuleDefinition.noClasses()
                    .that().resideInAnyPackage(CORE + "." + module, CORE + "." + module + ".internal..",
                            CORE + "." + module + ".persistence..")
                    .should().dependOnClassesThat().resideInAPackage(CORE + ".access..")
                    .because(module + "'s services do not use access; only its routes do")
                    .check(classes);
        }
    }

    @Test
    @DisplayName("a module's controllers call its API, not its internals")
    void controllersCallTheirModuleApi() {
        // `internal` is what the API is built from. A controller reaching into it makes the class it
        // reaches part of the module's surface without saying so; if a route needs it, it belongs at
        // the root. Persistence is `apiNeverTouchesPersistence`'s.
        for (String module : MODULES) {
            ArchRuleDefinition.noClasses()
                    .that().resideInAPackage(CORE + "." + module + ".web..")
                    .should().dependOnClassesThat().resideInAPackage(CORE + "." + module + ".internal..")
                    .allowEmptyShould(true)
                    .check(classes);
        }
    }

    @Test
    @DisplayName("an entity reaches no repository")
    void entitiesReachNoRepository() {
        // The order `core.persistence` → `core.repositories` gave for free, kept inside a module's
        // single `persistence` package: an entity describes a table, a repository reads it.
        ArchRuleDefinition.noClasses()
                .that().areAnnotatedWith("jakarta.persistence.Entity")
                .or().areAnnotatedWith("jakarta.persistence.Embeddable")
                .should().dependOnClassesThat().areAssignableTo("org.springframework.data.repository.Repository")
                .check(classes);
    }

    @Test
    @DisplayName("nothing of the persistence layer reaches the api layer, not even for one call")
    void apiNeverTouchesPersistence() {
        // `SchemaNameCollisionTest` keeps entities out of responses; this keeps them out of `api`
        // altogether. Twenty-five classes of `api` named a persistence type when this was added,
        // the principal among them: it carried the account's password hash and TOTP secret to every route, and a
        // controller could hand a row back to a service that saved whatever had been done to it.
        // Services answer with records named `…View` now. No exception list and no freeze: a
        // controller that needs a row needs a service method instead. Every module's `web` is held
        // to it, against every module's `persistence`, its own included — and against the
        // repositories a module keeps beside its entities, and the query records it publishes as a
        // named interface, which the layer rule alone would let a controller name as a type.
        ArchRuleDefinition.noClasses()
                .that().resideInAnyPackage(layer(".web.."))
                .should().dependOnClassesThat().resideInAnyPackage(CORE + ".*.persistence..")
                .check(classes);
    }

    @Test
    @DisplayName("the api layer opens no transaction: a transaction is a decision, and decisions are the services'")
    void apiOpensNoTransaction() {
        // The layering above keeps `api` out of the repositories; this keeps it out of the
        // transaction boundary, which is the other half of "a controller maps HTTP". Three
        // controllers held a `TransactionTemplate` or `@Transactional` before the move.
        ArchRuleDefinition.noClasses()
                .that().resideInAnyPackage(layer(".web.."))
                .should().dependOnClassesThat()
                .haveFullyQualifiedName("org.springframework.transaction.support.TransactionTemplate")
                .orShould().dependOnClassesThat()
                .haveFullyQualifiedName("org.springframework.transaction.annotation.Transactional")
                .check(classes);
    }

    /** Where the filter chain lives: {@code access} took it with it from {@code core.api.security} (decision 0028). */
    private static final String SECURITY_WEB = CORE + ".access.web.security..";

    @Test
    @DisplayName("no controller writes the audit log: the service that performs an action records it")
    void controllersWriteNoAuditEntry() {
        // An entry written by the route is an entry the next caller of the same service does not
        // write — a second route, a scheduled job — and whether it is written before or after the
        // commit becomes each controller's own guess. Ten controllers still held `AuditLogService`
        // when this was added. The security web layer is left out on purpose: the filter chain
        // audits what happens before any controller runs — a refused bearer token, a denied route, a
        // single-sign-on callback — events that belong to no service method the entry could move to.
        // Named by class literal, not by string: the class moved package once, and a string naming
        // where it used to be would have left this rule checking nothing.
        ArchRuleDefinition.noClasses()
                .that().resideInAnyPackage(layer(".web.."))
                .and().resideOutsideOfPackage(SECURITY_WEB)
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
        // A module's repositories sit in its `persistence` package, which is therefore the one place
        // of a module left out; its root, `internal` and `web` are held to the rule, as `core.services`
        // and `core.api` were before step 5 emptied them.
        ArchRuleDefinition.noClasses()
                .that().resideInAnyPackage(Stream.concat(
                                Stream.of(layer("", ".internal..")),
                                Stream.of(layer(".web..")))
                        .toArray(String[]::new))
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
                .that().resideInAnyPackage(layer(".persistence.."))
                .should().dependOnClassesThat()
                .resideInAnyPackage("org.springframework.web..", "jakarta.servlet..")
                .check(classes);
    }

    @Test
    @DisplayName("every repository write carries @Transactional")
    void everyRepositoryWriteIsTransactional() {
        // Written in `core.repositories`' package-info for as long as the package existed, and true
        // of every module's repositories since; step 5 emptied the package, and the convention came
        // here rather than into a document. Spring Data makes its derived and inherited methods
        // transactional but not a custom modifying query, so one written without the annotation
        // fails outright when no caller has opened a transaction — and works when one has, which is
        // how the omission survives review and reaches production as an intermittent failure. The
        // derived `deleteBy…` methods are held to it too: they have no annotation to prompt the
        // question, and fail at runtime with "No EntityManager with actual transaction available"
        // rather than at startup.
        DescribedPredicate<com.tngtech.archunit.core.domain.JavaMethod> writes = DescribedPredicate.describe(
                "write rows",
                method -> method.isAnnotatedWith("org.springframework.data.jpa.repository.Modifying")
                        || method.getName().matches("(delete|remove)(All)?By.+"));
        ArchRuleDefinition.methods()
                .that().areDeclaredInClassesThat().areAssignableTo("org.springframework.data.repository.Repository")
                .and(writes)
                .should().beAnnotatedWith("org.springframework.transaction.annotation.Transactional")
                .orShould().beDeclaredInClassesThat()
                .areAnnotatedWith("org.springframework.transaction.annotation.Transactional")
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
