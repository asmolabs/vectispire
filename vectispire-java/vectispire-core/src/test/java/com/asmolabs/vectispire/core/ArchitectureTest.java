package com.asmolabs.vectispire.core;

import static com.tngtech.archunit.library.Architectures.layeredArchitecture;

import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.lang.syntax.ArchRuleDefinition;
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
                .whereLayer("repositories").mayOnlyBeAccessedByLayers("services", "api")
                .whereLayer("persistence").mayOnlyBeAccessedByLayers("repositories", "services", "api")
                .whereLayer("scanning").mayOnlyBeAccessedByLayers("services", "api")
                // No optional layers and no empty-should escape any more: every layer is
                // populated, so an empty one is now a package that was renamed or deleted — and
                // this rule going quiet is exactly how that would go unnoticed.
                .check(classes);
    }

    /**
     * Controllers that still reach a repository or open a transaction themselves — and may only leave.
     *
     * <p><b>The rule: a controller maps HTTP, a service decides and reads.</b> No repository, no
     * transaction, no business rule in {@code api}. The layering above allowed {@code api} to
     * reach {@code repositories} directly, and thirty-three controllers did: that is how
     * {@code AgentsAdminController} came to hold five repositories and a transaction template with
     * no service at all, and why a lookup written once in a controller was written again in the
     * next one, each with its own idea of visibility.
     *
     * <p><b>A ratchet, because thirty-three are not moved in one commit.</b> A controller not
     * listed here fails the moment it takes a repository or a transaction; one listed here fails
     * the moment it no longer does, so the entry is removed in the same commit and the list only
     * shrinks. When it is empty, this list goes and the layering above loses {@code api} from
     * the repositories' allowed callers.
     */
    private static final java.util.Set<String> CONTROLLERS_STILL_REACHING_DATA = java.util.Set.of(
            "AgentsAdminController",
            "AgentsController",
            "AiAdvisorController",
            "ApiKeysController",
            "AttestationController",
            "AuditLogController",
            "AuthController",
            "ContainersController",
            "CsafController",
            "CycloneDxController",
            "DashboardController",
            "ExceptionsRegisterController",
            "ExportsController",
            "GateController",
            "HistoryController",
            "InventoryController",
            "IssuesController",
            "OwaspController",
            "QualityController",
            "RepositoriesController",
            "RuleSetsController",
            "SbomDiffController",
            "ScansController",
            "ScimGroupsController",
            "ScimUsersController",
            "ScorecardController",
            "SettingsController",
            "SshKeysController",
            "TeamsController",
            "TicketingController",
            "TicketingWebhookController",
            "UsersController",
            "VexController");

    @Test
    @DisplayName("a controller reaches data only through a service — and the list of those that do not only shrinks")
    void controllersGoThroughServices() {
        java.util.Set<String> reaching = classes.stream()
                .filter(c -> c.getPackageName().startsWith(ROOT + ".core.api"))
                // Controllers, and the classes nested in them — the security filters and
                // interceptors beside them are infrastructure, not routes.
                .filter(c -> controllerOf(c).isPresent())
                .filter(c -> c.getDirectDependenciesFromSelf().stream().anyMatch(d ->
                        d.getTargetClass().getPackageName().startsWith(ROOT + ".core.repositories")
                                || d.getTargetClass().getName().equals("org.springframework.transaction.support.TransactionTemplate")
                                || d.getTargetClass().getName().equals("org.springframework.transaction.annotation.Transactional")))
                .map(c -> c.getName().substring(c.getName().lastIndexOf('.') + 1).replaceAll("\\$.*", ""))
                .collect(java.util.stream.Collectors.toCollection(java.util.TreeSet::new));

        org.assertj.core.api.Assertions.assertThat(reaching)
                .as("these controllers reach a repository or a transaction directly. Put the lookup, "
                        + "the rule and the write in a service method, and keep the controller to HTTP")
                .isSubsetOf(CONTROLLERS_STILL_REACHING_DATA);
        org.assertj.core.api.Assertions.assertThat(CONTROLLERS_STILL_REACHING_DATA)
                .as("these controllers no longer reach data directly: remove them from the list, "
                        + "so the ratchet cannot give the room back")
                .isSubsetOf(reaching);
    }

    private static java.util.Optional<com.tngtech.archunit.core.domain.JavaClass> controllerOf(
            com.tngtech.archunit.core.domain.JavaClass type) {
        com.tngtech.archunit.core.domain.JavaClass outer = type;
        while (outer.getEnclosingClass().isPresent()) {
            outer = outer.getEnclosingClass().get();
        }
        boolean controller = outer.isAnnotatedWith("org.springframework.web.bind.annotation.RestController")
                || outer.isAnnotatedWith("org.springframework.stereotype.Controller");
        return controller ? java.util.Optional.of(outer) : java.util.Optional.empty();
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
    @DisplayName("an entity describes a table and nothing else")
    void persistenceHasNoWebOrService() {
        // Dependency injection is not an entity's business, and neither is HTTP.
        ArchRuleDefinition.noClasses()
                .that().resideInAPackage(ROOT + ".core.persistence..")
                .should().dependOnClassesThat()
                .resideInAnyPackage("org.springframework.web..", "jakarta.servlet..")
                .check(classes);
    }

}
