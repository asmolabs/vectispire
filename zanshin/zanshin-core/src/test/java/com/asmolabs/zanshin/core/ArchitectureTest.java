package com.asmolabs.zanshin.core;

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
 * <p>The module split already carries the part that matters most: {@code zanshin-agent} does
 * not depend on {@code zanshin-core}, so a driver is not on its classpath and the violation
 * fails to compile rather than failing review. What one module cannot express is the rule
 * <em>inside</em> {@code zanshin-core}, and that is what this file is for.
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

    private static final String ROOT = "com.asmolabs.zanshin";

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
                // The port is in progress: layers that have not been ported yet are
                // legitimately empty. `findsSomethingToCheck` is what stops that from
                // becoming a suite which passes because it looks at nothing.
                .withOptionalLayers(true)
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
                .allowEmptyShould(true)
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
                        "liquibase..",
                        // The scanning half of `zanshin-common` needs a Docker client; the
                        // domain half must never. A calculation that reached the daemon would
                        // stop being testable without one, which is the property the whole
                        // layer exists for.
                        "com.github.dockerjava..")
                .allowEmptyShould(true)
                .check(classes);
    }

    @Test
    @DisplayName("only the repositories speak SQL")
    void onlyRepositoriesReachTheDatabase() {
        ArchRuleDefinition.noClasses()
                .that().resideInAnyPackage(ROOT + ".core.services..", ROOT + ".core.api..")
                .should().dependOnClassesThat()
                .resideInAnyPackage("java.sql..", "javax.sql..", "org.hibernate..")
                .allowEmptyShould(true)
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
                .allowEmptyShould(true)
                .check(classes);
    }

}
