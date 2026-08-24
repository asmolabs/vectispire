package com.asmolabs.vectispire.agent;

import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.lang.syntax.ArchRuleDefinition;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The rule the module graph already enforces, stated anyway.
 *
 * <p>{@code vectispire-agent} does not depend on {@code vectispire-core}, so no driver, no
 * Hibernate and no Spring Data is on its compile classpath: reaching the database does not
 * fail review, it fails to compile. This suite exists so that the person who adds the
 * dependency that <em>would</em> allow it breaks a test that explains why, rather than only a
 * compile that says {@code cannot find symbol}.
 *
 * <p>The why: an agent holding a database connection would also need {@code ENCRYPTION_KEY},
 * which is enough to decrypt <em>every</em> deployment key Vectispire holds. The security
 * property that justifies the agent's existence is precisely what it does not have — see
 * decision 0003.
 *
 * <p>It lives in this module rather than beside the other architecture rules because the
 * agent's classes are not on the control plane's classpath. Asserting it from there would
 * assert nothing at all.
 */
@DisplayName("agent isolation")
class AgentIsolationTest {

    @Test
    @DisplayName("the agent has no route to the database, which is why it may exist")
    void agentHasNoRouteToTheDatabase() {
        JavaClasses classes = new ClassFileImporter()
                .withImportOption(ImportOption.Predefined.DO_NOT_INCLUDE_TESTS)
                .importPackages("com.asmolabs.vectispire.agent");

        org.assertj.core.api.Assertions
                .assertThat(classes)
                .as("an empty import would make the rule below pass without checking anything")
                .isNotEmpty();

        ArchRuleDefinition.noClasses()
                .should().dependOnClassesThat()
                .resideInAnyPackage(
                        "com.asmolabs.vectispire.core..",
                        "java.sql..",
                        "javax.sql..",
                        "org.hibernate..",
                        "jakarta.persistence..",
                        "org.springframework.data..",
                        "org.flywaydb..",
                        "liquibase..")
                .check(classes);
    }
}
