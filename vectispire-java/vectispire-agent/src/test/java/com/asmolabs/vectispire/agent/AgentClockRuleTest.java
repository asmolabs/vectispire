package com.asmolabs.vectispire.agent;

import static org.assertj.core.api.Assertions.assertThat;

import com.tngtech.archunit.base.DescribedPredicate;
import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.lang.syntax.ArchRuleDefinition;
import java.time.Clock;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The control plane's {@code ArchitectureTest.timeIsReadFromAClock}, applied to the agent.
 *
 * <p>Here and not there for the reason {@link AgentIsolationTest} gives: the agent's classes are not
 * on the control plane's test classpath, so the rule over there never read them, and
 * {@code AgentProtocol} kept a {@code System.currentTimeMillis()} beside the runner's injected
 * clock — two sources for the sealing key's generation. The agent's clock is
 * {@code VectispireAgentApplication.clock}, the one reader of the system clock through
 * {@code Clock.systemUTC()}, which this rule does not name. {@code System.nanoTime()} measures a
 * duration, not a moment, and is not refused.
 */
@DisplayName("agent clock")
class AgentClockRuleTest {

    @Test
    @DisplayName("every moment the agent reads comes from the injected clock")
    void timeIsReadFromAClock() {
        JavaClasses classes = new ClassFileImporter()
                .withImportOption(ImportOption.Predefined.DO_NOT_INCLUDE_TESTS)
                .importPackages("com.asmolabs.vectispire.agent");

        assertThat(classes)
                .as("an empty import would make the rule below pass without checking anything")
                .isNotEmpty();

        ArchRuleDefinition.noClasses()
                .should().callMethodWhere(DescribedPredicate.describe(
                        "now() on a java.time type without a Clock, or System.currentTimeMillis()",
                        call -> (call.getName().equals("now")
                                        && call.getTargetOwner().getPackageName().equals("java.time")
                                        && call.getTarget().getRawParameterTypes().stream()
                                                .noneMatch(type -> type.isEquivalentTo(Clock.class)))
                                || (call.getName().equals("currentTimeMillis")
                                        && call.getTargetOwner().isEquivalentTo(System.class))))
                .check(classes);
    }
}
