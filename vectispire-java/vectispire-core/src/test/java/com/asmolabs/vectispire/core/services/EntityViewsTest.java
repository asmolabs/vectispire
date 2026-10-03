package com.asmolabs.vectispire.core.services;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.core.audit.AuditEntryView;
import com.asmolabs.vectispire.core.audit.persistence.AuditLogEntity;
import com.asmolabs.vectispire.core.inventory.ApiContractView;
import com.asmolabs.vectispire.core.inventory.persistence.ApiContractEntity;
import com.asmolabs.vectispire.core.issues.IssueView;
import com.asmolabs.vectispire.core.issues.persistence.IssueEntity;
import com.asmolabs.vectispire.core.targets.SolutionAdministrationService;
import com.asmolabs.vectispire.core.targets.persistence.ProjectEntity;
import com.asmolabs.vectispire.core.targets.persistence.SolutionEntity;
import com.asmolabs.vectispire.core.tickets.IssueTicketView;
import com.asmolabs.vectispire.core.tickets.persistence.IssueTicketEntity;
import com.fasterxml.jackson.annotation.JsonIgnore;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.lang.reflect.RecordComponent;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * No JPA entity crosses a route; a record restating its fields does, and a restatement drifts.
 * This fails when an entity gains a getter its view does not carry, so publishing a new column —
 * or deciding not to — is a change somebody makes on purpose.
 */
@DisplayName("views returned by the API")
class EntityViewsTest {

    static java.util.stream.Stream<Arguments> pairs() {
        return java.util.stream.Stream.of(
                Arguments.of(IssueEntity.class, IssueView.class, Set.of()),
                Arguments.of(IssueTicketEntity.class, IssueTicketView.class, Set.of()),
                Arguments.of(AuditLogEntity.class, AuditEntryView.class, Set.of()),
                Arguments.of(ApiContractEntity.class, ApiContractView.class, Set.of()),
                Arguments.of(SolutionEntity.class, SolutionAdministrationService.SolutionView.class, Set.of()),
                Arguments.of(ProjectEntity.class, SolutionAdministrationService.ProjectView.class, Set.of()),
                Arguments.of(com.asmolabs.vectispire.core.plugins.persistence.PluginActivationEntity.class,
                        com.asmolabs.vectispire.core.plugins.PluginActivationView.class,
                        Set.of("projectName", "solutionId", "solutionName")),
                Arguments.of(com.asmolabs.vectispire.core.reportplugins.persistence.ReportPluginActivationEntity.class,
                        com.asmolabs.vectispire.core.reportplugins.ReportPluginActivationView.class, Set.of("pluginName")),
                Arguments.of(com.asmolabs.vectispire.core.reportplugins.persistence.ReportRunEntity.class,
                        com.asmolabs.vectispire.core.reportplugins.ReportRunView.class,
                        Set.of("withdrawnAt", "withdrawnBy", "withdrawalJustification")),
                Arguments.of(com.asmolabs.vectispire.core.forges.persistence.ForgeDiscoveryEntity.class,
                        com.asmolabs.vectispire.core.forges.ForgeDiscoveryView.class, Set.of()),
                Arguments.of(com.asmolabs.vectispire.core.forges.persistence.ForgeRepositoryEntity.class,
                        com.asmolabs.vectispire.core.forges.ForgeRepositoryView.class, Set.of()),
                Arguments.of(com.asmolabs.vectispire.core.plugins.persistence.SarifSourceEntity.class,
                        com.asmolabs.vectispire.core.plugins.SarifSourceView.class, Set.of("apiKeyName")),
                Arguments.of(com.asmolabs.vectispire.core.plugins.persistence.SarifImportEntity.class,
                        com.asmolabs.vectispire.core.plugins.SarifImportView.class, Set.of()),
                Arguments.of(com.asmolabs.vectispire.core.plugins.persistence.CoverageImportEntity.class,
                        com.asmolabs.vectispire.core.plugins.CoverageImportView.class, Set.of()),
                Arguments.of(com.asmolabs.vectispire.core.plugins.persistence.CoveragePackageEntity.class,
                        com.asmolabs.vectispire.core.plugins.CoveragePackageView.class, Set.of()),
                Arguments.of(com.asmolabs.vectispire.core.plugins.persistence.TestReportImportEntity.class,
                        com.asmolabs.vectispire.core.plugins.TestReportImportView.class, Set.of()),
                Arguments.of(com.asmolabs.vectispire.core.inventory.persistence.BuildSbomEntity.class,
                        com.asmolabs.vectispire.core.inventory.BuildSbomView.class, Set.of("completedScanId")),
                Arguments.of(com.asmolabs.vectispire.core.plugins.persistence.TestSuiteResultEntity.class,
                        com.asmolabs.vectispire.core.plugins.TestSuiteResultView.class, Set.of()),
                Arguments.of(com.asmolabs.vectispire.core.checklists.persistence.ChecklistItemEntity.class,
                        com.asmolabs.vectispire.core.checklists.ChecklistItemView.class, Set.of()),
                Arguments.of(com.asmolabs.vectispire.core.checklists.persistence.ChecklistMeasurementEntity.class,
                        com.asmolabs.vectispire.core.checklists.ChecklistMeasurementView.class, Set.of()));
    }

    /**
     * @param derived the components a view adds that no column holds — a name looked up in another
     *     module — listed here so that adding one is as deliberate as publishing a column
     */
    @ParameterizedTest(name = "{1} carries every property of {0}")
    @MethodSource("pairs")
    void aViewCarriesEveryPublishedProperty(Class<?> entity, Class<? extends Record> view, Set<String> derived) {
        Set<String> published = Arrays.stream(entity.getMethods())
                .filter(method -> method.getDeclaringClass() == entity)
                .filter(method -> method.getParameterCount() == 0 && !Modifier.isStatic(method.getModifiers()))
                .filter(method -> !method.isAnnotationPresent(JsonIgnore.class))
                .map(Method::getName)
                .filter(name -> name.startsWith("get") && name.length() > 3)
                .map(name -> Character.toLowerCase(name.charAt(3)) + name.substring(4))
                .collect(Collectors.toSet());
        Set<String> carried = Arrays.stream(view.getRecordComponents())
                .map(RecordComponent::getName)
                .filter(name -> !derived.contains(name))
                .collect(Collectors.toSet());

        assertThat(carried).containsExactlyInAnyOrderElementsOf(published);
    }
}
