package com.asmolabs.vectispire.core.checklists;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.access.VisibilityService;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistMeasurementEntity;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("the repositories a revision's stored measurements carry, and who reads them")
class CarriedRepositoriesTest {

    @Test
    @DisplayName("every repository any stored row names, across the rows")
    void everyRepositoryNamed() {
        assertThat(CarriedRepositories.of(List.of(row(1, 2), row(2, 3), row()))).contains(Set.of(1L, 2L, 3L));
        assertThat(CarriedRepositories.of(List.of())).contains(Set.of());
    }

    @Test
    @DisplayName("a reader must see every one of them, not one of them")
    void everyNotAny() {
        Optional<Set<Long>> carried = Optional.of(Set.of(1L, 2L));
        assertThat(CarriedRepositories.seenBy(carried, only(1L))).isFalse();
        assertThat(CarriedRepositories.seenBy(carried, only(1L, 2L))).isTrue();
        assertThat(CarriedRepositories.seenBy(carried, everything(false))).isTrue();
        assertThat(CarriedRepositories.seenBy(Optional.of(Set.of()), only())).as("nothing carried, nothing asked")
                .isTrue();
    }

    @Test
    @DisplayName("evidence that does not read back is never fewer repositories: only who sees everything reads it")
    void unreadableIsNotEmpty() {
        ChecklistMeasurementEntity broken = new ChecklistMeasurementEntity();
        broken.setEvidence("{not json");
        Optional<Set<Long>> carried = CarriedRepositories.of(List.of(row(1), broken));

        assertThat(carried).isEmpty();
        assertThat(CarriedRepositories.seenBy(carried, only(1L, 2L, 3L))).isFalse();
        assertThat(CarriedRepositories.seenBy(carried, everything(true))).as("a narrowing credential").isFalse();
        assertThat(CarriedRepositories.seenBy(carried, everything(false))).isTrue();
    }

    private static ChecklistMeasurementEntity row(long... repositories) {
        StringBuilder json = new StringBuilder("{\"outcome\":\"pass\",\"repositories\":[");
        for (int i = 0; i < repositories.length; i++) {
            json.append(i == 0 ? "" : ",").append("{\"repositoryId\":").append(repositories[i])
                    .append(",\"status\":\"examined\"}");
        }
        ChecklistMeasurementEntity row = new ChecklistMeasurementEntity();
        row.setEvidence(json.append("],\"figures\":[],\"summary\":\"\"}").toString());
        return row;
    }

    private static VisibilityService.Allowance only(long... repositories) {
        Set<ScanTarget> targets = new java.util.HashSet<>();
        for (long id : repositories) {
            targets.add(new ScanTarget.Repository(id));
        }
        return new VisibilityService.Allowance(new Visibility.Only(targets), Set.of(), false);
    }

    private static VisibilityService.Allowance everything(boolean narrowed) {
        return new VisibilityService.Allowance(new Visibility.Everything(), Set.of(), narrowed);
    }
}
