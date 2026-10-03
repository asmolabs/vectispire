package com.asmolabs.vectispire.core.checklists;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.checklists.NoDataReason;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistMeasurementEntity;
import jakarta.persistence.Column;
import java.util.Arrays;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Every reason fits the column the measurement keeps it in.
 *
 * <p>A reason is added in the domain, which knows nothing of the column, and stored by a service that
 * bounds nothing it did not receive from a caller. One past forty characters would pass on a fixture
 * that enforces no length and fail the measurement's write on MySQL and PostgreSQL — the first time a
 * line had that reason, in production. {@code plugin_registry_authentication_required} is thirty-nine.
 */
@DisplayName("the reasons a measurement has no data")
class NoDataReasonColumnTest {

    @Test
    @DisplayName("each fits the reason column")
    void fitsTheColumn() throws NoSuchFieldException {
        int length = ChecklistMeasurementEntity.class.getDeclaredField("reason").getAnnotation(Column.class).length();

        assertThat(Arrays.stream(NoDataReason.values()).map(NoDataReason::wireName))
                .allSatisfy(reason -> assertThat(reason.length()).as(reason).isLessThanOrEqualTo(length));
    }
}
