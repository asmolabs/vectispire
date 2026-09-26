package com.asmolabs.vectispire.core.maintenance.internal;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.core.VectispireContextTest;
import com.asmolabs.vectispire.core.maintenance.MaintenanceTask;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.aop.support.AopUtils;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * The tasks the running application hands the tick — the half of {@link MaintenanceJobsTest} no
 * mock can see.
 *
 * <p>When the tick named its services, forgetting one was visible in the class. Now each module
 * contributes a bean, and a task that lost its {@code @Component}, or a module whose scan stopped
 * finding it, would simply not run — every unit test green, the feature gone, exactly as {@code
 * expireStale} was for as long as nothing called it. Read from the context, in the order Spring
 * injects the list, because that order is the hourly turn's.
 */
@DisplayName("the periodic tick, as the application composes it")
class MaintenanceCompositionTest extends VectispireContextTest {

    @Autowired
    private List<MaintenanceTask> tasks;

    @Test
    @DisplayName("contributes exactly the composition, in its order")
    void theApplicationContributesTheComposition() {
        List<Class<?>> contributed = tasks.stream().<Class<?>>map(AopUtils::getTargetClass).toList();
        assertThat(contributed).containsExactlyElementsOf(MaintenanceJobsTest.COMPOSITION);
    }
}
