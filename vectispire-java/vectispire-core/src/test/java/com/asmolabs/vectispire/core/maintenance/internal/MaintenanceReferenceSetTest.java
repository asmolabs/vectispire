package com.asmolabs.vectispire.core.maintenance.internal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import com.asmolabs.vectispire.core.RustReference;
import com.asmolabs.vectispire.core.maintenance.MaintenanceTask;
import com.asmolabs.vectispire.core.maintenance.MaintenanceTask.Cadence;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.core.annotation.Order;
import org.springframework.scheduling.annotation.Scheduled;

/**
 * The periodic tick's composition and its turns — the Rust control plane's {@code cp-maintenance} is held to it
 * ({@code vectispire-rust/reference/maintenance/composition.json}).
 *
 * <p><b>The Rust turns keep one ordered list across every module</b>, as Spring's {@code @Order} does here, and a
 * Rust module registers its task into a slot of that list. So the list itself is the contract: every slot of {@link
 * MaintenanceTask.Sequence} with its value, every task of {@link MaintenanceJobsTest#COMPOSITION} — the composition
 * {@code MaintenanceCompositionTest} holds the running application to — with its module, its slot and its cadence,
 * and each turn's interval and initial delay as {@link MaintenanceJobs}'s {@code @Scheduled} carries them.
 *
 * <p><b>Read, never restated.</b> A task's cadence is what its own {@code cadence()} answers, on an instance built
 * over mocks; its slot is its {@code @Order}; which turn a scheduled method runs is found by running it over one
 * recording task per cadence. A copy of any of these here would be checked against itself.
 */
class MaintenanceReferenceSetTest {

    @Test
    void theCompositionAndItsTurns() throws Exception {
        ObjectNode out = RustReference.object();

        // The slots, in their order: the reserved ones of modules not yet ported included.
        Map<Integer, String> slots = new LinkedHashMap<>();
        List<Field> fields = new ArrayList<>(Arrays.stream(MaintenanceTask.Sequence.class.getDeclaredFields())
                .filter(field -> Modifier.isStatic(field.getModifiers()) && field.getType() == int.class)
                .toList());
        fields.sort(Comparator.comparingInt(MaintenanceReferenceSetTest::value));
        ArrayNode sequence = out.putArray("sequence");
        for (Field field : fields) {
            int value = value(field);
            assertThat(slots.put(value, field.getName())).as("two slots share %d", value).isNull();
            ObjectNode row = sequence.addObject();
            row.put("slot", field.getName());
            row.put("order", value);
        }

        ArrayNode cadences = out.putArray("cadences");
        for (Cadence cadence : Cadence.values()) {
            ObjectNode row = cadences.addObject();
            row.put("cadence", cadence.name());
            row.put("label", cadence.label());
            Method method = scheduledMethodOf(cadence);
            Scheduled scheduled = method.getAnnotation(Scheduled.class);
            row.put("method", method.getName());
            row.put("fixedDelay", scheduled.fixedDelayString());
            row.put("initialDelay", scheduled.initialDelayString());
        }

        ArrayNode tasks = out.putArray("tasks");
        int previous = Integer.MIN_VALUE;
        for (Class<? extends MaintenanceTask> type : MaintenanceJobsTest.COMPOSITION) {
            Order order = type.getAnnotation(Order.class);
            assertThat(order).as("%s carries its @Order", type.getSimpleName()).isNotNull();
            assertThat(order.value()).as("COMPOSITION is in the order Spring injects it").isGreaterThan(previous);
            previous = order.value();
            String slot = slots.get(order.value());
            assertThat(slot).as("%s's @Order is a Sequence slot", type.getSimpleName()).isNotNull();
            ObjectNode row = tasks.addObject();
            row.put("task", type.getSimpleName());
            row.put("module", moduleOf(type));
            row.put("slot", slot);
            row.put("order", order.value());
            row.put("cadence", instantiate(type).cadence().name());
        }
        RustReference.expect("maintenance/composition.json", out, MaintenanceReferenceSetTest.class);
    }

    private static int value(Field field) {
        try {
            return field.getInt(null);
        } catch (IllegalAccessException unreadable) {
            throw new IllegalStateException(unreadable);
        }
    }

    /** {@code core.<module>.internal.SomeTask} → {@code <module>}. */
    private static String moduleOf(Class<?> type) {
        String[] parts = type.getPackageName().split("\\.");
        int core = Arrays.asList(parts).indexOf("core");
        return parts[core + 1];
    }

    /** The task over mocks of what its constructor takes: {@code cadence()} touches none of them. */
    private static MaintenanceTask instantiate(Class<? extends MaintenanceTask> type) throws Exception {
        Constructor<?>[] constructors = type.getDeclaredConstructors();
        assertThat(constructors).as("%s has one constructor", type.getSimpleName()).hasSize(1);
        Constructor<?> constructor = constructors[0];
        constructor.setAccessible(true);
        Object[] arguments = Arrays.stream(constructor.getParameterTypes()).map(parameter -> (Object) mock(parameter))
                .toArray();
        return (MaintenanceTask) constructor.newInstance(arguments);
    }

    /** The {@code @Scheduled} method of {@link MaintenanceJobs} that runs {@code cadence}'s turn, found by running each. */
    private static Method scheduledMethodOf(Cadence cadence) throws Exception {
        List<Method> found = new ArrayList<>();
        for (Method method : MaintenanceJobs.class.getDeclaredMethods()) {
            if (!method.isAnnotationPresent(Scheduled.class)) {
                continue;
            }
            List<Cadence> ran = new ArrayList<>();
            List<MaintenanceTask> recorders = Arrays.stream(Cadence.values())
                    .<MaintenanceTask>map(each -> new MaintenanceTask() {
                        @Override
                        public Cadence cadence() {
                            return each;
                        }

                        @Override
                        public void run() {
                            ran.add(each);
                        }
                    })
                    .toList();
            method.invoke(new MaintenanceJobs(recorders));
            if (ran.equals(List.of(cadence))) {
                found.add(method);
            }
        }
        assertThat(found).as("exactly one scheduled method runs the %s turn", cadence).hasSize(1);
        return found.get(0);
    }
}
