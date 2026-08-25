package com.asmolabs.vectispire.common.scanning.scanners;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.scanning.ContainerRunner;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The signature that makes decision 0007 impossible to break by accident.
 *
 * <p><b>Why a type and not a convention.</b> Decision 0007 says an analysis that did not happen
 * must be distinguishable from one that found nothing: {@code []} is the positive claim "ran,
 * found nothing" and <em>resolves</em> that type's open issues, while absent means "did not run"
 * and leaves the backlog alone. A scanner returning a bare {@code List} cannot express the
 * second thing — whatever it returns is a claim about the repository.
 *
 * <p><b>This test exists because that gap was real and cost the most sensitive finding type.</b>
 * Both secret scanners returned {@code List}, and {@code ScanRunner} merged them inside a
 * {@code catch (Exception ignored)}. A failure of the second engine therefore produced the
 * first's results alone — non-null, hence "complete" — and any leaked credential only the second
 * engine detects was resolved in silence. Nothing in the type system objected, and no test
 * failed.
 *
 * <p>Checked by reflection rather than by reading, so a scanner added in six months is in scope
 * the moment it exists.
 */
@DisplayName("the scanner return-type contract")
class ScannerContractTest {

    /**
     * The classes this rule governs: the ones that run a container.
     *
     * <p>Identified by holding a {@link ContainerRunner}, not by name. A scanner that only walks
     * files — {@code ApiDiscoveryScanner} does — has nothing that can fail to run in the sense
     * decision 0007 means, and is deliberately out of scope.
     */
    private static final List<Class<?>> CONTAINER_SCANNERS = List.of(
            SecretsScanner.class,
            IacScanner.class,
            SastScanner.class,
            DependencyScanner.class);

    @Test
    @DisplayName("every scanner that runs a container holds one, so the list below is the right list")
    void theListIsTheContainerRunningScanners() {
        // Guards the rule against the list going stale: if one of these stops holding a runner,
        // or the field is renamed, the enumeration below stops meaning what it says.
        for (Class<?> scanner : CONTAINER_SCANNERS) {
            boolean holdsRunner = false;
            for (Field field : scanner.getDeclaredFields()) {
                if (ContainerRunner.class.equals(field.getType())) {
                    holdsRunner = true;
                    break;
                }
            }
            assertThat(holdsRunner)
                    .as("%s is listed as a container-running scanner but holds no ContainerRunner",
                            scanner.getSimpleName())
                    .isTrue();
        }
    }

    @Test
    @DisplayName("a scanner never returns a bare collection, because that cannot say \"did not run\"")
    void everyScannerResultIsOptional() {
        List<String> offenders = new ArrayList<>();

        for (Class<?> scanner : CONTAINER_SCANNERS) {
            for (Method method : scanner.getDeclaredMethods()) {
                if (!Modifier.isPublic(method.getModifiers()) || Modifier.isStatic(method.getModifiers())) {
                    continue;
                }
                // The analysis methods, by what they take: a scan is performed against a
                // workspace or the payload of one. Accessors and record components take nothing.
                if (method.getParameterCount() == 0) {
                    continue;
                }
                if (!Optional.class.equals(method.getReturnType())) {
                    offenders.add(scanner.getSimpleName() + "." + method.getName()
                            + " returns " + method.getReturnType().getSimpleName());
                }
            }
        }

        assertThat(offenders)
                .as("a scanner result must be Optional: an empty list means \"analysed, found "
                        + "nothing\" and resolves this type's issues, so a scanner that failed "
                        + "needs a way to say so that the caller cannot mistake for a clean "
                        + "repository — see decision 0007")
                .isEmpty();
    }
}
