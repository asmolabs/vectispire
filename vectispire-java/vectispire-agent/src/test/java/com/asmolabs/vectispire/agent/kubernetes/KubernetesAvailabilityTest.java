package com.asmolabs.vectispire.agent.kubernetes;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.scanning.ScannerLimits;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Whether the Kubernetes executor can run anything, decided without a cluster: what each answer of the API server
 * makes of it. The real Role is the {@code kubernetes} job's ({@code ExecutorChoiceClusterTest}).
 */
@DisplayName("the Kubernetes executor's availability")
class KubernetesAvailabilityTest {

    private final KubernetesApi api = mock(KubernetesApi.class);
    private final KubernetesExecutor executor = new KubernetesExecutor(api, new KubernetesExecutor.Settings(
            "scans", "agent", KubernetesExecutor.HELPER_IMAGE, "1000:1000", Duration.ofMinutes(1),
            ScannerLimits.DEFAULT, new ObjectMapper().createObjectNode()));

    @Test
    @DisplayName("listing and a dry run both allowed: available, and it scans repositories only")
    void available() {
        when(api.pods(eq("scans"), anyString())).thenReturn(List.of());

        assertThat(executor.whyUnavailable()).isEmpty();
        assertThat(executor.isAvailable()).isTrue();
        assertThat(executor.exportsImages()).isFalse();
    }

    @Test
    @DisplayName("an API server that does not list the namespace: unavailable, with its answer")
    void cannotList() {
        when(api.pods(eq("scans"), anyString())).thenThrow(new KubernetesException("GET answered HTTP 401: Unauthorized", 401));

        assertThat(executor.whyUnavailable()).hasValueSatisfying(why -> assertThat(why).contains("did not list pods in scans").contains("401"));
    }

    @Test
    @DisplayName("a Role without create: unavailable, though the listing worked")
    void cannotCreate() {
        when(api.pods(eq("scans"), anyString())).thenReturn(List.of());
        doThrow(new KubernetesException("pods is forbidden: User \"system:serviceaccount:agents:agent\" cannot create "
                + "resource \"pods\" in API group \"\" in the namespace \"scans\"", 403))
                .when(api).createPodDryRun(eq("scans"), any());

        assertThat(executor.whyUnavailable()).hasValueSatisfying(why -> assertThat(why).contains("cannot create resource"));
    }

    @Test
    @DisplayName("a dry run that admission turns away is still a create the Role allowed: available")
    void admissionIsNotTheRole() {
        when(api.pods(eq("scans"), anyString())).thenReturn(List.of());
        doThrow(new KubernetesException("pods \"vs-availability-probe\" is forbidden: violates PodSecurity \"restricted:latest\"", 403))
                .when(api).createPodDryRun(eq("scans"), any());
        assertThat(executor.whyUnavailable()).isEmpty();

        doThrow(new KubernetesException("admission webhook \"policy\" denied the request", 400))
                .when(api).createPodDryRun(eq("scans"), any());
        assertThat(executor.whyUnavailable()).isEmpty();
    }

    @Test
    @DisplayName("a dry run that never reached the API server: unavailable")
    void unreachable() {
        when(api.pods(eq("scans"), anyString())).thenReturn(List.of());
        doThrow(new KubernetesException("The API server is unreachable: connect timed out", new java.io.IOException("timeout")))
                .when(api).createPodDryRun(eq("scans"), any());

        assertThat(executor.whyUnavailable()).hasValueSatisfying(why -> assertThat(why).contains("unreachable"));
    }
}
