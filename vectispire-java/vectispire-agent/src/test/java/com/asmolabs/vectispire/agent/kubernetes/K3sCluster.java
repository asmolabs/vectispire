package com.asmolabs.vectispire.agent.kubernetes;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import org.testcontainers.containers.Container;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.utility.DockerImageName;

/**
 * A real cluster for the executor's tests: k3s in a container, with a scan namespace set up as decision
 * 0045 requires it — Pod Security {@code restricted} enforced — and a service account holding exactly
 * the Role the chart will render, so a call the executor makes outside it fails here first.
 *
 * <p>Privileged, as k3s needs: these tests run under the {@code kubernetesTest} task, never in
 * {@code test}, and fail without Docker rather than skip.
 */
public final class K3sCluster implements AutoCloseable {

    public static final String NAMESPACE = "vectispire-scans";
    public static final String BUSYBOX = "busybox@sha256:bdf57e528e45e4433820e045b29b4597825a1c9e38353532d90a01445013f82e";

    /** A version upstream still supports, as 0045 requires of the target. */
    private static final DockerImageName K3S = DockerImageName.parse(
            "rancher/k3s:v1.34.1-k3s1@sha256:5e0707cfd1239b358ef73f3254bc3eadc027dd30cd5ec6ca41e29e47652a1b8c")
            .asCompatibleSubstituteFor("rancher/k3s");

    /**
     * The chart's Role, its rules read from the template the chart renders — so these tests run under the very
     * rules an installation gets, and a verb the chart drops fails here (decision 0045 §3).
     */
    private static final java.nio.file.Path CHART_ROLE =
            java.nio.file.Path.of("../../deploy/helm/vectispire/templates/agents/scans-role.yaml");

    static String chartRules() {
        try {
            String template = Files.readString(CHART_ROLE);
            String role = template.substring(template.indexOf("kind: Role\n"));
            String rules = role.substring(role.indexOf("\nrules:\n") + 1, role.indexOf("\n---"));
            if (rules.contains("{{") || !rules.contains("pods/exec")) {
                throw new IllegalStateException("The chart's Role rules are not the static block expected: " + rules);
            }
            return rules;
        } catch (IOException unreadable) {
            throw new IllegalStateException("The chart's Role could not be read from " + CHART_ROLE.toAbsolutePath(), unreadable);
        }
    }

    private static final String ROLE = """
            apiVersion: rbac.authorization.k8s.io/v1
            kind: Role
            metadata: {name: vectispire-agent, namespace: %1$s}
            %2$s
            ---
            apiVersion: rbac.authorization.k8s.io/v1
            kind: RoleBinding
            metadata: {name: vectispire-agent, namespace: %1$s}
            subjects: [{kind: ServiceAccount, name: vectispire-agent, namespace: %1$s}]
            roleRef: {apiGroup: rbac.authorization.k8s.io, kind: Role, name: vectispire-agent}
            """;

    private final GenericContainer<?> k3s;
    private final KubernetesApi api;

    @SuppressWarnings("resource")
    public K3sCluster() {
        k3s = new GenericContainer<>(K3S)
                .withPrivilegedMode(true)
                .withCommand("server", "--disable=traefik,metrics-server,servicelb", "--tls-san=localhost")
                .withExposedPorts(6443);
        k3s.start();
        try {
            await("the API server", "kubectl", "get", "--raw", "/readyz");
            await("a ready node", "kubectl", "wait", "--for=condition=Ready", "node", "--all", "--timeout=5s");
            await("the default service account", "kubectl", "get", "serviceaccount", "default", "-n", "default");
            kubectl("create", "namespace", NAMESPACE);
            kubectl("label", "namespace", NAMESPACE, "pod-security.kubernetes.io/enforce=restricted",
                    "pod-security.kubernetes.io/enforce-version=latest");
            kubectl("create", "serviceaccount", "vectispire-agent", "-n", NAMESPACE);
            apply(ROLE.formatted(NAMESPACE, chartRules().stripTrailing()));
            String token = kubectl("create", "token", "vectispire-agent", "-n", NAMESPACE, "--duration=2h").strip();

            Path ca = Files.createTempFile("k3s-ca", ".crt");
            k3s.copyFileFromContainer("/var/lib/rancher/k3s/server/tls/server-ca.crt", ca.toString());
            api = new KubernetesApi(URI.create("https://localhost:" + k3s.getMappedPort(6443)), () -> token,
                    KubernetesApi.trusting(ca), new ObjectMapper());
        } catch (IOException | RuntimeException failed) {
            k3s.stop();
            throw new IllegalStateException("The k3s cluster could not be prepared: " + failed.getMessage(), failed);
        }
    }

    /** The API as the agent's service account sees it — not as the cluster's administrator. */
    public KubernetesApi api() {
        return api;
    }

    /** As the administrator, for what the test arranges and the agent may not do. */
    public String kubectl(String... arguments) {
        try {
            String[] command = new String[arguments.length + 1];
            command[0] = "kubectl";
            System.arraycopy(arguments, 0, command, 1, arguments.length);
            Container.ExecResult result = k3s.execInContainer(command);
            if (result.getExitCode() != 0) {
                throw new IllegalStateException("kubectl " + String.join(" ", arguments) + ": " + result.getStderr());
            }
            return result.getStdout();
        } catch (IOException failed) {
            throw new IllegalStateException(failed);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(interrupted);
        }
    }

    public void apply(String manifest) {
        try {
            Container.ExecResult result = k3s.execInContainer("sh", "-c", "cat <<'EOF' | kubectl apply -f -\n" + manifest + "\nEOF");
            if (result.getExitCode() != 0) {
                throw new IllegalStateException("kubectl apply: " + result.getStderr());
            }
        } catch (IOException failed) {
            throw new IllegalStateException(failed);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(interrupted);
        }
    }

    private void await(String what, String... command) {
        long deadline = System.nanoTime() + Duration.ofMinutes(3).toNanos();
        while (true) {
            try {
                if (k3s.execInContainer(command).getExitCode() == 0) {
                    return;
                }
                if (System.nanoTime() > deadline) {
                    throw new IllegalStateException("k3s never had " + what + ".");
                }
                Thread.sleep(1000);
            } catch (IOException failed) {
                throw new IllegalStateException(failed);
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException(interrupted);
            }
        }
    }

    @Override
    public void close() {
        k3s.stop();
    }
}
