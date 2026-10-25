package com.asmolabs.vectispire.agent.kubernetes;

import com.asmolabs.vectispire.common.scanning.ContainerRun;
import com.asmolabs.vectispire.common.scanning.ContainerRunner;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;

/**
 * The pod one {@link ContainerRun} becomes (decision 0045), and what its status says went wrong.
 *
 * <p><b>Three containers.</b> {@code receive}, an init container, installs a static busybox for the
 * wrapper and waits for the workspace, so the scanner never starts on a half-copied tree. {@code scanner}
 * is the request, in the closed shape. {@code holder} outlives it so its output can be read over
 * {@code exec}: an ordinary container, since a native sidecar is stopped with the pod — the spike's
 * correction.
 *
 * <p><b>Standard output goes to a file, never to the log.</b> The kubelet rotates logs, and a report cut
 * by a rotation and read leniently is the absent-versus-empty defect (0007). So the scanner runs through
 * the busybox shell, {@code exec "$@" >stdout 2>stderr}, which needs the program named — the
 * {@linkplain ContainerRun#entrypoint() declared entrypoint}. A run that declares none keeps its image's
 * entrypoint, and its output goes to the log, read as a diagnostic and nothing more.
 */
final class ScanPods {

    static final String RECEIVE = "receive";
    static final String SCANNER = "scanner";
    static final String HOLDER = "holder";

    /** The workspace, each mount a subdirectory {@code m<i>} of it. */
    static final String WORK = "/work";
    /** Written by the agent once every mount is copied in: the scanner starts after it. */
    static final String RECEIVED = WORK + "/.received";
    /** The wrapper's busybox and the scanner's two streams. */
    static final String TOOLS = "/vectispire";
    static final String BUSYBOX = TOOLS + "/busybox";
    static final String STDOUT = TOOLS + "/out/stdout";
    static final String STDERR = TOOLS + "/out/stderr";

    static final String LABEL_AGENT = "vectispire.dev/agent";
    static final String LABEL_NETWORK = "vectispire.dev/network";
    static final String LABEL_SCANNER = "vectispire.dev/scanner";
    /** The value a NetworkPolicy denies all traffic to; {@code egress} is the one allowed out (0045 §5). */
    static final String OFFLINE = "none";
    static final String ONLINE = "egress";

    /** Waiting reasons that will not resolve themselves: the run fails now rather than at its timeout. */
    private static final Set<String> CANNOT_START = Set.of("ErrImagePull", "ImagePullBackOff", "InvalidImageName",
            "ErrImageNeverPull", "CreateContainerConfigError", "CreateContainerError", "RunContainerError");

    /** How long the pod outlives what the agent waits for, if the agent dies with it: a backstop, not a timeout. */
    private static final Duration BACKSTOP = Duration.ofMinutes(10);

    private static final ObjectMapper JSON = new ObjectMapper();

    private ScanPods() {}

    /**
     * @param uid the numeric user the three containers run as — the workspace's owner, never root
     * @param mountNames the name each mount's content has under its subdirectory: empty for a directory,
     *     the file's name for a file
     */
    static ObjectNode pod(String name, ContainerRun request, KubernetesExecutor.Settings settings, long uid, long gid,
            List<String> mountNames, Duration timeout) {

        ObjectNode pod = JSON.createObjectNode();
        pod.put("apiVersion", "v1");
        pod.put("kind", "Pod");
        ObjectNode metadata = pod.putObject("metadata");
        metadata.put("name", name);
        ObjectNode labels = metadata.putObject("labels");
        labels.put("app.kubernetes.io/managed-by", "vectispire-agent");
        labels.put(LABEL_AGENT, settings.agent());
        labels.put(LABEL_NETWORK, request.network() ? ONLINE : OFFLINE);
        labels.put(LABEL_SCANNER, labelValue(request.label()));

        ObjectNode spec = pod.putObject("spec");
        spec.put("restartPolicy", "Never");
        // The scan pod reaches nothing of the API: the agent's token stays in the agent's pod.
        spec.put("automountServiceAccountToken", false);
        spec.put("enableServiceLinks", false);
        spec.put("activeDeadlineSeconds", settings.startTimeout().plus(timeout).plus(BACKSTOP).toSeconds());
        spec.put("terminationGracePeriodSeconds", 0);
        ObjectNode podSecurity = spec.putObject("securityContext");
        podSecurity.put("runAsNonRoot", true);
        podSecurity.put("runAsUser", uid);
        podSecurity.put("runAsGroup", gid);
        podSecurity.putObject("seccompProfile").put("type", "RuntimeDefault");
        settings.placement().properties().forEach(field -> spec.set(field.getKey(), field.getValue().deepCopy()));

        ArrayNode volumes = spec.putArray("volumes");
        volumes.addObject().put("name", "work").putObject("emptyDir");
        volumes.addObject().put("name", "tools").putObject("emptyDir")
                // The busybox, the standard output up to its ceiling and the error stream: past it the pod is
                // evicted, a failure, never a truncation.
                .put("sizeLimit", String.valueOf(settings.limits().outputBytes() + ContainerRunner.STDERR_BYTES + 64L * 1024 * 1024));
        memory(volumes, "tmp", ContainerRunner.SCRATCH_MEGABYTES + "Mi");
        memory(volumes, "home", ContainerRunner.SCRATCH_MEGABYTES + "Mi");
        if (request.output() != null) {
            // Memory-backed with a size: the kernel answers ENOSPC past it (measured, 0045's spike).
            memory(volumes, "output", String.valueOf(request.output().bytes()));
        }

        ArrayNode init = spec.putArray("initContainers");
        ObjectNode receive = container(init, RECEIVE, settings.helperImage(), uid, gid, 64);
        command(receive, "sh", "-c", "mkdir -p " + TOOLS + "/out && cp /bin/busybox " + BUSYBOX
                + " && until [ -f " + RECEIVED + " ]; do sleep 0.2; done");
        mount(receive, "work", WORK, false, null);
        mount(receive, "tools", TOOLS, false, null);

        ArrayNode containers = spec.putArray("containers");
        ObjectNode scanner = containers.addObject();
        scanner.put("name", SCANNER);
        scanner.put("image", request.image());
        scanner.put("imagePullPolicy", "IfNotPresent");
        if (request.entrypoint() != null) {
            List<String> wrapped = new ArrayList<>(List.of(BUSYBOX, "sh", "-c",
                    "exec \"$@\" >" + STDOUT + " 2>" + STDERR, "scanner"));
            wrapped.addAll(request.entrypoint());
            wrapped.addAll(request.command());
            command(scanner, wrapped.toArray(String[]::new));
        } else {
            ArrayNode args = scanner.putArray("args");
            request.command().forEach(args::add);
        }
        ArrayNode env = scanner.putArray("env");
        for (String variable : ContainerRunner.SCANNER_ENVIRONMENT) {
            int equals = variable.indexOf('=');
            env.addObject().put("name", variable.substring(0, equals)).put("value", variable.substring(equals + 1));
        }
        ObjectNode resources = scanner.putObject("resources");
        String memory = String.valueOf(settings.limits().memory());
        String cpu = Math.max(1, settings.limits().nanoCpus() / 1_000_000) + "m";
        // Requests equal to limits: what the scanner is promised is what it may take.
        resources.putObject("limits").put("memory", memory).put("cpu", cpu);
        resources.putObject("requests").put("memory", memory).put("cpu", cpu);
        scanner.set("securityContext", closedShape(uid, gid));
        for (int i = 0; i < request.mounts().size(); i++) {
            ContainerRun.Mount mount = request.mounts().get(i);
            String subPath = "m" + i + (mountNames.get(i).isEmpty() ? "" : "/" + mountNames.get(i));
            mount(scanner, "work", mount.target(), mount.readOnly(), subPath);
        }
        mount(scanner, "tools", TOOLS, false, null);
        mount(scanner, "tmp", "/tmp", false, null);
        mount(scanner, "home", ContainerRunner.SCRATCH_HOME, false, null);
        if (request.output() != null) {
            mount(scanner, "output", request.output().target(), false, null);
        }

        ObjectNode holder = container(containers, HOLDER, settings.helperImage(), uid, gid, 32);
        command(holder, "sleep", String.valueOf(settings.startTimeout().plus(timeout).plus(BACKSTOP).toSeconds()));
        mount(holder, "work", WORK, true, null);
        mount(holder, "tools", TOOLS, true, null);
        if (request.output() != null) {
            mount(holder, "output", request.output().target(), true, null);
        }
        return pod;
    }

    /**
     * What makes the pod's run hopeless, while it is still going: an image that cannot be pulled, a
     * container that cannot be created, a pod failed or evicted. Empty while it may still succeed.
     */
    static Optional<String> failure(JsonNode pod) {
        JsonNode status = pod.path("status");
        if ("Failed".equals(status.path("phase").asText())) {
            return Optional.of("the pod failed (" + status.path("reason").asText("no reason") + "): "
                    + status.path("message").asText("no message"));
        }
        for (String kind : List.of("initContainerStatuses", "containerStatuses")) {
            for (JsonNode container : status.path(kind)) {
                JsonNode waiting = container.path("state").path("waiting");
                String reason = waiting.path("reason").asText("");
                if (CANNOT_START.contains(reason)) {
                    return Optional.of("its " + container.path("name").asText() + " container could not start ("
                            + reason + "): " + waiting.path("message").asText("no message"));
                }
                JsonNode terminated = container.path("state").path("terminated");
                if (kind.equals("initContainerStatuses") && !terminated.isMissingNode()
                        && terminated.path("exitCode").asInt(0) != 0) {
                    return Optional.of("its " + container.path("name").asText() + " container exited "
                            + terminated.path("exitCode").asInt() + ": " + terminated.path("reason").asText(""));
                }
            }
        }
        return Optional.empty();
    }

    /** Why the pod is not scheduled yet, for a timeout's message: the scheduler's own words. */
    static String pending(JsonNode pod) {
        for (JsonNode condition : pod.path("status").path("conditions")) {
            if ("PodScheduled".equals(condition.path("type").asText()) && "False".equals(condition.path("status").asText())) {
                return "not scheduled: " + condition.path("message").asText(condition.path("reason").asText());
            }
        }
        return "phase " + pod.path("status").path("phase").asText("unknown");
    }

    /** Is the receiving init container running, ready for the workspace? */
    static boolean receiving(JsonNode pod) {
        for (JsonNode container : pod.path("status").path("initContainerStatuses")) {
            if (RECEIVE.equals(container.path("name").asText()) && container.path("state").has("running")) {
                return true;
            }
        }
        return false;
    }

    /** The scanner's end, once it has ended: its exit code and the reason the runtime gives. */
    static Optional<JsonNode> scannerTerminated(JsonNode pod) {
        for (JsonNode container : pod.path("status").path("containerStatuses")) {
            if (SCANNER.equals(container.path("name").asText()) && container.path("state").has("terminated")) {
                return Optional.of(container.path("state").path("terminated"));
            }
        }
        return Optional.empty();
    }

    /** A label value: 63 characters of {@code [a-z0-9-._]}, starting and ending with an alphanumeric. */
    static String labelValue(String text) {
        String value = text.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9._-]+", "-").replaceAll("^[^a-z0-9]+", "");
        value = value.substring(0, Math.min(value.length(), 63)).replaceAll("[^a-z0-9]+$", "");
        return value.isEmpty() ? "scan" : value;
    }

    private static ObjectNode container(ArrayNode into, String name, String image, long uid, long gid, int memoryMiB) {
        ObjectNode container = into.addObject();
        container.put("name", name);
        container.put("image", image);
        container.put("imagePullPolicy", "IfNotPresent");
        ObjectNode resources = container.putObject("resources");
        resources.putObject("limits").put("memory", memoryMiB + "Mi").put("cpu", "100m");
        resources.putObject("requests").put("memory", memoryMiB + "Mi").put("cpu", "100m");
        container.set("securityContext", closedShape(uid, gid));
        return container;
    }

    /** The closed shape's properties that Kubernetes expresses per container (0045 §2). */
    private static ObjectNode closedShape(long uid, long gid) {
        ObjectNode security = JSON.createObjectNode();
        security.put("runAsNonRoot", true);
        security.put("runAsUser", uid);
        security.put("runAsGroup", gid);
        security.put("allowPrivilegeEscalation", false);
        security.put("readOnlyRootFilesystem", true);
        security.put("privileged", false);
        security.putObject("capabilities").putArray("drop").add("ALL");
        security.putObject("seccompProfile").put("type", "RuntimeDefault");
        return security;
    }

    private static void command(ObjectNode container, String... command) {
        ArrayNode array = container.putArray("command");
        for (String part : command) {
            array.add(part);
        }
    }

    private static void mount(ObjectNode container, String volume, String path, boolean readOnly, String subPath) {
        ArrayNode mounts = container.has("volumeMounts") ? (ArrayNode) container.get("volumeMounts")
                : container.putArray("volumeMounts");
        ObjectNode mount = mounts.addObject().put("name", volume).put("mountPath", path).put("readOnly", readOnly);
        if (subPath != null) {
            mount.put("subPath", subPath);
        }
    }

    private static void memory(ArrayNode volumes, String name, String size) {
        volumes.addObject().put("name", name).putObject("emptyDir").put("medium", "Memory").put("sizeLimit", size);
    }
}
