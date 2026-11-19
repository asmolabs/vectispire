package com.asmolabs.vectispire.agent.kubernetes;

import com.asmolabs.vectispire.agent.RustReference;
import com.asmolabs.vectispire.common.scanning.ContainerRun;
import com.asmolabs.vectispire.common.scanning.ContainerRunner;
import com.asmolabs.vectispire.common.scanning.ScannerLimits;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;
import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveOutputStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * What the Kubernetes executor's pure parts answer for fixed inputs — the files the Rust agent's port of it
 * ({@code vectispire-rust/crates/kubernetes}) is held to, in {@code vectispire-rust/reference/kubernetes/}.
 *
 * <p><b>The parts that decide what reaches the cluster, and what comes back from it.</b> The pod a run becomes
 * (its security context, its limits, its volumes and their sizes, the wrapper, the placement and the cache's node),
 * the probes' pods and scripts, the API server's address as the agent accepts or refuses it, the exec stream's
 * framing and its ceiling, a pod's status read as a failure, and the archive the holder sends back read as files or
 * refused. Each file carries its inputs beside the answers, so the Rust test reads both from one place.
 *
 * <p>Two implementations agree only where something compares them: a pod spec drifting on one side is a scan pod
 * with another security context, which no test of a single side would see.
 */
class KubernetesReferenceSetTest {

    private static final ObjectMapper JSON = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);

    @TempDir
    Path directory;

    // ----------------------------------------------------------------------------------------------- the pods

    @Test
    void thePodsTheRunsBecome() throws Exception {
        ArrayNode cases = JSON.createArrayNode();
        ScannerLimits small = new ScannerLimits(256L * 1024 * 1024, 512, Duration.ofMinutes(2), 500_000_000L, 1024 * 1024);
        ScannerLimits large = new ScannerLimits(2048L * 1024 * 1024, 512, Duration.ofMinutes(15), 2_000_000_000L,
                256L * 1024 * 1024);
        ScannerLimits tiny = new ScannerLimits(48L * 1024 * 1024, 512, Duration.ofMinutes(15), 400_000L, 4096);

        ObjectNode pool = (ObjectNode) JSON.readTree("""
                {"nodeSelector": {"vectispire.dev/agents": "true"},
                 "tolerations": [{"key": "vectispire.dev/scans", "operator": "Exists", "effect": "NoSchedule"}]}
                """);
        ObjectNode affinity = (ObjectNode) JSON.readTree("""
                {"affinity": {"nodeAffinity": {"requiredDuringSchedulingIgnoredDuringExecution": {"nodeSelectorTerms": [
                   {"matchExpressions": [{"key": "pool", "operator": "In", "values": ["scans"]}]},
                   {"matchFields": [{"key": "metadata.name", "operator": "In", "values": ["spare"]}]}]}},
                  "podAntiAffinity": {"preferredDuringSchedulingIgnoredDuringExecution": []}}}
                """);
        ObjectNode emptyTerms = (ObjectNode) JSON.readTree("""
                {"affinity": {"nodeAffinity": {"requiredDuringSchedulingIgnoredDuringExecution": {"nodeSelectorTerms": []}}}}
                """);

        pod(cases, "secrets, a writable workspace", settings("Vectispire Agent_1", "1000:1000", 300, small, null, null),
                run("zricethezav/gitleaks@sha256:" + "c".repeat(64), List.of("detect", "--source", "/scan/source"),
                        List.of(new ContainerRun.Mount("/w/scan", "/scan", false, 0)), "gitleaks", false,
                        List.of("gitleaks")),
                1000, 1000, List.of(new ScanPods.MountSource(false, "")), 12_345, Duration.ofMinutes(15), Duration.ZERO);
        pod(cases, "the matcher, its generation from the cache, on the agent's node",
                settings("agent", "1000:1000", 180, large, affinity, new KubernetesExecutor.MatcherCache("matcher-cache",
                        Path.of("/db/generations"), "node-a")),
                run("anchore/grype@sha256:" + "1".repeat(64), List.of("sbom:/scan/sbom.json", "-o", "json"),
                        List.of(new ContainerRun.Mount("/w/scan", "/scan", true, 0),
                                new ContainerRun.Mount("/db/generations/1761400000000-aaaaaaaa", "/cache", true, 0)),
                        "grype", false, List.of("/grype")),
                1001, 1002, List.of(new ScanPods.MountSource(false, ""), new ScanPods.MountSource(true, "1761400000000-aaaaaaaa")),
                7_000_000, Duration.ofMinutes(15), Duration.ofSeconds(9));
        pod(cases, "the cache with no node named, and a placement with no term",
                settings("agent", "1000:1000", 60, small, emptyTerms, new KubernetesExecutor.MatcherCache("cache",
                        Path.of("/db/generations"), "")),
                run("anchore/grype@sha256:" + "1".repeat(64), List.of("db", "status"),
                        List.of(new ContainerRun.Mount("/db/generations/g1", "/cache", true, 0)), "grype", false,
                        List.of("/grype")),
                1000, 1000, List.of(new ScanPods.MountSource(true, "g1")), 0, Duration.ofMinutes(2), Duration.ZERO);
        pod(cases, "the cache with a node and no placement at all",
                settings("agent", "1000:1000", 60, small, null, new KubernetesExecutor.MatcherCache("cache",
                        Path.of("/db/generations"), "node-b")),
                run("anchore/grype@sha256:" + "1".repeat(64), List.of("db", "status"),
                        List.of(new ContainerRun.Mount("/db/generations/g1", "/cache", true, 0)), "grype", false,
                        List.of("/grype")),
                1000, 1000, List.of(new ScanPods.MountSource(true, "g1")), 0, Duration.ofMinutes(2), Duration.ZERO);
        pod(cases, "a plugin: no entrypoint declared, online, a file mount, its pool",
                settings("agent", "1000:1000", 300, small, pool, null),
                run("registry.example/acme/Scanner:1.0@sha256:" + "e".repeat(64), List.of("--scan", "/in", "--out", "/out"),
                        List.of(new ContainerRun.Mount("/w/rules/config.json", "/in/config.json", true, 0),
                                new ContainerRun.Mount("/w/out", "/out", false, 0)),
                        "Plugin ACME/Scanner — v1.0 (beta)!", true, null),
                4242, 4243, List.of(new ScanPods.MountSource(false, "config.json"), new ScanPods.MountSource(false, "")),
                99, Duration.ofSeconds(90), Duration.ofSeconds(1));
        pod(cases, "semgrep: an empty entrypoint, the registry login's mount",
                settings("agent", "1000:1000", 300, large, null, null),
                run("semgrep/semgrep@sha256:" + "b".repeat(64), List.of("semgrep", "scan", "--json"),
                        List.of(new ContainerRun.Mount("/w/scan", "/scan", true, 0),
                                new ContainerRun.Mount("/w/login", ContainerRunner.REGISTRY_LOGIN_MOUNT, true, 0)),
                        "semgrep", false, List.of()),
                1000, 1000, List.of(new ScanPods.MountSource(false, ""), new ScanPods.MountSource(false, "")),
                1, Duration.ofMinutes(15), Duration.ZERO);
        pod(cases, "the database's download: a declared writable size, online",
                settings("agent", "1000:1000", 300, large, null, null),
                run("anchore/grype@sha256:" + "1".repeat(64), List.of("db", "update"),
                        List.of(new ContainerRun.Mount("/db/staging", "/cache", false, 12L * 1024 * 1024 * 1024)),
                        "grype", true, List.of("/grype")),
                1000, 1000, List.of(new ScanPods.MountSource(false, "")), 0, Duration.ofMinutes(15),
                Duration.ofSeconds(1536));
        pod(cases, "a CPU under one milli, a memory under 64 MiB",
                settings("agent", "1000:1000", 1, tiny, null, null),
                run("busybox@sha256:" + "5".repeat(64), List.of("sh", "-c", "echo $HOME"), List.of(), "", false, List.of()),
                1000, 1000, List.of(), 0, Duration.ofSeconds(1), Duration.ZERO);
        RustReference.expect("kubernetes/pods.json", JSON.writeValueAsString(cases) + "\n");
    }

    private static KubernetesExecutor.Settings settings(String agent, String user, long startSeconds, ScannerLimits limits,
            ObjectNode placement, KubernetesExecutor.MatcherCache cache) {
        return new KubernetesExecutor.Settings("vectispire-scans", agent, KubernetesExecutor.HELPER_IMAGE, user,
                Duration.ofSeconds(startSeconds), limits, placement, cache);
    }

    private static ContainerRun run(String image, List<String> command, List<ContainerRun.Mount> mounts, String label,
            boolean network, List<String> entrypoint) {
        return new ContainerRun(image, command, mounts, label, network, false, null, null, null, null, entrypoint);
    }

    private static void pod(ArrayNode cases, String name, KubernetesExecutor.Settings settings, ContainerRun run, long uid,
            long gid, List<ScanPods.MountSource> sources, long workBytes, Duration timeout, Duration transfers) {
        ObjectNode entry = cases.addObject();
        entry.put("name", name);
        ObjectNode given = entry.putObject("settings");
        given.put("namespace", settings.namespace()).put("agent", settings.agent()).put("helperImage", settings.helperImage())
                .put("defaultUser", settings.defaultUser()).put("startTimeoutSeconds", settings.startTimeout().toSeconds());
        given.putObject("limits").put("memory", settings.limits().memory()).put("nanoCpus", settings.limits().nanoCpus())
                .put("outputBytes", settings.limits().outputBytes()).put("timeoutSeconds", settings.limits().timeout().toSeconds());
        given.set("placement", settings.placement());
        if (settings.cache() == null) {
            given.putNull("cache");
        } else {
            given.putObject("cache").put("claim", settings.cache().claim()).put("node", settings.cache().node());
        }
        ObjectNode request = entry.putObject("request");
        request.put("image", run.image()).put("label", run.label()).put("network", run.network());
        run.command().forEach(request.putArray("command")::add);
        if (run.entrypoint() == null) {
            request.putNull("entrypoint");
        } else {
            run.entrypoint().forEach(request.putArray("entrypoint")::add);
        }
        ArrayNode mounts = request.putArray("mounts");
        run.mounts().forEach(mount -> mounts.addObject().put("source", mount.source()).put("target", mount.target())
                .put("readOnly", mount.readOnly()).put("writableBytes", mount.writableBytes()));
        ArrayNode mountSources = entry.putArray("sources");
        sources.forEach(source -> mountSources.addObject().put("cached", source.cached()).put("name", source.name()));
        entry.put("uid", uid).put("gid", gid).put("workBytes", workBytes).put("timeoutSeconds", timeout.toSeconds())
                .put("transfersSeconds", transfers.toSeconds());
        String podName = KubernetesExecutor.podName(run.label(), new byte[] {1, 2, 3, 4, 5});
        entry.put("podName", podName);
        entry.set("pod", ScanPods.pod(podName, run, settings, uid, gid, sources, workBytes, timeout, transfers));
    }

    // ------------------------------------------------------------------------- names, statuses and probes

    @Test
    void labelsNamesAndScripts() throws Exception {
        ObjectNode file = JSON.createObjectNode();
        ArrayNode labels = file.putArray("labels");
        for (String text : List.of("gitleaks", "syft (SBOM of image registry.example/app:1.0)", "Semgrep", "", "---",
                "-._", "é accented ünïcode", "x".repeat(100), "a".repeat(62) + "._-b", "a.b_c-d", "trailing-._",
                "UPPER lower", "plugin acme/scanner@sha256:" + "f".repeat(64), "İstanbul", "Kelvin",
                "ΣΑΣ", "日本語のスキャナー", "network probe", "  spaced  out  ", "9lives", "_underscore_first",
                "a" + "-".repeat(70) + "b")) {
            labels.addObject().put("text", text).put("value", ScanPods.labelValue(text))
                    .put("podName", KubernetesExecutor.podName(text, new byte[] {0, (byte) 0xff, 0x10, 0x7f, (byte) 0x80}));
        }

        ArrayNode untilRefused = file.putArray("untilRefused");
        for (Object[] target : new Object[][] {{"10.43.0.1", 443, 5}, {"fd00::1", 6443, 2}, {"192.168.1.1", 1, 30}}) {
            untilRefused.addObject().put("host", (String) target[0]).put("port", (int) target[1])
                    .put("connectSeconds", (int) target[2])
                    .put("script", KubernetesExecutor.untilRefused((String) target[0], (int) target[1], (int) target[2]));
        }
        ArrayNode probes = file.putArray("probeCommands");
        for (Object[] target : new Object[][] {{"10.43.0.1", 443}, {"fd00::1", 6443}}) {
            ObjectNode probe = probes.addObject().put("host", (String) target[0]).put("port", (int) target[1]);
            KubernetesExecutor.probeCommand((String) target[0], (int) target[1]).forEach(probe.putArray("command")::add);
        }
        ArrayNode copyBack = file.putArray("copyBack");
        for (String directory : List.of("/work/m0", "/work/m3")) {
            copyBack.addObject().put("directory", directory).put("script", KubernetesExecutor.copyBackScript(directory));
        }
        ArrayNode prune = file.putArray("prune");
        for (Set<String> held : List.<Set<String>>of(Set.of("1761400000000-aaaaaaaa"),
                new LinkedHashSet<>(List.of("b", "a", "1-c")))) {
            ObjectNode entry = prune.addObject();
            held.forEach(entry.putArray("held")::add);
            entry.put("script", KubernetesExecutor.pruneScript(held));
        }
        String root = ScanPods.CACHE + "/" + ScanPods.GENERATIONS;
        file.putObject("seed").put("root", root).put("name", "g1").put("partial", root + "/.g1.partial")
                .put("receive", KubernetesExecutor.seedScript(root, "g1", root + "/.g1.partial"))
                .put("complete", KubernetesExecutor.completeScript(root, "g1", root + "/.g1.partial"));
        ArrayNode transfers = file.putArray("transferSeconds");
        for (long bytes : new long[] {0, 8L * 1024 * 1024 - 1, 8L * 1024 * 1024, 3_000_000_000L, 12L * 1024 * 1024 * 1024}) {
            transfers.addObject().put("bytes", bytes).put("seconds", KubernetesExecutor.transferTime(bytes).toSeconds());
        }

        ArrayNode addresses = file.putArray("targets");
        for (String target : List.of("10.43.0.1:443", "[fd00::1]:443", "fd00::1:443", "host:443", "10.0.0.1", "10.0.0.1:0",
                ":443", "10.0.0.1:65535", "10.0.0.1:65536", "10.0.0.1:+443", "1.2.3.4:٤٤٣", "1.2.3.4:",
                "[]:443", "[10.0.0.1]:80", "1.2.3.4:-1", "ABCD::ef:1", "1.2.3.4:99999999999")) {
            ObjectNode entry = addresses.addObject().put("target", target);
            try {
                Map.Entry<String, Integer> read = KubernetesExecutor.address(target);
                entry.put("host", read.getKey()).put("port", read.getValue());
            } catch (IllegalArgumentException refused) {
                entry.put("refused", refused.getMessage());
            }
        }

        ArrayNode owners = file.putArray("owners");
        for (String user : List.of("1000:1000", "1000", "0:0", "0", "1000:0", "-1:5", "abc", "1000:abc", "1000:1000:1",
                "", "+5:+6", " 1000", "99999999999999999999", "١٠٠٠:5", "5:", ":5")) {
            ObjectNode entry = owners.addObject().put("user", user);
            try {
                long[] owner = KubernetesExecutor.owner(user, "gitleaks");
                entry.put("uid", owner[0]).put("gid", owner[1]);
            } catch (RuntimeException refused) {
                entry.put("refused", refused.getMessage());
            }
        }

        ArrayNode placements = file.putArray("placements");
        for (String placement : List.of("{}", "{\"nodeSelector\": {}}", "{\"hostNetwork\": true}",
                "{\"affinity\": {}, \"tolerations\": [], \"priorityClassName\": \"x\"}")) {
            ObjectNode entry = placements.addObject();
            entry.set("placement", JSON.readTree(placement));
            try {
                new KubernetesExecutor.Settings("ns", "a", KubernetesExecutor.HELPER_IMAGE, "1000:1000", Duration.ofMinutes(1),
                        ScannerLimits.DEFAULT, (ObjectNode) JSON.readTree(placement));
                entry.putNull("refused");
            } catch (IllegalArgumentException refused) {
                entry.put("refused", refused.getMessage());
            }
        }

        ArrayNode probePods = file.putArray("probePods");
        for (ObjectNode placement : List.of(JSON.createObjectNode(), (ObjectNode) JSON.readTree("""
                {"nodeSelector": {"vectispire.dev/agents": "true"}, "tolerations": [{"operator": "Exists"}]}"""))) {
            KubernetesExecutor.Settings settings = new KubernetesExecutor.Settings("ns", "a", KubernetesExecutor.HELPER_IMAGE,
                    "1000:1000", Duration.ofMinutes(1), ScannerLimits.DEFAULT, placement);
            ObjectNode entry = probePods.addObject();
            entry.set("placement", placement);
            entry.set("availability", KubernetesExecutor.availabilityProbe(settings));
            entry.set("podSecurity", KubernetesExecutor.podSecurityProbe(settings));
        }

        ArrayNode refusals = file.putArray("refusals");
        for (Object[] refusal : new Object[][] {
                {403, "pods \"vs-availability-probe\" is forbidden: User \"system:serviceaccount:a:b\" cannot create resource "
                        + "\"pods\" in API group \"\" in the namespace \"ns\""},
                {403, "pods \"vs-pod-security-probe\" is forbidden: violates PodSecurity \"restricted:latest\": privileged"},
                {403, "admission webhook \"x\" denied the request: cannot create resource here"},
                {401, "Unauthorized: cannot create resource"},
                {422, "PodSecurity"},
                {0, "The API server is unreachable: connection refused"},
                {500, "cannot create resource"}}) {
            KubernetesException exception = new KubernetesException((String) refusal[1], (int) refusal[0]);
            refusals.addObject().put("status", (int) refusal[0]).put("message", (String) refusal[1])
                    .put("forbiddenByRole", KubernetesExecutor.forbiddenByRole(exception))
                    .put("podSecurityRefused", KubernetesExecutor.podSecurityRefused(exception));
        }
        RustReference.expect("kubernetes/names.json", JSON.writeValueAsString(file) + "\n");
    }

    @Test
    void whatAPodsStatusSays() throws Exception {
        List<String> documents = List.of(
                "{}",
                "{\"status\": {}}",
                "{\"status\": {\"phase\": \"Pending\", \"initContainerStatuses\": [{\"name\": \"receive\", \"state\": {\"running\": {\"startedAt\": \"x\"}}}]}}",
                "{\"status\": {\"phase\": \"Pending\", \"initContainerStatuses\": [{\"name\": \"receive\", \"state\": {\"waiting\": {\"reason\": \"PodInitializing\"}}}]}}",
                "{\"status\": {\"phase\": \"Pending\", \"initContainerStatuses\": [{\"name\": \"other\", \"state\": {\"running\": {}}}]}}",
                "{\"status\": {\"phase\": \"Pending\", \"containerStatuses\": [{\"name\": \"scanner\", \"state\": {\"waiting\": {\"reason\": \"ErrImagePull\", \"message\": \"rpc error: not found\"}}}]}}",
                "{\"status\": {\"phase\": \"Pending\", \"containerStatuses\": [{\"name\": \"holder\", \"state\": {\"waiting\": {\"reason\": \"ImagePullBackOff\"}}}]}}",
                "{\"status\": {\"phase\": \"Pending\", \"containerStatuses\": [{\"name\": \"scanner\", \"state\": {\"waiting\": {\"reason\": \"ContainerCreating\"}}}]}}",
                "{\"status\": {\"phase\": \"Pending\", \"initContainerStatuses\": [{\"name\": \"receive\", \"state\": {\"waiting\": {\"reason\": \"CreateContainerConfigError\", \"message\": null}}}]}}",
                "{\"status\": {\"phase\": \"Pending\", \"initContainerStatuses\": [{\"name\": \"receive\", \"state\": {\"terminated\": {\"exitCode\": 1, \"reason\": \"Error\"}}}]}}",
                "{\"status\": {\"phase\": \"Pending\", \"initContainerStatuses\": [{\"name\": \"receive\", \"state\": {\"terminated\": {\"exitCode\": 0, \"reason\": \"Completed\"}}}]}}",
                "{\"status\": {\"phase\": \"Pending\", \"initContainerStatuses\": [{\"name\": \"receive\", \"state\": {\"terminated\": {}}}]}}",
                "{\"status\": {\"phase\": \"Running\", \"containerStatuses\": [{\"name\": \"scanner\", \"state\": {\"terminated\": {\"exitCode\": 2, \"reason\": \"Error\"}}}]}}",
                "{\"status\": {\"phase\": \"Failed\", \"reason\": \"Evicted\", \"message\": \"The node was low on resource: memory.\"}}",
                "{\"status\": {\"phase\": \"Failed\"}}",
                "{\"status\": {\"phase\": \"Failed\", \"reason\": \"DeadlineExceeded\", \"message\": \"Pod was active on the node longer than the specified deadline\"}}",
                "{\"status\": {\"phase\": \"Pending\", \"conditions\": [{\"type\": \"PodScheduled\", \"status\": \"False\", \"reason\": \"Unschedulable\", \"message\": \"0/1 nodes are available: 1 Insufficient cpu.\"}]}}",
                "{\"status\": {\"phase\": \"Pending\", \"conditions\": [{\"type\": \"PodScheduled\", \"status\": \"False\", \"reason\": \"Unschedulable\"}]}}",
                "{\"status\": {\"phase\": \"Pending\", \"conditions\": [{\"type\": \"PodScheduled\", \"status\": \"True\"}, {\"type\": \"Ready\", \"status\": \"False\", \"message\": \"x\"}]}}",
                "{\"status\": {\"phase\": \"Running\", \"containerStatuses\": [{\"name\": \"scanner\", \"state\": {\"terminated\": {\"exitCode\": 137, \"reason\": \"OOMKilled\"}}}, {\"name\": \"holder\", \"state\": {\"running\": {}}}]}}",
                "{\"status\": {\"phase\": \"Running\", \"containerStatuses\": [{\"name\": \"scanner\", \"state\": {\"terminated\": {\"exitCode\": 137, \"reason\": \"Error\"}}}]}}",
                "{\"status\": {\"phase\": \"Running\", \"containerStatuses\": [{\"name\": \"scanner\", \"state\": {\"terminated\": {\"exitCode\": 0, \"reason\": \"Completed\"}}}]}}",
                "{\"status\": {\"phase\": \"Running\", \"containerStatuses\": [{\"name\": \"scanner\", \"state\": {\"terminated\": {\"reason\": \"OOMKilled\"}}}]}}",
                "{\"status\": {\"phase\": \"Running\", \"containerStatuses\": [{\"name\": \"scanner\", \"state\": {\"terminated\": {\"exitCode\": \"137\"}}}]}}",
                "{\"status\": {\"phase\": \"Running\", \"containerStatuses\": [{\"name\": \"scanner\", \"state\": {\"terminated\": {\"exitCode\": 137.9}}}]}}",
                "{\"status\": {\"phase\": \"Running\", \"containerStatuses\": [{\"name\": \"holder\", \"state\": {\"terminated\": {\"exitCode\": 137}}}]}}",
                "{\"status\": {\"phase\": \"Running\", \"containerStatuses\": {\"x\": {\"name\": \"scanner\", \"state\": {\"terminated\": {\"exitCode\": 3}}}}}}",
                "{\"status\": {\"phase\": 7, \"reason\": 3, \"message\": true}}",
                "{\"status\": {\"phase\": \"Failed\", \"reason\": {\"a\": 1}, \"message\": [1]}}",
                "{\"status\": {\"phase\": \"Pending\", \"initContainerStatuses\": [{\"name\": \"receive\", \"state\": {\"terminated\": {\"exitCode\": \"x\", \"reason\": 5}}}]}}");
        ArrayNode cases = JSON.createArrayNode();
        for (String text : documents) {
            JsonNode pod = JSON.readTree(text);
            ObjectNode entry = cases.addObject();
            entry.set("pod", pod);
            entry.put("failure", ScanPods.failure(pod).orElse(null));
            entry.put("pending", ScanPods.pending(pod));
            entry.put("receiving", ScanPods.receiving(pod));
            var terminated = ScanPods.scannerTerminated(pod);
            entry.set("scannerTerminated", terminated.orElse(null));
            if (terminated.isPresent()) {
                entry.put("killed", ScanPods.killed(terminated.get()));
                entry.put("exitCode", terminated.get().path("exitCode").asInt());
                entry.put("reason", terminated.get().path("reason").asText());
            }
        }
        RustReference.expect("kubernetes/statuses.json", JSON.writeValueAsString(cases) + "\n");
    }

    // ------------------------------------------------------------------------------ the API server's address

    @Test
    void theApiServersAddressAcceptedOrRefused() throws Exception {
        Map<String, List<String>> dns = new HashMap<>();
        dns.put("kubernetes.default.svc", List.of("10.43.0.1"));
        dns.put("10.43.0.1", List.of("10.43.0.1"));
        dns.put("10.0.0.9", List.of("10.0.0.9"));
        dns.put("api.internal", List.of("10.43.0.1", "10.0.0.9"));
        dns.put("only-service.internal", List.of("10.43.0.1"));
        dns.put("empty.internal", List.of());
        ArrayNode cases = JSON.createArrayNode();
        Object[][] inputs = {
                {"10.43.0.1", "443", dns},
                {"10.43.0.1", "6443", dns},
                {" 10.43.0.1 ", " 443 ", dns},
                {null, "443", dns},
                {"10.43.0.1", null, dns},
                {"", "443", dns},
                {"10.43.0.1", "  ", dns},
                {"10.43.0.1", "abc", dns},
                {"10.43.0.1", "0", dns},
                {"10.43.0.1", "65536", dns},
                {"10.43.0.1", "+443", dns},
                {"10.43.0.1", "٤٤٣", dns},
                {"10.43.0.1", "-1", dns},
                {"10.0.0.9", "443", dns},
                {"api.internal", "443", dns},
                {"only-service.internal", "443", dns},
                {"kubernetes.default.svc", "443", dns},
                {"unknown.internal", "443", dns},
                {"empty.internal", "443", dns},
                {"10.43.0.1", "443", Map.of("10.43.0.1", List.of("10.43.0.1"))},
                {"10.43.0.1", "443", Map.of("kubernetes.default.svc", List.of(), "10.43.0.1", List.of("10.43.0.1"))},
                {"fd00::1", "443", Map.of("kubernetes.default.svc", List.of("fd00::1"), "fd00::1", List.of("fd00::1"))},
                {"fd00::1", "443", Map.of("kubernetes.default.svc", List.of("fd00:0:0:0:0:0:0:2"), "fd00::1", List.of("fd00::1"))},
                {"[fd00::1]", "443", Map.of("kubernetes.default.svc", List.of("fd00::1"), "[fd00::1]", List.of("fd00::1"))},
                {"10.43.0.1", "443", Map.of("kubernetes.default.svc", List.of("10.43.0.1", "fd00::1"), "10.43.0.1",
                        List.of("10.43.0.1"))},
        };
        for (Object[] input : inputs) {
            @SuppressWarnings("unchecked")
            Map<String, List<String>> table = (Map<String, List<String>>) input[2];
            ObjectNode entry = cases.addObject();
            entry.put("host", (String) input[0]).put("port", (String) input[1]);
            ObjectNode resolved = entry.putObject("dns");
            table.entrySet().stream().sorted(Map.Entry.comparingByKey())
                    .forEach(name -> {
                        ArrayNode found = resolved.putArray(name.getKey());
                        name.getValue().forEach(found::add);
                    });
            Map<String, String> environment = new HashMap<>();
            environment.put("KUBERNETES_SERVICE_HOST", (String) input[0]);
            environment.put("KUBERNETES_SERVICE_PORT", (String) input[1]);
            try {
                entry.put("uri", ClusterApiAddress.of(environment::get, host -> {
                    List<String> found = table.get(host);
                    if (found == null) {
                        throw new UnknownHostException(host);
                    }
                    List<InetAddress> addresses = new ArrayList<>();
                    for (String literal : found) {
                        addresses.add(InetAddress.getByName(literal));
                    }
                    return addresses.toArray(InetAddress[]::new);
                }).toString());
            } catch (IllegalStateException refused) {
                entry.put("refused", refused.getMessage());
            }
        }
        RustReference.expect("kubernetes/addresses.json", JSON.writeValueAsString(cases) + "\n");
    }

    // ----------------------------------------------------------------------------------- the exec channels

    @Test
    void theExecStreamSortedByChannel() throws Exception {
        ArrayNode cases = JSON.createArrayNode();
        String success = "{\"metadata\":{},\"status\":\"Success\"}";
        String exited3 = "{\"metadata\":{},\"status\":\"Failure\",\"message\":\"command terminated with non-zero exit code: "
                + "error executing command [sh -c exit 3], exit code 3\",\"reason\":\"NonZeroExitCode\",\"details\":"
                + "{\"causes\":[{\"reason\":\"ExitCode\",\"message\":\"3\"}]}}";
        channels(cases, "stdout, stderr, success", 1024, false,
                frame(1, "hello", true), frame(2, "warn", true), frame(3, success, true));
        channels(cases, "a message in fragments: only the first carries its channel", 1024, false,
                frame(1, "ab", false), raw("cd", false), raw("ef", true), frame(3, success, true));
        channels(cases, "an empty first fragment: the channel is the next one's first byte", 1024, false,
                raw("", false), frame(1, "xy", true), frame(3, success, true));
        channels(cases, "a status in fragments", 1024, false, frame(1, "out", true),
                frame(3, exited3.substring(0, 40), false), raw(exited3.substring(40), true));
        channels(cases, "exactly the ceiling", 4, false, frame(1, "abcd", true), frame(3, success, true));
        channels(cases, "one byte past the ceiling", 4, false, frame(1, "abcde", true), frame(3, success, true));
        channels(cases, "far past the ceiling, in two messages", 4, false, frame(1, "abc", true), frame(1, "defghij", true));
        channels(cases, "a ceiling of zero", 0, false, frame(1, "", true), frame(3, success, true));
        channels(cases, "a ceiling of zero, passed", 0, false, frame(1, "x", true));
        channels(cases, "to a sink: standard output is not kept", 1024, true, frame(1, "streamed", true), frame(3, success, true));
        channels(cases, "a sink past its ceiling", 3, true, frame(1, "streamed", true));
        channels(cases, "a channel nobody asked for", 1024, false, frame(7, "noise", true), frame(0, "in", true),
                frame(1, "kept", true), frame(3, success, true));
        channels(cases, "standard error past its bound", 1024, false, frame(2, "e".repeat(70_000), true),
                frame(2, "more", true), frame(3, success, true));
        channels(cases, "no status", 1024, false, frame(1, "out", true));
        channels(cases, "a status that is not JSON", 1024, false, frame(3, "{not json", true));
        channels(cases, "a status that is JSON but not an object", 1024, false, frame(3, "[1,2]", true));
        channels(cases, "exit 3", 1024, false, frame(3, exited3, true));
        channels(cases, "exit code written with a sign", 1024, false, frame(3, exited3.replace("\"message\":\"3\"", "\"message\":\"+3\""), true));
        channels(cases, "exit code with a space", 1024, false, frame(3, exited3.replace("\"message\":\"3\"", "\"message\":\" 3\""), true));
        channels(cases, "exit code as a number", 1024, false, frame(3, exited3.replace("\"message\":\"3\"", "\"message\":3"), true));
        channels(cases, "exit code in Arabic-Indic digits", 1024, false,
                frame(3, exited3.replace("\"message\":\"3\"", "\"message\":\"٣\""), true));
        channels(cases, "a second exit cause after one that is not a number", 1024, false, frame(3, exited3.replace(
                "[{\"reason\":\"ExitCode\",\"message\":\"3\"}]",
                "[{\"reason\":\"Other\",\"message\":\"x\"},{\"reason\":\"ExitCode\",\"message\":\"x\"},{\"reason\":\"ExitCode\",\"message\":\"4\"}]"),
                true));
        channels(cases, "non-zero with no cause", 1024, false,
                frame(3, "{\"status\":\"Failure\",\"reason\":\"NonZeroExitCode\",\"message\":\"m\",\"code\":500}", true));
        channels(cases, "the command did not run", 1024, false, frame(3, "{\"kind\":\"Status\",\"status\":\"Failure\","
                + "\"message\":\"container not found (\\\"nope\\\")\",\"reason\":\"InternalError\",\"code\":500}", true));
        channels(cases, "the command did not run, no message, a code as text", 1024, false,
                frame(3, "{\"status\":\"Failure\",\"code\":\"404\"}", true));
        channels(cases, "a status past its bound", 1024, false, frame(3, "{\"status\":\"Success\",\"pad\":\""
                + "p".repeat(70_000) + "\"}", true));
        channels(cases, "a success status with trailing content", 1024, false, frame(3, success + " ", true));
        RustReference.expect("kubernetes/exec-channels.json", JSON.writeValueAsString(cases) + "\n");
    }

    private record Fragment(byte[] bytes, boolean last) {}

    private static Fragment frame(int channel, String text, boolean last) {
        byte[] body = text.getBytes(StandardCharsets.UTF_8);
        byte[] bytes = new byte[body.length + 1];
        bytes[0] = (byte) channel;
        System.arraycopy(body, 0, bytes, 1, body.length);
        return new Fragment(bytes, last);
    }

    private static Fragment raw(String text, boolean last) {
        return new Fragment(text.getBytes(StandardCharsets.UTF_8), last);
    }

    private static void channels(ArrayNode cases, String name, long ceiling, boolean sink, Fragment... fragments) {
        ObjectNode entry = cases.addObject();
        entry.put("name", name).put("ceiling", ceiling).put("sink", sink);
        ArrayNode given = entry.putArray("fragments");
        ByteArrayOutputStream sunk = new ByteArrayOutputStream();
        // Wrapped, as the copy back's file is not a ByteArrayOutputStream: `stdout()` keeps nothing of a sink.
        ExecChannels channels = sink ? new ExecChannels(new java.io.FilterOutputStream(sunk) {}, ceiling)
                : new ExecChannels(ceiling);
        int accepted = 0;
        for (Fragment fragment : fragments) {
            given.addObject().put("bytes", Base64.getEncoder().encodeToString(fragment.bytes())).put("last", fragment.last());
            accepted++;
            if (!channels.accept(ByteBuffer.wrap(fragment.bytes()), fragment.last())) {
                break;
            }
        }
        // How many fragments were read before the stream was given up: the rest are never asked for.
        entry.put("accepted", accepted);
        entry.put("stdout", Base64.getEncoder().encodeToString(channels.stdout()));
        entry.put("sunk", Base64.getEncoder().encodeToString(sunk.toByteArray()));
        entry.put("stderr", channels.stderr());
        entry.put("overCeiling", channels.overCeiling());
        try {
            channels.exitCode(new ObjectMapper()).ifPresentOrElse(code -> entry.put("exitCode", code),
                    () -> entry.putNull("exitCode"));
        } catch (KubernetesException refused) {
            entry.putObject("refused").put("message", refused.getMessage()).put("status", refused.status());
        }
    }

    // --------------------------------------------------------------------------------- what comes back

    /** One entry of a hostile archive, as a scanner in a pod could have written it. */
    private record Entry(String name, char type, String content, String link) {

        static Entry file(String name, String content) {
            return new Entry(name, '0', content, null);
        }
    }

    @Test
    void whatTheHolderSendsBack_readAsFilesOrRefused() throws Exception {
        ArrayNode cases = JSON.createArrayNode();
        archive(cases, "files and directories, as busybox lists them", 1024, Map.of(),
                new Entry("./", '5', null, null), Entry.file("./report.json", "[]"), new Entry("./deep/", '5', null, null),
                Entry.file("./deep/x.txt", "x"));
        archive(cases, "names without the dot", 1024, Map.of(), Entry.file("report.json", "[]"), Entry.file("a/b/c.txt", "c"));
        archive(cases, "an old-style regular file", 1024, Map.of(), new Entry("old.txt", '\0', "old", null));
        archive(cases, "a long name", 1024, Map.of(), Entry.file("./" + "d".repeat(80) + "/" + "f".repeat(80) + ".json", "long"));
        archive(cases, "an absolute name", 1024, Map.of(), Entry.file("/etc/passwd", "root"));
        archive(cases, "a name climbing out", 1024, Map.of(), Entry.file("../escape", "x"));
        archive(cases, "a name climbing out through a directory", 1024, Map.of(), Entry.file("a/../../x", "x"));
        archive(cases, "a name climbing and coming back", 1024, Map.of(), Entry.file("a/../b.txt", "b"));
        archive(cases, "the mount itself as a file", 1024, Map.of(), Entry.file(".", "x"));
        archive(cases, "a symbolic link", 1024, Map.of(), Entry.file("ok.txt", "ok"), new Entry("link.json", '2', null, "/etc/passwd"));
        archive(cases, "a hard link", 1024, Map.of(), new Entry("hard", '1', null, "ok.txt"));
        archive(cases, "a FIFO", 1024, Map.of(), new Entry("pipe", '6', null, null));
        archive(cases, "a device", 1024, Map.of(), new Entry("dev", '3', null, null));
        archive(cases, "a sparse file", 1024, Map.of(), new Entry("sparse", 'S', "s", null));
        archive(cases, "past the ceiling over two files", 10, Map.of(), Entry.file("one", "123456"), Entry.file("two", "123456"));
        archive(cases, "exactly the ceiling", 12, Map.of(), Entry.file("one", "123456"), Entry.file("two", "123456"));
        archive(cases, "a link in the mount, written through", 1024, Map.of("out", "../elsewhere"), Entry.file("out/x", "x"));
        archive(cases, "a link in the mount, deeper", 1024, Map.of("a/b", "../../elsewhere"), Entry.file("a/b/c/x", "x"));
        archive(cases, "a link in the mount that stays inside it", 1024, Map.of("dir", "real"), Entry.file("dir/f", "f"));
        archive(cases, "a link in the mount, written over", 1024, Map.of("report.json", "../elsewhere/r"),
                Entry.file("report.json", "[]"));
        archive(cases, "a file already there, replaced", 1024, Map.of("kept.txt", ""), Entry.file("kept.txt", "new"));
        archive(cases, "directories only", 1024, Map.of(), new Entry("./a/", '5', null, null), new Entry("./a/b/", '5', null, null));
        archive(cases, "nothing at all", 1024, Map.of());
        archive(cases, "a link before the files, counted against the ceiling as nothing", 2, Map.of(),
                new Entry("l", '2', null, "x"), Entry.file("f", "ab"));
        RustReference.expect("kubernetes/archives.json", JSON.writeValueAsString(cases) + "\n");
    }

    /**
     * @param existing what the mount holds before the archive is read: a name and a link target, or {@code ""} for a
     *     regular file holding "old"
     */
    private void archive(ArrayNode cases, String name, long ceiling, Map<String, String> existing, Entry... entries)
            throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (TarArchiveOutputStream tar = new TarArchiveOutputStream(bytes)) {
            tar.setLongFileMode(TarArchiveOutputStream.LONGFILE_GNU);
            for (Entry entry : entries) {
                // Absolute names kept as written: the default constructor strips the leading slash, and the case
                // would then test nothing.
                TarArchiveEntry written = entry.type() == '0' || entry.type() == '5'
                        ? new TarArchiveEntry(entry.name(), true) : new TarArchiveEntry(entry.name(), (byte) entry.type(), true);
                written.setModTime(0);
                written.setUserName("");
                written.setGroupName("");
                written.setIds(1000, 1000);
                written.setMode(entry.type() == '5' ? 040755 : 0100644);
                if (entry.link() != null) {
                    written.setLinkName(entry.link());
                }
                byte[] content = entry.content() == null ? new byte[0] : entry.content().getBytes(StandardCharsets.UTF_8);
                if (entry.content() != null) {
                    written.setSize(content.length);
                }
                tar.putArchiveEntry(written);
                tar.write(content);
                tar.closeArchiveEntry();
            }
            tar.finish();
        }
        Path root = Files.createDirectories(directory.resolve("case-" + cases.size()));
        Path mount = Files.createDirectories(root.resolve("mount"));
        Files.createDirectories(root.resolve("elsewhere"));
        Files.createDirectories(mount.resolve("real"));
        for (Map.Entry<String, String> present : new java.util.TreeMap<>(existing).entrySet()) {
            Path at = mount.resolve(present.getKey());
            Files.createDirectories(at.getParent());
            if (present.getValue().isEmpty()) {
                Files.writeString(at, "old");
            } else {
                Files.createSymbolicLink(at, Path.of(present.getValue()));
            }
        }

        ObjectNode entry = cases.addObject();
        entry.put("name", name).put("ceiling", ceiling);
        ObjectNode before = entry.putObject("existing");
        new java.util.TreeMap<>(existing).forEach(before::put);
        entry.put("archive", Base64.getEncoder().encodeToString(bytes.toByteArray()));
        try {
            List<String> written = MountArchives.extractWritten(new ByteArrayInputStream(bytes.toByteArray()), mount, ceiling);
            written.forEach(entry.putArray("written")::add);
            ObjectNode files = entry.putObject("files");
            try (Stream<Path> walk = Files.walk(mount)) {
                walk.filter(path -> Files.isRegularFile(path, java.nio.file.LinkOption.NOFOLLOW_LINKS)).sorted()
                        .forEach(path -> {
                            try {
                                files.put(mount.relativize(path).toString(), Files.readString(path));
                            } catch (IOException unreadable) {
                                throw new IllegalStateException(unreadable);
                            }
                        });
            }
        } catch (IOException refused) {
            entry.put("refused", refused.getMessage());
        }
    }
}
