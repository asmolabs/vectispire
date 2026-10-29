package com.asmolabs.vectispire.agent.kubernetes;

import com.asmolabs.vectispire.common.scanning.ContainerRun;
import com.asmolabs.vectispire.common.scanning.ScannerLimits;
import com.fasterxml.jackson.databind.JsonNode;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

/**
 * TEMPORARY — reverted before merge. Watches what the cluster itself reports for the scanner container (reason,
 * exit code, signal) of each run, for the kill variants and for the out-of-memory case under CPU pressure.
 */
@Tag("kubernetes")
class OomRaceProbeTest {

    @Test
    void probe() throws Exception {
        K3sCluster cluster = new K3sCluster();
        Map<String, String> seen = new ConcurrentHashMap<>();
        Thread watcher = Thread.ofVirtual().start(() -> {
            while (!Thread.currentThread().isInterrupted()) {
                try {
                    for (JsonNode pod : cluster.api().pods(K3sCluster.NAMESPACE, ScanPods.LABEL_AGENT + "=probe-agent")) {
                        ScanPods.scannerTerminated(pod).ifPresent(t -> seen.putIfAbsent(pod.path("metadata").path("name").asText(),
                                t.toString()));
                    }
                    Thread.sleep(50);
                } catch (InterruptedException stop) {
                    return;
                } catch (RuntimeException ignored) {
                    // keep watching
                }
            }
        });
        try {
            KubernetesExecutor small = new KubernetesExecutor(cluster.api(), new KubernetesExecutor.Settings(K3sCluster.NAMESPACE,
                    "probe-agent", KubernetesExecutor.HELPER_IMAGE, "1000:1000", Duration.ofMinutes(3),
                    new ScannerLimits(48L * 1024 * 1024, 512, Duration.ofMinutes(2), 500_000_000L, 1024 * 1024), null));
            List<String> scripts = new ArrayList<>(List.of(
                    "sh -c 'kill -9 $$'; exit $?",
                    "sh -c 'kill -9 $$; echo survived'; echo \"inner=$?\"; exit $?",
                    "sleep 60 & kill -9 $!; wait $!; exit $?",
                    "exit 137"));
            for (int i = 0; i < 40; i++) {
                scripts.add("a=$(head -c 200000000 /dev/zero | tr '\\0' a); echo ${#a}");
            }
            Map<String, Integer> tally = new TreeMap<>();
            for (int i = 0; i < scripts.size(); i++) {
                boolean pressure = i >= 4 && i % 2 == 1;
                List<Thread> burners = new ArrayList<>();
                if (pressure) {
                    for (int c = 0; c < Runtime.getRuntime().availableProcessors() * 2; c++) {
                        burners.add(Thread.ofPlatform().daemon().start(() -> {
                            long x = 0;
                            while (!Thread.currentThread().isInterrupted()) {
                                x += System.nanoTime() % 7;
                            }
                        }));
                    }
                }
                seen.clear();
                String outcome;
                try {
                    var result = small.run(ContainerRun.of(KubernetesExecutor.HELPER_IMAGE, List.of("sh", "-c", scripts.get(i)),
                            List.of(), "shell test").withEntrypoint(List.of()));
                    outcome = "RETURNED exit=" + result.exitCode() + " stdout=" + result.stdout().strip() + " stderr=" + result.stderr().strip();
                } catch (RuntimeException failed) {
                    outcome = "THREW " + failed.getMessage();
                } finally {
                    burners.forEach(Thread::interrupt);
                    for (Thread burner : burners) {
                        burner.join();
                    }
                }
                System.out.println("OOM-PROBE run " + i + (pressure ? " (pressure)" : "") + " [" + scripts.get(i) + "]: " + outcome
                        + " | cluster said " + seen.values());
                if (i >= 4) {
                    for (String status : seen.values()) {
                        tally.merge(status.replaceAll("\"(startedAt|finishedAt|containerID)\":\"[^\"]*\",?", ""), 1, Integer::sum);
                    }
                }
            }
            System.out.println("OOM-PROBE tally " + tally);
        } finally {
            watcher.interrupt();
            cluster.close();
        }
    }
}
