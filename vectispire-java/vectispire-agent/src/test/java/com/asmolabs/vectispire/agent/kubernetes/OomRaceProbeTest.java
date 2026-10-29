package com.asmolabs.vectispire.agent.kubernetes;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.scanning.ContainerRun;
import com.asmolabs.vectispire.common.scanning.ScannerFailureException;
import com.asmolabs.vectispire.common.scanning.ScannerLimits;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

/**
 * TEMPORARY — reverted before merge. Runs the out-of-memory case forty times on CI's runner, half of them with
 * every core busy, and tallies which path reported it: "ran out of memory" is the runtime's OOMKilled, "was
 * killed (exit 137" is the lost reason — a run that returned, before the fix.
 */
@Tag("kubernetes")
class OomRaceProbeTest {

    @Test
    void probe() throws Exception {
        K3sCluster cluster = new K3sCluster();
        try {
            KubernetesExecutor small = new KubernetesExecutor(cluster.api(), new KubernetesExecutor.Settings(K3sCluster.NAMESPACE,
                    "probe-agent", KubernetesExecutor.HELPER_IMAGE, "1000:1000", Duration.ofMinutes(3),
                    new ScannerLimits(48L * 1024 * 1024, 512, Duration.ofMinutes(2), 500_000_000L, 1024 * 1024), null));
            ContainerRun run = ContainerRun.of(KubernetesExecutor.HELPER_IMAGE,
                    List.of("sh", "-c", "a=$(head -c 200000000 /dev/zero | tr '\\0' a); echo ${#a}"), List.of(), "shell test")
                    .withEntrypoint(List.of());
            Map<String, Integer> tally = new TreeMap<>();
            for (int i = 0; i < 40; i++) {
                boolean pressure = i % 2 == 1;
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
                String outcome;
                try {
                    var result = small.run(run);
                    outcome = "RETURNED exit=" + result.exitCode();
                } catch (ScannerFailureException failed) {
                    outcome = failed.getMessage().contains("was killed (exit 137") ? "LOST-REASON 137"
                            : failed.getMessage().contains("ran out of memory") ? "OOMKilled" : "OTHER " + failed.getMessage();
                } finally {
                    burners.forEach(Thread::interrupt);
                    for (Thread burner : burners) {
                        burner.join();
                    }
                }
                System.out.println("OOM-PROBE run " + i + (pressure ? " (pressure)" : "") + ": " + outcome);
                tally.merge((pressure ? "pressure " : "idle ") + outcome, 1, Integer::sum);
            }
            System.out.println("OOM-PROBE tally " + tally);
            assertThat(tally.keySet()).as("every run a failure: " + tally).allMatch(key -> !key.contains("RETURNED"));
        } finally {
            cluster.close();
        }
    }
}
