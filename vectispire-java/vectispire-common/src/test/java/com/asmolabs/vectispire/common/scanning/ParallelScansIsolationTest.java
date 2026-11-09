package com.asmolabs.vectispire.common.scanning;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * What two scans running side by side on one agent may share, and what they may not.
 *
 * <p>A remote agent runs up to {@code max_concurrent} scans in one process, each through the same
 * {@link ScanRunner}. Until then every one of these paths was used by one scan at a time, so
 * nothing had ever checked that two could not collide. What was read: the workspace is a random
 * temporary directory per scan, the vulnerability database cache lives inside it, containers are
 * never named, and the bundled rules are copied into each workspace. What was found: the one file
 * two scans deliberately share — {@code known_hosts}, which has to outlive a clone to detect an
 * intercepted host — was prepared by check-then-create, and the second of two first clones failed.
 */
@DisplayName("two scans running side by side")
class ParallelScansIsolationTest {

    @Test
    @DisplayName("each gets a workspace of its own, and the first to finish removes only its own")
    void workspacesAreNotShared() throws Exception {
        CyclicBarrier bothInside = new CyclicBarrier(2);
        CountDownLatch firstGone = new CountDownLatch(1);

        try (ExecutorService pool = Executors.newFixedThreadPool(2)) {
            Future<Path> first = pool.submit(() -> Workspace.withWorkspace(workspace -> {
                write(workspace.source().resolve("pom.xml"), "first");
                await(bothInside);
                return workspace.root();
            }));
            Future<Boolean> second = pool.submit(() -> Workspace.withWorkspace(workspace -> {
                write(workspace.source().resolve("pom.xml"), "second");
                await(bothInside);
                try {
                    // The other scan has finished and deleted its tree by now; this one's clone
                    // must be exactly as it was left.
                    assertThat(firstGone.await(10, TimeUnit.SECONDS)).isTrue();
                    return Files.readString(workspace.source().resolve("pom.xml")).equals("second");
                } catch (Exception unreadable) {
                    return false;
                }
            }));

            Path firstRoot = first.get(10, TimeUnit.SECONDS);
            assertThat(firstRoot).doesNotExist();
            firstGone.countDown();
            assertThat(second.get(10, TimeUnit.SECONDS)).as("the second scan's clone survived the first's cleanup").isTrue();
        }
    }

    @Test
    @DisplayName("two first clones on a fresh machine both find a known_hosts file, neither fails")
    void knownHostsIsPreparedByWhoeverComesFirst(@TempDir Path home) throws Exception {
        // Raced on a fresh path each round: the window of check-then-create is a few microseconds,
        // so one round proves little and a hundred rounds of sixteen find it on every machine this
        // was tried on.
        int racers = 16;
        try (ExecutorService pool = Executors.newFixedThreadPool(racers)) {
            for (int round = 0; round < 100; round++) {
                Path knownHosts = home.resolve("round-" + round).resolve(".ssh").resolve("known_hosts");
                CyclicBarrier together = new CyclicBarrier(racers);
                List<Callable<Void>> clones = new ArrayList<>();
                for (int racer = 0; racer < racers; racer++) {
                    clones.add(() -> {
                        together.await(10, TimeUnit.SECONDS);
                        GitClone.prepareKnownHosts(knownHosts);
                        return null;
                    });
                }
                for (Future<Void> clone : pool.invokeAll(clones)) {
                    clone.get();
                }
                assertThat(knownHosts).exists();
            }
        }
    }

    @Test
    @DisplayName("a known_hosts file already there is kept as it is")
    void anExistingKnownHostsIsKept(@TempDir Path home) throws Exception {
        Path knownHosts = home.resolve(".ssh").resolve("known_hosts");
        Files.createDirectories(knownHosts.getParent());
        Files.writeString(knownHosts, "gitlab.example.com ssh-ed25519 AAAA\n");

        GitClone.prepareKnownHosts(knownHosts);

        // Truncated, every host would be a first contact again — the check that detects an
        // intercepted host, silently reset.
        assertThat(knownHosts).hasContent("gitlab.example.com ssh-ed25519 AAAA");
    }

    private static void write(Path file, String content) {
        try {
            Files.createDirectories(file.getParent());
            Files.writeString(file, content);
        } catch (java.io.IOException e) {
            throw new java.io.UncheckedIOException(e);
        }
    }

    private static void await(CyclicBarrier barrier) {
        try {
            barrier.await(10, TimeUnit.SECONDS);
        } catch (Exception interrupted) {
            throw new IllegalStateException(interrupted);
        }
    }
}
