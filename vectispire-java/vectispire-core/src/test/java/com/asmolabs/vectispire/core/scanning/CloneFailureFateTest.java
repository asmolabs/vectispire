package com.asmolabs.vectispire.core.scanning;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.common.scanning.ContainerRunner;
import com.asmolabs.vectispire.common.scanning.GitClone;
import com.asmolabs.vectispire.common.scanning.ScanRunner;
import com.asmolabs.vectispire.common.scanning.ScanTask;
import com.asmolabs.vectispire.common.scanning.scanners.ScannerImages;
import com.asmolabs.vectispire.core.VectispireContextTest;
import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import com.asmolabs.vectispire.core.scanning.persistence.ScanRepository;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.bean.override.convention.TestBean;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

/**
 * A repository that is not there and a host that cannot be reached, through the built-in worker as it
 * runs them: the real clone, the real dispatcher, the real queue on the real database, the clock the
 * whole application reads.
 *
 * <p><b>The two failures a scan meets most, and the two fates the queue has.</b> The first must fail
 * at its first attempt — three attempts and twenty minutes spent on the same answer only delay the
 * reason reaching the screen, which is what a {@code git://} repository its daemon does not serve did
 * until the clone's diagnosis read the daemon's refusal. The second must wait and retry: a minute,
 * then five, then fail as the last. Each half is tested elsewhere — the diagnosis against JGit's
 * exceptions, the rule as a pure function, the dispatcher with a mocked queue — and what this pins is
 * that they compose: the kind the clone decides is the one the row ends with, and the instant on the
 * row is the one the next claim honours.
 *
 * <p>Only the containers are replaced, and never reached: the clone runs before any scanner, and a
 * scan that cannot clone starts none. The windows are read off the application's own {@link Clock},
 * moved by hand — wall time would make "about a minute" a flake or a sleep.
 */
@DisplayName("a clone that cannot run, through the built-in worker: failed at once, or retried after a minute")
class CloneFailureFateTest extends VectispireContextTest {

    private static final MovableClock CLOCK = new MovableClock(Instant.now().truncatedTo(ChronoUnit.SECONDS));

    /** The application's clock, every bean's: the queue stamps and selects with it. */
    @TestBean
    private Clock clock;

    static Clock clock() {
        return CLOCK;
    }

    @MockitoBean
    private ScanRunner runner;

    @Autowired
    private ScanDispatcher dispatcher;

    @Autowired
    private ScanRepository scans;

    @Autowired
    private GitRepositoryRepository repositories;

    private final ContainerRunner containers = mock(ContainerRunner.class);
    private GitDaemonRefusing daemon;
    private Path rules;

    @BeforeEach
    void realClone() throws IOException {
        daemon = new GitDaemonRefusing();
        rules = Files.createTempDirectory("clone-fate-rules");
        ScanRunner real = new ScanRunner(containers, ScannerImages.PINNED, rules, hash -> List.of(),
                new GitClone.HostKeyPolicy.TrustEveryHost(), GitClone.WithoutKey.NONE, CLOCK);
        when(runner.run(any())).thenAnswer(call -> real.run(call.getArgument(0, ScanTask.class)));
        // A scan another test of this class left waiting would be claimed here once the clock passes it.
        scans.findAll().stream()
                .filter(scan -> ScanStatus.PENDING.wireName().equals(scan.getStatus()))
                .forEach(scan -> {
                    scan.setStatus(ScanStatus.FAILED.wireName());
                    scans.save(scan);
                });
    }

    @AfterEach
    void stop() throws IOException {
        daemon.close();
        Files.deleteIfExists(rules);
    }

    @Test
    @DisplayName("a repository its server does not have fails at its first attempt, says so, and is not retried")
    void aMissingRepositoryFailsAtOnce() {
        long scanId = queued(daemon.url("missing.git"));

        ScanDispatcher.Dispatched round = dispatch();

        assertThat(round).isEqualTo(new ScanDispatcher.Dispatched(1, 0, 1));
        ScanEntity scan = scans.findById(scanId).orElseThrow();
        assertThat(scan.getStatus()).isEqualTo(ScanStatus.FAILED.wireName());
        assertThat(scan.getAttempts()).isEqualTo(1);
        assertThat(scan.getNotBefore()).as("no retry scheduled").isNull();
        assertThat(scan.getError())
                .startsWith("Attempt 1 of 3 could not run on the built-in worker, and another attempt would meet the"
                        + " same refusal: ")
                .endsWith(daemon.url("missing.git") + " could not be found.");
        assertThat(daemon.requests()).as("one clone, one refusal").isEqualTo(1);

        CLOCK.advance(Duration.ofHours(1));
        assertThat(dispatch().claimed()).as("a failed scan is never taken again").isZero();
        assertThat(daemon.requests()).isEqualTo(1);
        verifyNoInteractions(containers);
    }

    @Test
    @DisplayName("a host that cannot be reached waits a minute, then five, and fails as the last of three")
    void anUnreachableHostRetries() {
        // `.invalid` never resolves (RFC 6761), here or on any runner.
        String url = "git://forge.vectispire.invalid/team/repo.git";
        long scanId = queued(url);
        Instant failedAt = CLOCK.instant();

        assertThat(dispatch()).isEqualTo(new ScanDispatcher.Dispatched(1, 0, 1));

        ScanEntity scan = scans.findById(scanId).orElseThrow();
        assertThat(scan.getStatus()).isEqualTo(ScanStatus.PENDING.wireName());
        assertThat(scan.getAttempts()).isEqualTo(1);
        assertThat(scan.getNotBefore()).isEqualTo(failedAt.plus(Duration.ofMinutes(1)));
        assertThat(scan.getError())
                .isEqualTo("Attempt 1 of 3 could not run on the built-in worker; the scan is back in the queue, not before "
                        + failedAt.plus(Duration.ofMinutes(1)) + ": The clone of " + url
                        + " could not reach its host. Is the repository reachable from this machine?");

        CLOCK.advance(Duration.ofSeconds(59));
        assertThat(dispatch().claimed()).as("a second before its minute, the scan waits").isZero();

        CLOCK.advance(Duration.ofSeconds(1));
        Instant secondFailure = CLOCK.instant();
        assertThat(dispatch()).as("at its minute, it is taken again").isEqualTo(new ScanDispatcher.Dispatched(1, 0, 1));
        scan = scans.findById(scanId).orElseThrow();
        assertThat(scan.getStatus()).isEqualTo(ScanStatus.PENDING.wireName());
        assertThat(scan.getAttempts()).isEqualTo(2);
        assertThat(scan.getNotBefore()).isEqualTo(secondFailure.plus(Duration.ofMinutes(5)));

        CLOCK.advance(Duration.ofMinutes(5).minusSeconds(1));
        assertThat(dispatch().claimed()).isZero();
        CLOCK.advance(Duration.ofSeconds(1));
        assertThat(dispatch()).isEqualTo(new ScanDispatcher.Dispatched(1, 0, 1));

        scan = scans.findById(scanId).orElseThrow();
        assertThat(scan.getStatus()).isEqualTo(ScanStatus.FAILED.wireName());
        assertThat(scan.getAttempts()).isEqualTo(3);
        assertThat(scan.getNotBefore()).isNull();
        assertThat(scan.getError()).startsWith("Attempt 3 of 3 could not run on the built-in worker, and it was the last: ");
        verifyNoInteractions(containers);
    }

    private ScanDispatcher.Dispatched dispatch() {
        return dispatcher.dispatch("built-in-clone-fate", 1, List.of());
    }

    private long queued(String url) {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl(url);
        repository.setBranch("main");
        long repositoryId = repositories.save(repository).getId();

        ScanEntity scan = new ScanEntity();
        scan.setRepoId(repositoryId);
        scan.setBranch("main");
        scan.setStatus(ScanStatus.PENDING.wireName());
        scan.setCreatedAt(CLOCK.instant());
        scan.setFindingsCount(0);
        scan.setNewIssuesCount(0);
        scan.setResolvedIssuesCount(0);
        return scans.save(scan).getId();
    }

    /**
     * What {@code git daemon} answers for a path it does not serve: one pkt-line, {@code ERR} and its
     * sentence, as git 2.55's daemon sends it (measured with {@code GIT_TRACE_PACKET}).
     */
    private static final class GitDaemonRefusing implements AutoCloseable {
        private final ServerSocket socket = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
        private final java.util.concurrent.atomic.AtomicInteger requests = new java.util.concurrent.atomic.AtomicInteger();

        GitDaemonRefusing() throws IOException {
            Thread.ofVirtual().start(() -> {
                while (!socket.isClosed()) {
                    try (Socket client = socket.accept()) {
                        InputStream in = client.getInputStream();
                        int length = Integer.parseInt(new String(in.readNBytes(4), StandardCharsets.US_ASCII), 16);
                        String request = new String(in.readNBytes(length - 4), StandardCharsets.UTF_8);
                        requests.incrementAndGet();
                        String path = request.substring(request.indexOf(' ') + 1, request.indexOf('\0'));
                        String refusal = "ERR access denied or repository not exported: " + path;
                        client.getOutputStream()
                                .write(String.format("%04x%s", refusal.length() + 4, refusal).getBytes(StandardCharsets.UTF_8));
                        client.getOutputStream().flush();
                    } catch (IOException | RuntimeException closed) {
                        // The socket closed under accept(), or a client that hung up: either way, next.
                    }
                }
            });
        }

        String url(String path) {
            return "git://127.0.0.1:" + socket.getLocalPort() + "/" + path;
        }

        int requests() {
            return requests.get();
        }

        @Override
        public void close() throws IOException {
            socket.close();
        }
    }

    private static final class MovableClock extends Clock {
        private volatile Instant now;

        MovableClock(Instant start) {
            this.now = start;
        }

        void advance(Duration by) {
            now = now.plus(by);
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }
}
