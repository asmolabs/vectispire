package com.asmolabs.vectispire.common.rust;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.json.JsonMapper;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import java.util.Properties;
import java.util.stream.Stream;

/**
 * A scanner's container result as a reference case — {@code <scanner>/runs/NN-name.stdout}, beside it
 * an optional {@code .stderr} and an optional {@code .case} ({@code exit=}, {@code subPath=}) — and the
 * outcome the scan made of it, written to {@code <scanner>/outcomes/NN-name.txt}.
 *
 * <p><b>The whole of a scan's reading, not only its parser.</b> What an exit code, an empty stdout or
 * a thin report becomes — findings, absent, or a failure — decides a backlog as surely as a path does
 * (decision 0007): "absent" leaves the target's issues alone, an empty list resolves them all. So the
 * outcome is recorded as one of three, and the Rust port is held to the kind as well as the bytes.
 */
public final class ScannerRuns {

    /** The agent's wire mapper, as {@code SecretsReferenceSetTest} builds it. */
    public static final ObjectMapper WIRE = JsonMapper.builder()
            .addModule(new com.fasterxml.jackson.datatype.jsr310.JavaTimeModule())
            .addModule(new com.fasterxml.jackson.datatype.jdk8.Jdk8Module())
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
            .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
            .build();

    private ScannerRuns() {}

    /** One recorded container result. */
    public record Run(String name, String stdout, String stderr, int exitCode, String subPath) {}

    /** What the scan answered for a run. */
    public interface Scan {
        Optional<? extends List<?>> apply(Run run);
    }

    public static List<Run> runs(String scanner) {
        Path dir = ReferenceSet.resolve(scanner + "/runs");
        try (Stream<Path> listed = Files.list(dir)) {
            return listed.filter(path -> path.toString().endsWith(".stdout")).sorted().map(ScannerRuns::read).toList();
        } catch (IOException unreadable) {
            throw new UncheckedIOException(unreadable);
        }
    }

    private static Run read(Path stdout) {
        try {
            String name = stdout.getFileName().toString().replaceFirst("\\.stdout$", "");
            Path stderr = stdout.resolveSibling(name + ".stderr");
            Path caseFile = stdout.resolveSibling(name + ".case");
            Properties props = new Properties();
            if (Files.exists(caseFile)) {
                try (var reader = Files.newBufferedReader(caseFile, StandardCharsets.UTF_8)) {
                    props.load(reader);
                }
            }
            return new Run(
                    name,
                    Files.readString(stdout, StandardCharsets.UTF_8),
                    Files.exists(stderr) ? Files.readString(stderr, StandardCharsets.UTF_8) : "",
                    Integer.parseInt(props.getProperty("exit", "0")),
                    props.getProperty("subPath"));
        } catch (IOException unreadable) {
            throw new UncheckedIOException(unreadable);
        }
    }

    /** Runs every case through {@code scan} and holds the outcomes to the committed files. */
    public static void expectOutcomes(String scanner, Scan scan) throws Exception {
        List<Run> runs = runs(scanner);
        if (runs.size() < 10) {
            throw new IllegalStateException("the " + scanner + " reference set is there: " + runs.size() + " runs");
        }
        for (Run run : runs) {
            String outcome;
            try {
                Optional<? extends List<?>> findings = scan.apply(run);
                outcome = findings.isEmpty() ? "absent\n" : "findings\n" + WIRE.writeValueAsString(findings.get()) + "\n";
            } catch (RuntimeException failed) {
                outcome = "failure\n" + failed.getMessage() + "\n";
            }
            ReferenceSet.expect(scanner + "/outcomes/" + run.name() + ".txt", outcome);
        }
    }
}
