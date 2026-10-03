package com.asmolabs.vectispire.reportdemo;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

/**
 * Vectispire's demonstration report plugin (decision 0035 §6): {@code --in <export.json> --out <summary.xlsx>}.
 *
 * <p>The manifest it is published with calls it as {@code ["--in", "{input}", "--out", "{output}"]}, which the
 * executor turns into {@code /report/input/export.json} and {@code /report/output/summary.xlsx}. It reads that
 * one file, writes that one file, and exits:
 *
 * <ul>
 *   <li>{@code 0} — the workbook is written;
 *   <li>{@code 1} — the export could not be read, or is missing a part it renders, or the workbook could not
 *       be written;
 *   <li>{@code 2} — the export is of another schema or another major than this plugin reads;
 *   <li>{@code 64} — it was called with other arguments.
 * </ul>
 *
 * <p>Every non-zero exit says why on stderr, in one sentence: the platform fails the run on any of them (0035
 * §2 — a renderer exits 0 or failed) and quotes that sentence as the run's detail.
 *
 * <p><b>The output is written once, whole.</b> The workbook is built in memory and written in one call, so a
 * refusal leaves no half-written file behind — and the bounded output directory of 0035 §2 has sixteen inodes
 * and a byte ceiling, which a temporary file beside it would spend for nothing.
 */
public final class ReportDemo {

    static final int EXIT_UNWRITABLE = 1;
    static final int EXIT_USAGE = 64;

    private ReportDemo() {}

    public static void main(String[] args) {
        int code = run(args, System.err);
        if (code != 0) {
            System.exit(code);
        }
    }

    /**
     * The workbook for {@code export}.
     *
     * @throws IllegalArgumentException naming why, for an export this plugin does not render — the in-process
     *     entry the platform's contract test calls, which has no exit code to read
     */
    public static byte[] render(byte[] export) {
        try {
            return SummaryWorkbook.render(ExportDocument.read(export));
        } catch (RefusedExport refused) {
            throw new IllegalArgumentException(refused.getMessage(), refused);
        }
    }

    static int run(String[] args, PrintStream err) {
        if (args.length != 4 || !"--in".equals(args[0]) || !"--out".equals(args[2])) {
            err.println("Usage: --in <export.json> --out <summary.xlsx>");
            return EXIT_USAGE;
        }
        Path in = Path.of(args[1]);
        Path out = Path.of(args[3]);
        byte[] export;
        try {
            export = Files.readAllBytes(in);
        } catch (IOException unreadable) {
            err.println("The export " + in + " could not be read: " + unreadable.getMessage());
            return RefusedExport.Kind.UNREADABLE.exitCode();
        }
        byte[] workbook;
        try {
            workbook = SummaryWorkbook.render(ExportDocument.read(export));
        } catch (RefusedExport refused) {
            err.println(refused.getMessage());
            return refused.kind().exitCode();
        }
        try {
            // Never through a link left where the file is to be written (O_NOFOLLOW: the open itself fails):
            // the executor reads its output as a regular file and refuses anything else, and so does this side.
            Files.write(out, workbook, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING,
                    StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS);
        } catch (IOException unwritable) {
            err.println("The workbook could not be written to " + out + ": " + unwritable.getMessage());
            return EXIT_UNWRITABLE;
        }
        return 0;
    }
}
