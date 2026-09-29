package com.asmolabs.vectispire.common.scanning;

import com.asmolabs.vectispire.common.domain.plugins.Language;
import com.asmolabs.vectispire.common.domain.plugins.PluginManifest;
import com.asmolabs.vectispire.common.domain.plugins.PluginRef;
import com.asmolabs.vectispire.common.scanning.scanners.PluginScanner;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

/**
 * The plugins a task names, each turned into one of its three states.
 *
 * <p>A class of its own rather than a method of {@link ScanRunner} so that the decisions — which
 * definition is believed, when a plugin applies, what counts as absent — are exercised without a
 * clone; the runner calls it once the tree is there.
 *
 * <h2>In order</h2>
 *
 * <ol>
 *   <li><b>Every manifest is fetched and checked against the task's digest</b> before anything runs.
 *       One that cannot be fetched, does not hash to the digest, or does not validate is absent: the
 *       executor will not run a plugin other than the one the control plane decided.
 *   <li><b>The census is taken once</b> — the runner's, of the whole tree, or here for the union of
 *       the languages the plugins declare.
 *   <li><b>Each plugin is not applicable, produced or absent.</b> A plugin whose languages the census
 *       proves absent is not run. Any failure of a plugin is its own: the next one still runs, and the
 *       scanners' results are not touched.
 * </ol>
 */
public final class PluginSteps {

    private final PluginScanner scanner;
    private final PluginProvider provider;

    public PluginSteps(PluginScanner scanner, PluginProvider provider) {
        this.scanner = scanner;
        this.provider = provider == null ? PluginProvider.NONE : provider;
    }

    private record Resolved(PluginRef reference, PluginManifest manifest) {}

    /** The same, taking its own census of the tree. */
    public List<PluginStep> run(List<PluginRef> references, Workspace workspace, Path analysedRoot) {
        return run(references, workspace, analysedRoot, null);
    }

    /**
     * @param analysedRoot the directory the scan is limited to; when it is absent from this
     *     checkout, every plugin is absent — nothing was examined, which is not "no language"
     * @param census the census the runner already took of {@code analysedRoot}, whole — or null, and
     *     one is taken here for the plugins' languages only
     */
    public List<PluginStep> run(
            List<PluginRef> references, Workspace workspace, Path analysedRoot, LanguageCensus.Census census) {
        List<PluginStep> steps = new ArrayList<>(references.size());
        List<Resolved> resolved = new ArrayList<>(references.size());
        for (PluginRef reference : references) {
            Fetched fetched = fetch(reference);
            if (fetched.manifest() != null) {
                resolved.add(new Resolved(reference, fetched.manifest()));
            } else {
                steps.add(absent(reference, fetched.failure()));
            }
        }
        if (resolved.isEmpty()) {
            return List.copyOf(steps);
        }

        if (analysedRoot == null || !Files.isDirectory(analysedRoot, LinkOption.NOFOLLOW_LINKS)) {
            for (Resolved plugin : resolved) {
                steps.add(absent(plugin.reference(), "the directory this scan is limited to is absent from the checkout"));
            }
            return List.copyOf(steps);
        }

        if (census == null) {
            Set<Language> wanted = EnumSet.noneOf(Language.class);
            resolved.forEach(plugin -> wanted.addAll(plugin.manifest().languages()));
            census = LanguageCensus.of(analysedRoot, wanted);
        }

        for (Resolved plugin : resolved) {
            PluginRef reference = plugin.reference();
            PluginManifest manifest = plugin.manifest();
            if (!census.applies(manifest.languages())) {
                steps.add(new PluginStep.NotApplicable(reference.id(), reference.digest(), manifest.languages()));
                continue;
            }
            try {
                steps.add(scanner.scan(workspace, analysedRoot, manifest)
                        .<PluginStep>map(report -> new PluginStep.Produced(
                                reference.id(), reference.digest(), report.toolName(), report.toolVersion(), report.findings()))
                        .orElseGet(() -> absent(reference,
                                "the plugin's report says it computed no results, or carries no run")));
            } catch (RuntimeException failure) {
                steps.add(absent(reference, failure.getMessage() == null ? failure.toString() : failure.getMessage()));
            }
        }
        return List.copyOf(steps);
    }

    /** A manifest believed, or the reason it was not — exactly one of the two. */
    private record Fetched(PluginManifest manifest, String failure) {}

    private Fetched fetch(PluginRef reference) {
        try {
            PluginManifest manifest = provider.manifest(reference);
            if (manifest == null) {
                return new Fetched(null, "no definition was returned for it");
            }
            if (!reference.id().equals(manifest.id()) || !reference.digest().equals(manifest.digest())) {
                return new Fetched(null, "the definition received is not the one the task names (digest "
                        + reference.digest() + "); it is not run");
            }
            return new Fetched(manifest.validated(), null);
        } catch (RuntimeException failure) {
            return new Fetched(null, "its definition could not be obtained: "
                    + (failure.getMessage() == null ? failure.toString() : failure.getMessage()));
        }
    }

    private static PluginStep.Absent absent(PluginRef reference, String reason) {
        return new PluginStep.Absent(reference.id(), reference.digest(), reason);
    }
}
