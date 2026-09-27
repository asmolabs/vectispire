package com.asmolabs.vectispire.common.domain.plugins;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * The languages a plugin may declare, and how a file names the one it is written in.
 *
 * <p><b>The vocabulary is the Semgrep catalogue's</b>: its top-level directories, which are what an
 * operator already picks from on the rule set screen ({@code RuleCatalogue}). A plugin declaring
 * {@code java} and a rule set covering {@code java} then mean the same thing, and a manifest naming
 * a language outside this list is refused at registration rather than never matching anything.
 * Semgrep's {@code generic} is left out: a plugin that applies to everything declares nothing it
 * could be skipped for, and should say so by listing the languages it actually reads.
 *
 * <p><b>Recognised by file name alone, in linear time.</b> The census runs in the worker's own
 * process over a tree somebody else wrote — in the built-in worker, the control plane's — so it
 * never opens a file and never runs a pattern: a lowercase copy, one {@code lastIndexOf}, two map
 * lookups. The 2026-09-26 audit found a backtracking pattern that one committed file could pin for
 * minutes ({@code AnalysisBudget}); this has nothing that can backtrack.
 *
 * <p><b>A manifest is a sign too.</b> {@code pom.xml} says Java before a single {@code .java} file
 * has been seen — the same files {@code ProjectManifest} reads — and a {@code build.gradle.kts} says
 * both Java (the build) and Kotlin (the script), so a name may answer several languages.
 */
public enum Language {
    APEX("apex", List.of("cls", "trigger"), List.of()),
    BASH("bash", List.of("sh", "bash"), List.of()),
    C("c", List.of("c", "h"), List.of()),
    CLOJURE("clojure", List.of("clj", "cljs", "cljc"), List.of("project.clj", "deps.edn")),
    CSHARP("csharp", List.of("cs", "csx", "csproj", "sln"), List.of()),
    DOCKERFILE("dockerfile", List.of("dockerfile"), List.of("dockerfile", "containerfile")),
    ELIXIR("elixir", List.of("ex", "exs"), List.of("mix.exs")),
    GO("go", List.of("go"), List.of("go.mod")),
    HTML("html", List.of("html", "htm"), List.of()),
    JAVA("java", List.of("java"), List.of("pom.xml", "build.gradle", "build.gradle.kts")),
    JAVASCRIPT("javascript", List.of("js", "jsx", "mjs", "cjs"), List.of("package.json")),
    JSON("json", List.of("json"), List.of()),
    KOTLIN("kotlin", List.of("kt", "kts"), List.of()),
    OCAML("ocaml", List.of("ml", "mli"), List.of("dune-project")),
    PHP("php", List.of("php"), List.of("composer.json")),
    PYTHON("python", List.of("py", "pyi"),
            List.of("pyproject.toml", "requirements.txt", "setup.py", "setup.cfg", "pipfile")),
    RUBY("ruby", List.of("rb"), List.of("gemfile")),
    RUST("rust", List.of("rs"), List.of("cargo.toml")),
    SCALA("scala", List.of("scala", "sc"), List.of("build.sbt")),
    SOLIDITY("solidity", List.of("sol"), List.of()),
    SWIFT("swift", List.of("swift"), List.of("package.swift")),
    TERRAFORM("terraform", List.of("tf", "tfvars", "hcl"), List.of()),
    TYPESCRIPT("typescript", List.of("ts", "tsx", "mts", "cts"), List.of("tsconfig.json")),
    YAML("yaml", List.of("yaml", "yml"), List.of());

    private static final Map<String, Set<Language>> BY_EXTENSION = index(true);
    private static final Map<String, Set<Language>> BY_NAME = index(false);

    private final String wireName;
    private final List<String> extensions;
    private final List<String> fileNames;

    Language(String wireName, List<String> extensions, List<String> fileNames) {
        this.wireName = wireName;
        this.extensions = extensions;
        this.fileNames = fileNames;
    }

    /** The form a manifest, the API and the database carry — the catalogue directory's name. */
    @JsonValue
    public String wireName() {
        return wireName;
    }

    @JsonCreator
    public static Language fromJson(String value) {
        return fromWireName(value).orElseThrow(() -> new IllegalArgumentException(
                "Unknown language \"" + value + "\"; expected one of " + wireNames() + "."));
    }

    public static Optional<Language> fromWireName(String value) {
        if (value == null) {
            return Optional.empty();
        }
        String normalized = value.trim().toLowerCase(Locale.ROOT);
        return Arrays.stream(values()).filter(language -> language.wireName.equals(normalized)).findFirst();
    }

    /** Every wire name, in declaration order — for a refusal that says what would have been accepted. */
    public static List<String> wireNames() {
        return Arrays.stream(values()).map(Language::wireName).toList();
    }

    /**
     * The languages a file's name says it belongs to — empty for a name that says nothing.
     *
     * <p>Linear in the length of the name, whatever the name: no pattern, no loop over the
     * languages. {@code Dockerfile.prod} is the one prefix rule, checked with {@code startsWith}.
     */
    public static Set<Language> ofFileName(String fileName) {
        if (fileName == null || fileName.isEmpty()) {
            return Set.of();
        }
        String lower = fileName.toLowerCase(Locale.ROOT);
        Set<Language> found = EnumSet.noneOf(Language.class);
        Set<Language> named = BY_NAME.get(lower);
        if (named != null) {
            found.addAll(named);
        }
        int dot = lower.lastIndexOf('.');
        if (dot >= 0 && dot < lower.length() - 1) {
            Set<Language> extended = BY_EXTENSION.get(lower.substring(dot + 1));
            if (extended != null) {
                found.addAll(extended);
            }
        }
        if (lower.startsWith("dockerfile.")) {
            found.add(DOCKERFILE);
        }
        return found.isEmpty() ? Set.of() : Collections.unmodifiableSet(found);
    }

    private static Map<String, Set<Language>> index(boolean extensions) {
        Map<String, Set<Language>> index = new HashMap<>();
        for (Language language : values()) {
            for (String key : extensions ? language.extensions : language.fileNames) {
                index.computeIfAbsent(key, ignored -> EnumSet.noneOf(Language.class)).add(language);
            }
        }
        Map<String, Set<Language>> frozen = new HashMap<>();
        index.forEach((key, languages) -> frozen.put(key, Collections.unmodifiableSet(languages)));
        return Map.copyOf(frozen);
    }
}
