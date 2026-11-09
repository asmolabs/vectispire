package com.asmolabs.vectispire.common.domain.checklists;

import com.asmolabs.vectispire.common.domain.plugins.Language;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

/**
 * Which languages a static analysis must read for a checklist to call a repository examined (decision
 * 0032 §6): those in which a program's behaviour is written.
 *
 * <p><b>Left out, and why each.</b> {@code json} and {@code yaml} are data; {@code html} is markup —
 * a page's scripts are counted when they are files of their own; {@code dockerfile} and {@code
 * terraform} describe infrastructure, which the IaC step reads ({@code builtin:iac}), not the SAST
 * rules. Requiring SAST rules for them would keep every repository carrying a CI file from passing,
 * and would say nothing about its code.
 *
 * <p><b>Kept, though it is tempting to leave out: {@code bash}.</b> A shell script runs in the
 * pipelines and on the hosts, and command injection is a SAST finding like any other; the upstream
 * catalogue has rules for it. A repository whose {@code .sh} files no rule reads is not one whose code
 * was analysed.
 *
 * <p>An exhaustive {@code switch}: a language added to the vocabulary does not compile until somebody
 * decides here which side it is on — a default would decide it silently, and the wrong way round lets
 * a line pass on a tree nobody read.
 */
public final class SourceLanguages {

    private SourceLanguages() {}

    public static boolean isSource(Language language) {
        return switch (language) {
            case JSON, YAML, HTML, DOCKERFILE, TERRAFORM -> false;
            case APEX, BASH, C, CLOJURE, CSHARP, ELIXIR, GO, JAVA, JAVASCRIPT, KOTLIN, OCAML, PHP, PYTHON, RUBY, RUST,
                    SCALA, SOLIDITY, SWIFT, TYPESCRIPT -> true;
        };
    }

    /** The source languages among these, in the vocabulary's order. */
    public static Set<Language> of(Set<Language> languages) {
        Set<Language> source = EnumSet.noneOf(Language.class);
        languages.stream().filter(SourceLanguages::isSource).forEach(source::add);
        return Collections.unmodifiableSet(source);
    }
}
