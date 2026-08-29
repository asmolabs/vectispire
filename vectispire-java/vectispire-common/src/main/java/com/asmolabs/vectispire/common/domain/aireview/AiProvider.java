package com.asmolabs.vectispire.common.domain.aireview;

import java.util.Arrays;
import java.util.Locale;

/**
 * Who reviews the code: a model on a machine the operator controls, or OpenAI's API.
 *
 * <p><b>The two are not variants of one destination.</b> Ollama's default is a loopback address
 * and the guard refuses a public one unless somebody acknowledged it; OpenAI is a public host by
 * definition, reached over the internet, with the repository's source code in the request body.
 * Choosing it is choosing to send that code to a third party — which is why
 * {@link #sendsCodeToAThirdParty()} exists as a question the screens and the service can both ask,
 * rather than as a string comparison repeated at every call site.
 *
 * <p><b>An unrecognised stored value reads as {@link #OLLAMA}</b>, not as an error and not as
 * OpenAI. The fallback has to point at the destination that leaks nothing: a typo in the database
 * then breaks the review by sending it nowhere, instead of quietly promoting a local deployment to
 * one that ships its code off-site.
 */
public enum AiProvider {

    /** A model on a host the operator runs, through Ollama's own API. */
    OLLAMA("ollama", "Ollama"),

    /** OpenAI's hosted API, over {@code /chat/completions}, authenticated by an API key. */
    OPENAI("openai", "OpenAI");

    private final String wireName;
    private final String displayName;

    AiProvider(String wireName, String displayName) {
        this.wireName = wireName;
        this.displayName = displayName;
    }

    /** The stored and transmitted form, lowercase. */
    public String wireName() {
        return wireName;
    }

    /** The form that belongs in a sentence somebody reads — "Is Ollama running", not "Is ollama running". */
    public String displayName() {
        return displayName;
    }

    /**
     * Whether picking this provider means the scanned code leaves the estate.
     *
     * <p>Asked rather than derived from the URL: an Ollama pointed at a public address leaks too,
     * but that case is already governed by the acknowledgement setting. This one is about a
     * provider that <em>cannot</em> be anything but remote, and so cannot be made safe by
     * configuring it differently.
     */
    public boolean sendsCodeToAThirdParty() {
        return this == OPENAI;
    }

    /** The stored value, read leniently. Unknown means {@link #OLLAMA} — see the class comment. */
    public static AiProvider of(String value) {
        if (value == null) {
            return OLLAMA;
        }
        String normalized = value.trim().toLowerCase(Locale.ROOT);
        return Arrays.stream(values())
                .filter(provider -> provider.wireName.equals(normalized))
                .findFirst()
                .orElse(OLLAMA);
    }

    /**
     * The same reading, but refusing what it does not recognise.
     *
     * <p>Used where a human just typed the value. The lenient {@link #of} is for reads, where
     * throwing would take a screen down over a row nobody can see; here the operator is present
     * and can be told.
     */
    public static AiProvider parse(String value) {
        String normalized = value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
        return Arrays.stream(values())
                .filter(provider -> provider.wireName.equals(normalized))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException(
                        "Unknown AI provider \"" + value + "\". Expected \"ollama\" or \"openai\"."));
    }
}
