package com.asmolabs.vectispire.core.access.web.security.chain;

import com.asmolabs.vectispire.core.crypto.SecretFile;
import java.util.Optional;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.ConstructorBinding;
import org.springframework.validation.annotation.Validated;

/**
 * The token a metrics scraper presents on {@code /actuator/prometheus}, and nowhere else — {@code
 * VECTISPIRE_METRICS_SCRAPE_TOKEN}, or {@code VECTISPIRE_METRICS_SCRAPE_TOKEN_FILE} naming a file
 * that holds it. Unset, the endpoint answers an administrator's session only.
 *
 * <p><b>Why a token of its own.</b> A Prometheus server cannot hold a session — it expires, and it
 * is minted by signing in with a password and a second factor — and every credential the API
 * already issues opens far more than a page of numbers: an administrator's session the whole
 * platform, an integration key its account's routes. The SCIM token set the pattern: a static
 * secret held by one third system, recognised on one path, granting nothing but that path.
 *
 * <p>Read from its file at each scrape, as the SCIM token is, so a rotated secret takes effect
 * without a restart.
 */
@Validated
@ConfigurationProperties("vectispire.metrics")
public record ScrapeTokenProperties(Optional<String> scrapeToken, Optional<String> scrapeTokenFile) {

    /**
     * The shortest scrape token accepted, in characters — the SCIM token's floor, for its reason: a
     * static secret compared on every request, throttled per address only, is as strong as it is long.
     */
    public static final int MIN_TOKEN_LENGTH = 32;

    private static final String FILE_VARIABLE = "VECTISPIRE_METRICS_SCRAPE_TOKEN_FILE";

    @ConstructorBinding
    public ScrapeTokenProperties {
        scrapeToken = scrapeToken == null ? Optional.empty() : scrapeToken.filter(t -> !t.isBlank());
        scrapeTokenFile = scrapeTokenFile == null
                ? Optional.empty()
                : scrapeTokenFile.map(String::trim).filter(t -> !t.isEmpty());
        // **Refused at start, not at the first scrape**: a short token accepted is one nobody hears
        // about until somebody has guessed it, and a scraper failing for weeks reads as an outage.
        // The parameters, not `token()`: a compact constructor assigns the fields after its body.
        resolve(scrapeToken, scrapeTokenFile).filter(value -> value.length() < MIN_TOKEN_LENGTH).ifPresent(value -> {
            throw new IllegalStateException("The metrics scrape token is " + value.length()
                    + " characters long; at least " + MIN_TOKEN_LENGTH
                    + " are required. Generate one with `openssl rand -base64 32`.");
        });
    }

    /** The token in force: the file's when one is named — a file that cannot be read is fatal — else the value's. */
    public Optional<String> token() {
        return resolve(scrapeToken, scrapeTokenFile);
    }

    private static Optional<String> resolve(Optional<String> value, Optional<String> file) {
        return file.isPresent() ? Optional.of(SecretFile.read(file.get(), FILE_VARIABLE)) : value;
    }
}
