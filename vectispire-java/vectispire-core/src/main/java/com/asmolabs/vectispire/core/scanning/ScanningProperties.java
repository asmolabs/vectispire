package com.asmolabs.vectispire.core.scanning;

import java.util.Optional;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

/**
 * Scanning on this control plane, {@code vectispire.scanning.*}: what it decides about scanning, and
 * how its built-in worker runs.
 *
 * <p><b>In the module's API</b>, because the report plugins read the plugin registry too: their images
 * are mirrored into the same one, and the key had a reader — and a default — in each module.
 *
 * @param imagePlatform the variant of an image to pull, {@code linux/amd64} and the like. Empty
 *     lets the daemon choose, which means the host's architecture — so an arm64 development
 *     machine would audit a variant nobody deploys. It lives here rather than on the agent
 *     because it is a decision about <em>what we want scanned</em>, not about the machine that
 *     runs the scan
 * @param bundledRules a directory to use instead of the rules packaged in the jar.
 *     Empty by default and rarely wanted: the shipped tree is the one the tests cover, and
 *     the previous behaviour — a relative {@code rules} path resolved against the process
 *     working directory — pointed at nothing and failed every repository scan
 * @param hostSsh whether a repository with no deployment key falls back to this machine's
 *     own git access. <b>On by default, and to be turned off on a shared installation</b>:
 *     with it on, every target anybody adds to Vectispire is cloned with whatever the host's key
 *     can reach, so the per-repository scoping — a key attached to one target, encrypted at
 *     rest — stops meaning anything, and adding a URL is enough to have Vectispire clone it with
 *     an identity nobody attached to it. The default favours the single-team install, where
 *     the operator's {@code ~/.ssh} is already the credential that reaches every target and
 *     the alternative was re-declaring it once per repository. Set {@code VECTISPIRE_HOST_SSH}
 *     to {@code false} where the people adding targets are not the people who own that key
 * @param pluginRegistry the internal registry plugin images are pulled from — the registry host of
 *     each image replaced, its path and digest kept, so the mirror serves but cannot substitute.
 *     Blank pulls each from its own registry
 * @param pluginSignatureRequired run no plugin whose manifest declares no signer unless the
 *     governor waived the requirement for it. On by default (decision 0017 §9.1): a declared signer
 *     is always verified, and false — every unsigned plugin runs here — is this executor's
 *     operator's explicit choice; the agent has the same setting, for its own host. Report plugins
 *     do not read it: their signer is required whatever it says
 * @param vulnerabilityDbDir the directory the matcher's database is downloaded to once and shared
 *     from, read-only, by every scan of the built-in worker. Blank is a directory beside the
 *     workspaces, in the temporary directory; set it to a disk that survives a restart, and the
 *     first scan after one does not wait for a download
 * @param images the scanner images, overridable one by one
 */
@Validated
@ConfigurationProperties("vectispire.scanning")
public record ScanningProperties(
        Optional<String> imagePlatform,
        String bundledRules,
        @DefaultValue("true") boolean hostSsh,
        String pluginRegistry,
        @DefaultValue("true") boolean pluginSignatureRequired,
        String vulnerabilityDbDir,
        @DefaultValue Images images) {

    public ScanningProperties {
        imagePlatform = imagePlatform == null ? Optional.empty() : imagePlatform.filter(value -> !value.isBlank());
        bundledRules = bundledRules == null ? "" : bundledRules;
        pluginRegistry = pluginRegistry == null ? "" : pluginRegistry;
        vulnerabilityDbDir = vulnerabilityDbDir == null ? "" : vulnerabilityDbDir;
        images = images == null ? new Images(null, null, null, null, null) : images;
    }

    /**
     * Blank keeps the digest Vectispire ships with — see {@code ScannerImages.withOverrides}. Named one
     * by one rather than as a map, so each is a property an operator finds in the documentation.
     */
    public record Images(String syft, String grype, String gitleaks, String checkov, String semgrep) {

        public Images {
            syft = syft == null ? "" : syft;
            grype = grype == null ? "" : grype;
            gitleaks = gitleaks == null ? "" : gitleaks;
            checkov = checkov == null ? "" : checkov;
            semgrep = semgrep == null ? "" : semgrep;
        }
    }
}
