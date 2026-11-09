package com.asmolabs.vectispire.common.domain.checklists;

import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.ToolKeys;
import com.asmolabs.vectispire.common.domain.plugins.InvalidPluginException;
import com.asmolabs.vectispire.common.domain.plugins.PluginManifest;
import com.asmolabs.vectispire.common.domain.text.BoundedText;
import java.util.EnumSet;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * What a findings rule reads: one analyser's results, as Vectispire keeps them apart (decision 0032
 * §6) — a built-in step of a scan, a plugin, or one tool of a declared source's imports.
 *
 * <p><b>Three kinds, because each is examined in its own way.</b> A built-in step is recorded on its
 * scan ({@code examined_types}); a plugin has three states, kept per scan ({@code plugin_steps}); an
 * imported tool produced when its import was accepted. A scope names which of the three a rule rests
 * on, and so which record says whether it looked — never inferred from the findings present, which
 * would read a tool that found nothing as a tool that never ran.
 *
 * <p>The key is the fingerprint's own tool key for a plugin and an import ({@link ToolKeys}), so that
 * a scope counts exactly the issues that tool's runs resolve — never a type, which would count every
 * plugin's and every import's issues as one tool's.
 */
public sealed interface ToolScope permits ToolScope.BuiltIn, ToolScope.Plugin, ToolScope.Imported {

    String BUILT_IN_PREFIX = "builtin:";

    /** The built-in types a scan's own steps examine and record — the ones a scope may name. */
    Set<FindingType> BUILT_IN_TYPES = Set.copyOf(EnumSet.of(FindingType.VULNERABILITY, FindingType.SECRET,
            FindingType.IAC, FindingType.SAST, FindingType.QUALITY, FindingType.EOL, FindingType.LICENSE));

    /** {@code builtin:sast}, {@code plugin:<id>}, {@code import:<source>/<tool>}. */
    String key();

    /** A step of the scan itself. */
    record BuiltIn(FindingType type) implements ToolScope {

        public BuiltIn {
            Objects.requireNonNull(type, "type");
            if (!BUILT_IN_TYPES.contains(type)) {
                throw new IllegalArgumentException("No built-in step examines " + type.wireName());
            }
        }

        @Override
        public String key() {
            return BUILT_IN_PREFIX + type.wireName();
        }
    }

    /** A plugin, by its id: the image and its digest stay out, as they stay out of its issues' identity. */
    record Plugin(String pluginId) implements ToolScope {

        public Plugin {
            Objects.requireNonNull(pluginId, "pluginId");
        }

        @Override
        public String key() {
            return ToolKeys.plugin(pluginId);
        }
    }

    /** One tool of a declared source's SARIF imports, its name lowercased as the import keys it. */
    record Imported(String sourceSlug, String toolName) implements ToolScope {

        public Imported {
            Objects.requireNonNull(sourceSlug, "sourceSlug");
            Objects.requireNonNull(toolName, "toolName");
        }

        @Override
        public String key() {
            return ToolKeys.imported(sourceSlug, toolName);
        }
    }

    /**
     * A scope as a rule names it, refused in words: a scope nobody can examine would read "never
     * examined" on every repository, and a misspelt one is a rule nobody meant.
     */
    static ToolScope parse(String value) {
        String scope = value == null ? "" : value.strip();
        if (scope.startsWith(BUILT_IN_PREFIX)) {
            String name = scope.substring(BUILT_IN_PREFIX.length());
            return FindingType.fromWireName(name)
                    .filter(BUILT_IN_TYPES::contains)
                    .<ToolScope>map(BuiltIn::new)
                    .orElseThrow(() -> new InvalidInputException("\"" + BoundedText.clip(scope, 60) + "\" names no built-in "
                            + "step; one of " + BUILT_IN_TYPES.stream().map(type -> BUILT_IN_PREFIX + type.wireName())
                                    .sorted().collect(Collectors.joining(", ")) + "."));
        }
        if (scope.startsWith(ToolKeys.PLUGIN_PREFIX)) {
            String id = scope.substring(ToolKeys.PLUGIN_PREFIX.length());
            try {
                return new Plugin(PluginManifest.requireId(id));
            } catch (InvalidPluginException refused) {
                throw new InvalidInputException("\"" + BoundedText.clip(scope, 60) + "\": " + refused.getMessage());
            }
        }
        if (scope.startsWith(ToolKeys.IMPORT_PREFIX)) {
            String rest = scope.substring(ToolKeys.IMPORT_PREFIX.length());
            int slash = rest.indexOf('/');
            String source = slash < 0 ? "" : rest.substring(0, slash);
            String tool = slash < 0 ? "" : rest.substring(slash + 1).strip().toLowerCase(Locale.ROOT);
            if (!isSlug(source) || tool.isEmpty() || tool.length() > 100 || tool.contains(",")
                    || tool.chars().anyMatch(Character::isISOControl)) {
                throw new InvalidInputException("\"" + BoundedText.clip(scope, 60) + "\" is no imported tool: "
                        + "import:<source>/<tool>, the declared source's slug and the tool's name as it declares it.");
            }
            return new Imported(source, tool);
        }
        throw new InvalidInputException("A scope is builtin:<step>, plugin:<id> or import:<source>/<tool>"
                + (scope.isEmpty() ? "; one is empty." : "; \"" + BoundedText.clip(scope, 60) + "\" is none of them."));
    }

    /** A declared source's slug, as {@code SarifSourceService} admits one: 2 to 40, lowercase, inner hyphens. */
    private static boolean isSlug(String value) {
        if (value.length() < 2 || value.length() > 40) {
            return false;
        }
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            boolean alphanumeric = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
            if (!alphanumeric && (c != '-' || i == 0 || i == value.length() - 1)) {
                return false;
            }
        }
        return true;
    }
}
