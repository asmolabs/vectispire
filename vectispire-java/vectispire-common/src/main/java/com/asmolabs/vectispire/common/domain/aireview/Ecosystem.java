package com.asmolabs.vectispire.common.domain.aireview;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Locale;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * The package ecosystems an upgrade command can be written for, named by a purl's type.
 *
 * <p><b>A command only for the ecosystem the component is in.</b> The advice offered {@code mvn
 * versions:use-next-releases} and {@code npm install} side by side whatever the component, and a
 * Maven descriptor with {@code <groupId>...</groupId>} for a Python package: two commands of which
 * one at best applied, and a snippet nobody could paste. The purl the scanner recorded says which
 * ecosystem the component belongs to; a component without one, or of a type not listed here, gets
 * no command — none is better than one that looks right and is not. RubyGems is left out for that
 * reason: Bundler has no one command that moves a gem already in the Gemfile to a given version.
 */
public enum Ecosystem {
    MAVEN("maven") {
        @Override
        Upgrade upgrade(Coordinates component, String version) {
            if (component.namespace() == null) {
                return null;
            }
            String coordinates = component.namespace() + ":" + component.name();
            return new Upgrade(
                    "mvn versions:use-dep-version -Dincludes=" + coordinates + " -DdepVersion=" + version
                            + " -DforceVersion=true",
                    "<dependency>\n    <groupId>" + component.namespace() + "</groupId>\n    <artifactId>"
                            + component.name() + "</artifactId>\n    <version>" + version + "</version>\n</dependency>");
        }
    },
    NPM("npm") {
        @Override
        Upgrade upgrade(Coordinates component, String version) {
            return new Upgrade("npm install " + component.qualifiedName("/") + "@" + version, "");
        }
    },
    PYPI("pypi") {
        @Override
        Upgrade upgrade(Coordinates component, String version) {
            return new Upgrade("pip install \"" + component.name() + "==" + version + "\"", "");
        }
    },
    CARGO("cargo") {
        @Override
        Upgrade upgrade(Coordinates component, String version) {
            return new Upgrade("cargo update -p " + component.name() + " --precise " + version, "");
        }
    },
    NUGET("nuget") {
        @Override
        Upgrade upgrade(Coordinates component, String version) {
            return new Upgrade("dotnet add package " + component.name() + " --version " + version, "");
        }
    },
    COMPOSER("composer") {
        @Override
        Upgrade upgrade(Coordinates component, String version) {
            return new Upgrade("composer require " + component.qualifiedName("/") + ":" + version, "");
        }
    },
    GOLANG("golang") {
        @Override
        Upgrade upgrade(Coordinates component, String version) {
            // A Go module version is semver with its leading v, which `go get` requires; scanners
            // record the fix with or without it.
            String tagged = version.startsWith("v") ? version : "v" + version;
            return new Upgrade("go get " + component.qualifiedName("/") + "@" + tagged, "");
        }
    };

    /**
     * A version as a command can take it: one version, no list and nothing a shell reads. A
     * scanner records several fixed versions for several release lines — {@code 2.12.2, 2.16.0} —
     * and which one applies depends on the line in use; that is a choice for the reader, not a
     * command to copy.
     */
    private static final Pattern ONE_VERSION = Pattern.compile("[A-Za-z0-9][A-Za-z0-9.+_~-]*");

    /** What a name or a namespace may be to go into a command unquoted. */
    private static final Pattern SAFE_PART = Pattern.compile("[A-Za-z0-9@][A-Za-z0-9._~/@-]*");

    private final String purlType;

    Ecosystem(String purlType) {
        this.purlType = purlType;
    }

    /**
     * The command and the descriptor that upgrade this component to this version.
     *
     * @param purl the component's package URL, as the scanner recorded it
     * @param version the fixed version recorded
     * @return empty when the purl is missing or unreadable, its type is not one listed here, or
     *     the version is not one version
     */
    public static Optional<Upgrade> upgradeOf(String purl, String version) {
        if (version == null || !ONE_VERSION.matcher(version.trim()).matches()) {
            return Optional.empty();
        }
        return Coordinates.parse(purl).flatMap(component -> Arrays.stream(values())
                .filter(ecosystem -> ecosystem.purlType.equals(component.type()))
                .findFirst()
                .map(ecosystem -> ecosystem.upgrade(component, version.trim())));
    }

    abstract Upgrade upgrade(Coordinates component, String version);

    /**
     * An upgrade to copy.
     *
     * @param command the command line
     * @param descriptor the dependency declaration, for an ecosystem whose manifest is edited by
     *     hand; empty otherwise
     */
    public record Upgrade(String command, String descriptor) {}

    /** A purl's type, namespace and name, decoded; the version, qualifiers and subpath dropped. */
    record Coordinates(String type, String namespace, String name) {

        String qualifiedName(String separator) {
            return namespace == null ? name : namespace + separator + name;
        }

        static Optional<Coordinates> parse(String purl) {
            if (purl == null || !purl.trim().startsWith("pkg:")) {
                return Optional.empty();
            }
            String value = purl.trim().substring("pkg:".length());
            for (char separator : new char[] {'#', '?'}) {
                int cut = value.indexOf(separator);
                if (cut >= 0) {
                    value = value.substring(0, cut);
                }
            }
            int at = value.lastIndexOf('@');
            if (at > 0) {
                value = value.substring(0, at);
            }
            String[] parts = value.split("/");
            if (parts.length < 2) {
                return Optional.empty();
            }
            String type = parts[0].toLowerCase(Locale.ROOT);
            String name = decode(parts[parts.length - 1]);
            String namespace = parts.length > 2
                    ? decode(String.join("/", Arrays.copyOfRange(parts, 1, parts.length - 1)))
                    : null;
            if (name == null || !SAFE_PART.matcher(name).matches()
                    || (namespace != null && !SAFE_PART.matcher(namespace).matches())) {
                // A name a shell would read as something else never reaches a command.
                return Optional.empty();
            }
            return Optional.of(new Coordinates(type, namespace, name));
        }

        private static String decode(String part) {
            try {
                String decoded = URLDecoder.decode(part.replace("+", "%2B"), StandardCharsets.UTF_8);
                return decoded.isBlank() ? null : decoded;
            } catch (IllegalArgumentException malformed) {
                return null;
            }
        }
    }
}
