package com.asmolabs.vectispire.common.domain.eol;

import java.util.Locale;

/**
 * Reducing a purl to what names the <b>product</b> rather than the build.
 *
 * <p>A SBOM purl carries a version and qualifiers —
 * {@code pkg:rpm/redhat/openssl@3.5.1?arch=x86_64} — where a catalog's identifiers carry
 * neither. Comparing them as they are matches nothing, and matching nothing looks exactly like
 * "this product has no known end of life".
 */
public final class Purls {

    private Purls() {}

    /** {@code pkg:type/namespace/name}, lowercase, with no version and no qualifiers. */
    public static String normalize(String purl) {
        String value = purl == null ? "" : purl.trim();
        for (String separator : new String[] {"?", "#"}) {
            int cut = value.indexOf(separator);
            if (cut >= 0) {
                value = value.substring(0, cut);
            }
        }
        int at = value.lastIndexOf('@');
        if (at > 0) {
            value = value.substring(0, at);
        }
        return value.toLowerCase(Locale.ROOT).replaceAll("/+$", "");
    }
}
