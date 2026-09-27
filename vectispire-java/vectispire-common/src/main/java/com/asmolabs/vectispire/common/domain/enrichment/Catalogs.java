package com.asmolabs.vectispire.common.domain.enrichment;

import java.util.ArrayList;
import java.util.List;

/**
 * The public catalogues Vectispire enriches findings from, and the batching their lookups share.
 *
 * <p><b>Both are synchronised and stored; a scan asks neither.</b> The EPSS scores were asked of
 * {@code api.first.org} per scan, ninety CVE at a time — which told FIRST which vulnerabilities each
 * repository carried. They are FIRST's daily file now ({@code EpssFile}), read by the control plane
 * as a whole, like CISA's catalogue.
 */
public final class Catalogs {

    private Catalogs() {}

    /**
     * The catalog of actively exploited vulnerabilities, published by CISA — the default of
     * {@code vectispire.threat-intel.kev-url}, which a mirror replaces. Read by the synchronisation
     * and stored, never per scan; see {@code KevCatalog} for how it is read.
     */
    public static final String KEV_CATALOG_URL =
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

    /**
     * Splits a list into batches of at most {@code size} — a local lookup's {@code in} list, kept
     * under every engine's bind-parameter ceiling.
     */
    public static <T> List<List<T>> batches(List<T> items, int size) {
        List<List<T>> batches = new ArrayList<>();
        for (int index = 0; index < items.size(); index += size) {
            batches.add(List.copyOf(items.subList(index, Math.min(index + size, items.size()))));
        }
        return batches;
    }
}
