package com.asmolabs.vectispire.core.inventory;

import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.PriorityQueue;

/**
 * The licence inventory while it is computed — a hash map of entries keyed by target, name and version
 * — and, when asked, each target's share of it kept as the keys it put into that map and took out, so
 * that the map the estate's scans make can be made again from memory, <b>in the order it iterates</b>.
 *
 * <p><b>Why the keys' history and not the entries.</b> The unpaged inventory has always come in a hash
 * map's order, and a client written against 0.11.0 sees no byte move. That order is
 * a function of the keys the map holds, of the order they entered it, and of how large it ever grew — a
 * component the build completed takes the scanner's key out before putting its own, and a key that
 * collided in a bucket stays behind the one that came first. Kept as entries, a target's inventory could
 * be listed, but not in that order: sorted, it would change every answer; put into a fresh map in some
 * order of ours, it would change the answer whenever two keys share a bucket. Replaying every key's
 * entries and exits, in the order the estate's read made them, rebuilds the very same map, whatever the
 * keys, the buckets, or the bins the map turned into trees.
 *
 * <p><b>That order does not depend on what else was read.</b> The read goes through the scans by
 * identifier — their SBOMs, then their component rows by scan and row, then their licence findings by
 * scan and finding — and a key begins with its target, so one target's keys never meet another's. Each
 * step is therefore stamped with its phase, its scan and its place among that scan's steps of the phase,
 * which is the same whichever targets were read beside it; the estate's sequence is the merge of its
 * targets' on that stamp.
 */
final class LicenceLedger {

    /** The read's three passes, in the order it makes them. */
    static final byte SBOM = 0;
    static final byte COMPONENTS = 1;
    static final byte FINDINGS = 2;

    /** Set on a step's phase when the step took a key out. */
    private static final byte REMOVAL = 0x10;

    /**
     * What an entry holds before the policy in force judges it and its target is named: both are read
     * at each answer, so a policy changed or a repository renamed is seen at once.
     *
     * @param rawVersion the version as read, null when none — the key holds it as {@code ""} and the
     *     entry as {@code "unknown"}
     */
    record Raw(String name, String rawVersion, String purl, String license, Scan scan) {

        String version() {
            return rawVersion != null ? rawVersion : "unknown";
        }

        /** The key it was filed under: its target, its name, its version — as the read always built it. */
        String key() {
            return scan.keyPrefix() + name + ":" + (rawVersion != null ? rawVersion : "");
        }
    }

    /** The columns of a scan an entry needs — whose it is and what it is named after — never its SBOM. */
    record Scan(long id, Long repoId, Long containerId) {

        String targetKind() {
            return repoId != null ? "repository" : (containerId != null ? "container" : "general");
        }

        Long targetId() {
            return repoId != null ? repoId : containerId;
        }

        /** The target the scan is attributed to, null for one attached to none. */
        ScanTarget owner() {
            if (repoId != null) {
                return new ScanTarget.Repository(repoId);
            }
            return containerId == null ? null : new ScanTarget.Container(containerId);
        }

        String keyPrefix() {
            return targetKind() + ":" + targetId() + ":";
        }
    }

    /**
     * One target's share of the inventory: the steps that put a key into the map or took one out, in
     * their order, each with the entry its key holds once the read is over.
     *
     * <p>Parallel arrays rather than a record a step: a target of 250 components makes about as many
     * steps, kept for as long as its scans do not move.
     */
    record Kept(long[] scans, int[] places, byte[] phases, Raw[] entries) {

        int size() {
            return scans.length;
        }

        /** Whether step {@code i} comes before step {@code j} of {@code other} in the read. */
        boolean before(int i, Kept other, int j) {
            int phase = Byte.compare((byte) (phases[i] & ~REMOVAL), (byte) (other.phases[j] & ~REMOVAL));
            if (phase != 0) {
                return phase < 0;
            }
            int scan = Long.compare(scans[i], other.scans[j]);
            if (scan != 0) {
                return scan < 0;
            }
            return places[i] < other.places[j];
        }
    }

    private final Map<String, Raw> entries = new HashMap<>();
    /** Each target's steps — the scans attached to none under null — or null when the read is not kept. */
    private final Map<ScanTarget, Journal> journals;
    private final Map<String, Raw> lastRemoved;

    private byte phase = -1;
    private long scan = -1;
    private int place;

    private LicenceLedger(boolean keeping) {
        this.journals = keeping ? new HashMap<>() : null;
        this.lastRemoved = keeping ? new HashMap<>() : null;
    }

    /** A read that answers once. */
    static LicenceLedger read() {
        return new LicenceLedger(false);
    }

    /** A read whose targets' shares are kept — {@link #kept()}. */
    static LicenceLedger keeping() {
        return new LicenceLedger(true);
    }

    Raw get(String key) {
        return entries.get(key);
    }

    boolean containsKey(String key) {
        return entries.containsKey(key);
    }

    void put(byte phase, Raw entry) {
        String key = entry.key();
        boolean entering = !entries.containsKey(key);
        entries.put(key, entry);
        step(phase, entry.scan(), key, entering, false);
    }

    /** Takes out the entry a scan of {@code scan}'s target filed under {@code key}, if there is one. */
    Raw remove(byte phase, Scan scan, String key) {
        Raw removed = entries.remove(key);
        if (removed != null && lastRemoved != null) {
            lastRemoved.put(key, removed);
        }
        step(phase, scan, key, removed != null, true);
        return removed;
    }

    /** The entries, in the map's order. */
    Collection<Raw> values() {
        return entries.values();
    }

    /**
     * Places are counted for every step, kept or not, so that a step's place depends only on its scan's
     * own steps in that phase — which the read makes in one run, its rows coming in scan order.
     */
    private void step(byte phase, Scan scan, String key, boolean structural, boolean removal) {
        if (phase != this.phase || scan.id() != this.scan) {
            this.phase = phase;
            this.scan = scan.id();
            place = 0;
        }
        int at = place++;
        if (journals == null || !structural) {
            // A key put again keeps its place in the map: only the value moves, which the kept entry carries.
            return;
        }
        journals.computeIfAbsent(scan.owner(), ignored -> new Journal())
                .add(scan.id(), at, (byte) (removal ? phase | REMOVAL : phase), key);
    }

    /**
     * Each target's share, the scans attached to none under a null key — compact, its strings shared
     * where they repeat, and holding nothing of the scans but their identifiers and targets.
     */
    Map<ScanTarget, Kept> kept() {
        if (journals == null) {
            throw new IllegalStateException("this read keeps nothing");
        }
        Map<String, String> strings = new HashMap<>();
        Map<Scan, Scan> scans = new HashMap<>();
        Map<Raw, Raw> compacted = new IdentityHashMap<>();
        Map<ScanTarget, Kept> kept = new HashMap<>();
        journals.forEach((owner, journal) -> {
            Raw[] held = new Raw[journal.size];
            for (int i = 0; i < journal.size; i++) {
                String key = journal.keys.get(i);
                Raw entry = entries.containsKey(key) ? entries.get(key) : lastRemoved.get(key);
                held[i] = compacted.computeIfAbsent(entry, raw -> new Raw(
                        shared(strings, raw.name()),
                        shared(strings, raw.rawVersion()),
                        shared(strings, raw.purl()),
                        shared(strings, raw.license()),
                        scans.computeIfAbsent(raw.scan(), scan -> scan)));
            }
            kept.put(owner, new Kept(
                    Arrays.copyOf(journal.scans, journal.size),
                    Arrays.copyOf(journal.places, journal.size),
                    Arrays.copyOf(journal.phases, journal.size),
                    held));
        });
        return kept;
    }

    private static String shared(Map<String, String> strings, String value) {
        return value == null ? null : strings.computeIfAbsent(value, same -> same);
    }

    /**
     * The map the read of these targets' scans makes, rebuilt from their shares: the same keys, the same
     * entries, iterating in the same order — see the class comment.
     */
    static Map<String, Raw> replay(Collection<Kept> shares) {
        List<Kept> nonEmpty = new ArrayList<>();
        int steps = 0;
        for (Kept share : shares) {
            if (share.size() > 0) {
                nonEmpty.add(share);
                steps += share.size();
            }
        }
        // Each share is in the read's order already; the estate's is their merge.
        int[] cursor = new int[nonEmpty.size()];
        PriorityQueue<Integer> next = new PriorityQueue<>(Math.max(1, nonEmpty.size()), (a, b) -> {
            if (a.equals(b)) {
                return 0;
            }
            return nonEmpty.get(a).before(cursor[a], nonEmpty.get(b), cursor[b]) ? -1 : 1;
        });
        for (int share = 0; share < nonEmpty.size(); share++) {
            next.add(share);
        }
        Map<String, Raw> map = new HashMap<>();
        for (int done = 0; done < steps; done++) {
            int share = next.poll();
            Kept kept = nonEmpty.get(share);
            int at = cursor[share];
            Raw entry = kept.entries()[at];
            if ((kept.phases()[at] & REMOVAL) != 0) {
                map.remove(entry.key());
            } else {
                map.put(entry.key(), entry);
            }
            cursor[share] = at + 1;
            if (cursor[share] < kept.size()) {
                next.add(share);
            }
        }
        return map;
    }

    /** One target's steps while the read goes on. */
    private static final class Journal {
        long[] scans = new long[16];
        int[] places = new int[16];
        byte[] phases = new byte[16];
        final List<String> keys = new ArrayList<>();
        int size;

        void add(long scan, int place, byte phase, String key) {
            if (size == scans.length) {
                scans = Arrays.copyOf(scans, size * 2);
                places = Arrays.copyOf(places, size * 2);
                phases = Arrays.copyOf(phases, size * 2);
            }
            scans[size] = scan;
            places[size] = place;
            phases[size] = phase;
            keys.add(key);
            size++;
        }
    }
}
