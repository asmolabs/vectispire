package com.asmolabs.vectispire.common.domain.checklists;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * How the items of a new version relate to the previous version's — which decides what happens to
 * a project's answers when it moves to the new version (decision 0032 §4).
 *
 * <ul>
 *   <li>same key, same content digest — {@link Unchanged}: the answer is carried as current;
 *   <li>same key, another digest — {@link Changed}: the KPI, the evidence, the binding or the
 *       wording moved, and a carried answer waits for somebody to confirm it;
 *   <li>a key only the new version has — {@link Added}: the line starts unanswered;
 *   <li>a key only the previous version has — {@link Removed}: its answer stays where it was given.
 * </ul>
 *
 * <p><b>Paired by hand.</b> A control reworded is, to a key derived from its text, one line removed
 * and another added — and its answer would be left behind. The importer may say "same control" for
 * an added item and a removed one: the new item takes the old key and is {@link Changed}, always,
 * since whatever made the keys differ is a change somebody must look at. The pairs are recorded with
 * the version; {@link #next()} is the new version's items with the keys they are stored under.
 *
 * @param changes the new version's items in their order, then the removed ones in theirs
 * @param next the new version's items, re-keyed where paired by hand
 */
public record VersionPairing(List<Change> changes, List<ChecklistItem> next) {

    public VersionPairing {
        changes = List.copyOf(changes);
        next = List.copyOf(next);
    }

    /** What became of one item between the two versions. */
    public sealed interface Change permits Unchanged, Changed, Added, Removed {}

    public record Unchanged(ChecklistItem previous, ChecklistItem next) implements Change {}

    /** @param pairedByHand the importer said these two are one control; {@code next} carries the old key */
    public record Changed(ChecklistItem previous, ChecklistItem next, boolean pairedByHand) implements Change {}

    public record Added(ChecklistItem next) implements Change {}

    public record Removed(ChecklistItem previous) implements Change {}

    /** "The new version's item {@code added} is the previous version's {@code removed}, reworded." */
    public record ManualPair(ItemKey added, ItemKey removed) {

        public ManualPair {
            Objects.requireNonNull(added, "added");
            Objects.requireNonNull(removed, "removed");
        }
    }

    /**
     * Pairs two versions' items.
     *
     * @param byHand pairs the importer made; each must join an item only the new version has with
     *     one only the previous version has, and each item may be paired once
     * @throws InvalidTemplateException a pair naming an item that is not added or not removed, or an
     *     item paired twice
     */
    public static VersionPairing of(List<ChecklistItem> previous, List<ChecklistItem> next, List<ManualPair> byHand) {
        Map<ItemKey, ChecklistItem> before = index(previous);
        Map<ItemKey, ChecklistItem> after = index(next);

        Map<ItemKey, ItemKey> renamed = new LinkedHashMap<>();
        Set<ItemKey> claimed = new HashSet<>();
        for (ManualPair pair : byHand) {
            if (!after.containsKey(pair.added()) || before.containsKey(pair.added())) {
                throw new InvalidTemplateException("An item paired by hand must be one the new version adds; "
                        + describe(pair.added(), after) + " is not.");
            }
            if (!before.containsKey(pair.removed()) || after.containsKey(pair.removed())) {
                throw new InvalidTemplateException("An item paired by hand must be one the new version removes; "
                        + describe(pair.removed(), before) + " is not.");
            }
            if (renamed.putIfAbsent(pair.added(), pair.removed()) != null) {
                throw new InvalidTemplateException(describe(pair.added(), after) + " is paired twice.");
            }
            if (!claimed.add(pair.removed())) {
                throw new InvalidTemplateException(describe(pair.removed(), before) + " is paired twice.");
            }
        }

        List<Change> changes = new ArrayList<>();
        List<ChecklistItem> rekeyed = new ArrayList<>();
        for (ChecklistItem item : next) {
            ItemKey oldKey = renamed.get(item.key());
            if (oldKey != null) {
                ChecklistItem paired = item.withKey(oldKey);
                changes.add(new Changed(before.get(oldKey), paired, true));
                rekeyed.add(paired);
                continue;
            }
            rekeyed.add(item);
            ChecklistItem was = before.get(item.key());
            if (was == null) {
                changes.add(new Added(item));
            } else if (was.contentDigest().equals(item.contentDigest())) {
                changes.add(new Unchanged(was, item));
            } else {
                changes.add(new Changed(was, item, false));
            }
        }
        for (ChecklistItem item : previous) {
            if (!after.containsKey(item.key()) && !claimed.contains(item.key())) {
                changes.add(new Removed(item));
            }
        }
        return new VersionPairing(changes, rekeyed);
    }

    private static Map<ItemKey, ChecklistItem> index(List<ChecklistItem> items) {
        Map<ItemKey, ChecklistItem> byKey = new LinkedHashMap<>();
        for (ChecklistItem item : items) {
            if (byKey.putIfAbsent(item.key(), item) != null) {
                throw new IllegalArgumentException("A version holds one item per key; " + item.key() + " twice");
            }
        }
        return byKey;
    }

    /** An item as the importer saw it — its row — rather than a key they never saw. */
    private static String describe(ItemKey key, Map<ItemKey, ChecklistItem> items) {
        ChecklistItem item = items.get(key);
        return item == null ? "an item that does not exist" : "the item on row " + item.row();
    }
}
