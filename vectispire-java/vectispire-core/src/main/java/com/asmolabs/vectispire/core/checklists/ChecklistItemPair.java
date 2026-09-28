package com.asmolabs.vectispire.core.checklists;

/**
 * "The new version's item {@code added} is the previous version's item {@code removed}, reworded"
 * (decision 0032 §4): the new item takes the old key, and a project's answer follows it, to be
 * confirmed. Keys as the preview shows them — {@code text:…} or {@code id:…}.
 */
public record ChecklistItemPair(String added, String removed) {}
