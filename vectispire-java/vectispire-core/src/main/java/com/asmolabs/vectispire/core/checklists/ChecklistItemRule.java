package com.asmolabs.vectispire.core.checklists;

/**
 * The rule one line of a draft is to be measured by (decision 0032 §6): the line named by its key as
 * the version shows it, and the rule — or null, to unbind the line.
 */
public record ChecklistItemRule(String itemKey, ChecklistRuleForm rule) {}
