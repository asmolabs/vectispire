package com.asmolabs.vectispire.common.domain.agents;

import java.util.OptionalInt;
import java.util.regex.Pattern;

/**
 * The version of the contract between Vectispire and its agents, and the range of them the control
 * plane serves.
 *
 * <p><b>An agent on an older version must be able to refuse cleanly.</b> Without this number
 * an agent speaking the old protocol receives a task it misreads and returns a plausible but
 * wrong result — a scan declaring a repository clean because it did not understand what it was
 * asked to look for.
 *
 * <p><b>What the number means.</b> A whole number, one more each time the control plane starts
 * handing an agent something the agent of the previous number would misread or could not do — a new
 * envelope, a new mandatory field, a step it must now run. It is not the release's number: most
 * releases leave it where it is. Adding an optional field is not a break: an agent that ignores it
 * does exactly what it did before. An agent announces {@link #VERSION}, the one it was built with.
 *
 * <p><b>The control plane serves a range</b>, {@link #OLDEST_SERVED} to {@link #CURRENT}, because
 * decision 0043 §2 promises it serves the agent of the previous minor release: on Kubernetes the
 * control plane and the agents roll at different moments, and a refusal during that window stops
 * every scan. A change the previous agent would not understand is therefore made in <b>two
 * releases</b>: the first moves {@link #CURRENT} up and keeps {@link #OLDEST_SERVED} where it was,
 * and the control plane hands each agent the form its announced number reads (it is on the agent's
 * row from the hello on); the next raises {@link #OLDEST_SERVED} and deletes the old form. A change
 * that cannot be made in two steps is not made in one.
 *
 * <p><b>Why this is written down.</b> 0.11.0 started sealing credentials in the {@code v2} envelope,
 * which no 0.10 agent opens, and left the number at 1: both agents announced the same contract, the
 * hello accepted both, and the older one failed later on work it could not read — the loud refusal
 * this number exists for never happened. Under this rule that envelope was contract 2, served beside
 * contract 1 for a release. A 0.10 agent still announces 1 and the range still accepts it; it is two
 * minors behind, outside the promise, and the first number moved after this one retires it.
 *
 * <p>An agent newer than the control plane is refused too: the supported order is the control plane
 * first, then its agents, and a control plane cannot know what a number it has never heard of asks.
 * {@code AgentContractTest} holds the range's shape; the {@code previous-agent} CI job runs the last
 * release's agent against the control plane of every commit, which is what decides whether an agent
 * that ignores a new field is still correct — not the reviewer's memory.
 */
public final class AgentContract {

    private AgentContract() {}

    /** The contract this build speaks, and the one its agent announces. */
    public static final int CURRENT = 1;

    /**
     * The oldest contract the control plane still serves. Equal to {@link #CURRENT} until a change
     * makes the two differ, and never raised in the release that moves {@link #CURRENT}.
     */
    public static final int OLDEST_SERVED = 1;

    /** {@link #CURRENT} as the hello carries it: a string on the wire, compared as a number here. */
    public static final String VERSION = String.valueOf(CURRENT);

    /** No sign, no leading zero, no fraction: "1.1" and "01" are not contracts anybody announced. */
    private static final Pattern NUMBER = Pattern.compile("[1-9][0-9]{0,8}");

    /** The number an agent announced, or empty when it is no contract number at all. */
    public static OptionalInt parse(String announced) {
        if (announced == null) {
            return OptionalInt.empty();
        }
        String trimmed = announced.trim();
        return NUMBER.matcher(trimmed).matches() ? OptionalInt.of(Integer.parseInt(trimmed)) : OptionalInt.empty();
    }

    /**
     * Is this contract one the control plane serves?
     *
     * <p>Within the range and nothing looser. "Same major" or "anything up to ours" looks welcoming
     * and moves the question elsewhere: every number below {@link #OLDEST_SERVED} is a form whose code
     * was deleted, and an agent reading it would be handed work it misreads.
     */
    public static boolean isCompatible(String announced) {
        OptionalInt number = parse(announced);
        return number.isPresent() && number.getAsInt() >= OLDEST_SERVED && number.getAsInt() <= CURRENT;
    }

    /** The range in words, for a refusal: "1", or "1 to 2". */
    public static String served() {
        return OLDEST_SERVED == CURRENT ? VERSION : OLDEST_SERVED + " to " + CURRENT;
    }

    /**
     * What an operator does about an agent outside the range — two different fixes, so two sentences.
     */
    public static String remedy(String announced) {
        OptionalInt number = parse(announced);
        return number.isPresent() && number.getAsInt() > CURRENT
                ? "Upgrade the control plane first, then its agents."
                : "Update the agent.";
    }
}
