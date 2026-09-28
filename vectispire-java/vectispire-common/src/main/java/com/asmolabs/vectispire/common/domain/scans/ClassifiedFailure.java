package com.asmolabs.vectispire.common.domain.scans;

/**
 * A failure that knows whether it would happen again — implemented by the exceptions that stop a
 * scan before a result exists and carry a typed diagnosis: a clone's, a task's that would not open, the
 * control plane's refusal to build a task.
 *
 * <p>An interface rather than a base class, because those exceptions already have their own parents
 * — an {@code IllegalStateException} that callers catch as such — and the kind has to reach
 * {@link FailureKind#of} through all of them.
 */
public interface ClassifiedFailure {

    /** Never null for a failure that means it; a null reads as undeclared, hence transient. */
    FailureKind failureKind();
}
