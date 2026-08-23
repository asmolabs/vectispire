/**
 * Nothing is configured across projects from here.
 *
 * Shared settings live in the `zanshin.java-conventions` plugin, which each module applies
 * for itself. Configuring subprojects from the root would work today and would rule out
 * Gradle's isolated-projects mode, which is where the tool is going.
 */
plugins {
    base
}
