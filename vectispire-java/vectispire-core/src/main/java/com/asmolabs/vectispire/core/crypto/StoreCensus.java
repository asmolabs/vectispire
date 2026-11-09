package com.asmolabs.vectispire.core.crypto;

/**
 * How the values of one sealed store stand against the configured keys.
 *
 * @param store what it holds, as an operator names it
 * @param reseal the gesture that moves a value still under a previous key to the current one
 * @param current sealed under the current key
 * @param previousKey readable only through {@code VECTISPIRE_PREVIOUS_ENCRYPTION_KEYS}: removing that key
 *     leaves these unreadable
 * @param unreadable no configured key opens them
 * @param clear stored before they were encrypted, and still used as they are
 */
public record StoreCensus(
        String store, String reseal, long current, long previousKey, long unreadable, long clear) {

    /** Whether this store still needs a previous key. */
    public boolean dependsOnPreviousKey() {
        return previousKey > 0;
    }

    /** Counts values one at a time, by what {@link EncryptionService#sealOf} says of each. */
    public static final class Counter {

        private final String store;
        private final String reseal;
        private long current;
        private long previousKey;
        private long unreadable;
        private long clear;

        public Counter(String store, String reseal) {
            this.store = store;
            this.reseal = reseal;
        }

        public Counter add(EncryptionService.Seal seal) {
            switch (seal) {
                case CURRENT -> current++;
                case PREVIOUS_KEY -> previousKey++;
                case UNREADABLE -> unreadable++;
                case CLEAR -> clear++;
                case EMPTY -> {
                    // Nothing stored: nothing to re-seal.
                }
            }
            return this;
        }

        public StoreCensus done() {
            return new StoreCensus(store, reseal, current, previousKey, unreadable, clear);
        }
    }
}
