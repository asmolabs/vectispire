package com.asmolabs.vectispire.core.crypto;

import java.util.List;

/**
 * What a module keeps sealed under {@code ENCRYPTION_KEY}, and which key each of its values is
 * sealed under now.
 *
 * <p><b>A rotation is finished when no store reports a value under a previous key</b>, and only
 * the stores know their rows. The procedure used to name three of them — SSH keys, clone tokens,
 * forge connections — while the signing key, the second factors and the integration secrets went
 * on reading under the old key: removing it then disabled sign-in for every account with a second
 * factor, stopped every signature, and dropped the SIEM's authorization header without a word.
 * Each module that seals something answers here; {@link EncryptionCensus} gathers them in one
 * place, and a module that seals a new kind of value adds its line or the census is wrong.
 */
public interface SealedStore {

    /** One line per kind of value this module keeps sealed. */
    List<StoreCensus> census();
}
