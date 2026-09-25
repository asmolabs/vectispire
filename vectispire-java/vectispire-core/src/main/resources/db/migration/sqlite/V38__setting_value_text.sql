-- A setting's value becomes `text`: an encrypted credential no longer fits in 255 characters.
--
-- Four credentials are stored in this table, encrypted: the tracker token, the webhook signing
-- secret, the inbound webhook secret and the OpenAI-compatible key. A ciphertext is "v2:" followed
-- by the Base64 of a 12-byte nonce, the text and a 16-byte tag, so it is about four thirds of the
-- secret plus forty characters — and at varchar(255) every secret longer than about 160 characters
-- was refused by the database at the write, as a 500. An Atlassian API token is 192 characters and
-- an OpenAI `sk-proj-` key longer still: the two credentials most people paste were the two that
-- could not be saved. V32 fixed the same arithmetic for the SIEM header.
--
-- `text` rather than a longer varchar because the column holds both kinds of value — free text
-- such as the ISMS scope statement, and ciphertext — and neither has a natural width. What bounds
-- them now is the service, which refuses a value before the database has to: see
-- `SettingType.TEXT` and `SettingsAdministrationService`.

-- Nothing to alter on SQLite, as in V32: it does not enforce a varchar length, so the ciphertext
-- already fits, and changing a column type there means rebuilding the table for no effect.

select 1;
