-- The tracker deliveries already acted on, by the hash of their body.
--
-- A signed GitHub delivery could be captured and replayed later: the HMAC covers the body and
-- nothing records that the body was seen, so a "closed" event sent again months on queued the same
-- decision again. The delivery identifier is no help — it travels in a header the signature does
-- not cover, and a replay can simply change it. The body can not change without breaking the
-- signature, and two real events never share one: each carries its own timestamps.
--
-- Kept thirty days, purged on write; the index serves that purge.

create table t_webhook_delivery (
    body_hash varchar(64) not null primary key,
    provider varchar(16) not null,
    received_at datetime(6) not null
);

create index idx_webhook_delivery_received on t_webhook_delivery (received_at);
