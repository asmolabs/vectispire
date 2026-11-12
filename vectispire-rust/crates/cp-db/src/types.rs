//! The column types whose Rust side is not obvious, read and written as Hibernate reads and writes them.
//!
//! | schema (MySQL / PostgreSQL) | Hibernate | here |
//! |---|---|---|
//! | `${ts}`: `datetime(6)` / `timestamp with time zone` | `Instant`, UTC | `time::OffsetDateTime` — sqlx writes it as UTC on both; take it from [`now`] |
//! | `${bool}`, and older `boolean`: `bit(1)` or `tinyint(1)` / `boolean` | `boolean` | `bool` — sqlx reads both MySQL spellings |
//! | `char(36)` / `character(36)` ids | `UUID` as `@JdbcTypeCode(CHAR)` | [`TextUuid`] |
//! | `${text}`, `text`: `longtext`, `text` / `text` | `String`, `LONGVARCHAR` | `String` |
//! | `${bytes}`: `longblob` / `bytea` | `byte[]`, `LONGVARBINARY` | `Vec<u8>` |
//! | `${double}`: `double` / `double precision` | `double` | `f64` |
//! | `${id}`: `bigint` identity | `Long` | `i64` |
//!
//! **sqlx's own `Uuid` is not used, on purpose.** On MySQL it binds sixteen bytes, and a `char(36)`
//! column would store them as text that is no identifier at all — on a row every other reader then
//! fails to find. The crate's `uuid` feature is off so that it cannot be bound by accident.

use sqlx::encode::IsNull;
use sqlx::error::BoxDynError;
use sqlx::mysql::{MySql, MySqlTypeInfo, MySqlValueRef};
use sqlx::postgres::{PgArgumentBuffer, PgTypeInfo, PgValueRef, Postgres};
use sqlx::{Decode, Encode, Type};
use time::OffsetDateTime;
use uuid::Uuid;

/// The current instant at the precision both engines keep: microseconds.
///
/// `CoreConfiguration.clock()` ticks in microseconds for the reason this does: an instant taken at
/// nanoseconds, stored, and also written into a response or a signed document then disagrees with
/// itself once read back — Linux clocks read nanoseconds, so the defect showed in CI and not on a Mac.
pub fn now() -> OffsetDateTime {
    to_microseconds(OffsetDateTime::now_utc())
}

/// `instant`, truncated to the microsecond — what `datetime(6)` and `timestamp` store.
pub fn to_microseconds(instant: OffsetDateTime) -> OffsetDateTime {
    let nanoseconds = instant.nanosecond();
    instant.replace_nanosecond(nanoseconds - nanoseconds % 1_000).unwrap_or(instant)
}

/// A UUID stored as its 36-character text, lower case with hyphens — `UUID.toString()`, which is what
/// Hibernate writes into the `char(36)` ids (`t_audit_log`, `t_api_key`, `t_agent`…).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TextUuid(pub Uuid);

impl std::fmt::Display for TextUuid {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.as_hyphenated().fmt(formatter)
    }
}

fn parse(text: &str) -> Result<TextUuid, BoxDynError> {
    // `Uuid::parse_str` also takes the simple, braced and URN forms; a char(36) column holds the
    // hyphenated one, and anything else in it is a row this side did not write and should not guess at.
    if text.len() != 36 {
        return Err(format!("a char(36) identifier holds {} characters", text.len()).into());
    }
    Ok(TextUuid(Uuid::try_parse(text)?))
}

impl Type<MySql> for TextUuid {
    fn type_info() -> MySqlTypeInfo {
        <str as Type<MySql>>::type_info()
    }

    fn compatible(ty: &MySqlTypeInfo) -> bool {
        <str as Type<MySql>>::compatible(ty)
    }
}

impl Encode<'_, MySql> for TextUuid {
    fn encode_by_ref(&self, buf: &mut Vec<u8>) -> Result<IsNull, BoxDynError> {
        <String as Encode<MySql>>::encode(self.to_string(), buf)
    }
}

impl<'r> Decode<'r, MySql> for TextUuid {
    fn decode(value: MySqlValueRef<'r>) -> Result<TextUuid, BoxDynError> {
        parse(<&str as Decode<MySql>>::decode(value)?)
    }
}

impl Type<Postgres> for TextUuid {
    fn type_info() -> PgTypeInfo {
        PgTypeInfo::with_name("bpchar")
    }

    fn compatible(ty: &PgTypeInfo) -> bool {
        <str as Type<Postgres>>::compatible(ty)
    }
}

impl Encode<'_, Postgres> for TextUuid {
    fn encode_by_ref(&self, buf: &mut PgArgumentBuffer) -> Result<IsNull, BoxDynError> {
        <String as Encode<Postgres>>::encode(self.to_string(), buf)
    }
}

impl<'r> Decode<'r, Postgres> for TextUuid {
    fn decode(value: PgValueRef<'r>) -> Result<TextUuid, BoxDynError> {
        parse(<&str as Decode<Postgres>>::decode(value)?)
    }
}

/// An instant in a column spelled before the placeholders ([`crate::parity::ColumnType::LegacyTimestamp`]):
/// on PostgreSQL `timestamp without time zone` holding UTC, which sqlx's `OffsetDateTime` refuses to
/// read; everywhere else exactly an `OffsetDateTime`.
///
/// Written as `timestamp with time zone`, which PostgreSQL converts into such a column in the session's
/// zone — UTC, the zone sqlx opens every session in and the zone pgjdbc wrote these values in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UtcInstant(pub OffsetDateTime);

impl Type<MySql> for UtcInstant {
    fn type_info() -> MySqlTypeInfo {
        <OffsetDateTime as Type<MySql>>::type_info()
    }

    fn compatible(ty: &MySqlTypeInfo) -> bool {
        <OffsetDateTime as Type<MySql>>::compatible(ty)
    }
}

impl Encode<'_, MySql> for UtcInstant {
    fn encode_by_ref(&self, buf: &mut Vec<u8>) -> Result<IsNull, BoxDynError> {
        <OffsetDateTime as Encode<MySql>>::encode(self.0, buf)
    }
}

impl<'r> Decode<'r, MySql> for UtcInstant {
    fn decode(value: MySqlValueRef<'r>) -> Result<UtcInstant, BoxDynError> {
        Ok(UtcInstant(<OffsetDateTime as Decode<MySql>>::decode(value)?))
    }
}

impl Type<Postgres> for UtcInstant {
    fn type_info() -> PgTypeInfo {
        <OffsetDateTime as Type<Postgres>>::type_info()
    }

    fn compatible(ty: &PgTypeInfo) -> bool {
        <OffsetDateTime as Type<Postgres>>::compatible(ty)
            || <time::PrimitiveDateTime as Type<Postgres>>::compatible(ty)
    }
}

impl Encode<'_, Postgres> for UtcInstant {
    fn encode_by_ref(&self, buf: &mut PgArgumentBuffer) -> Result<IsNull, BoxDynError> {
        <OffsetDateTime as Encode<Postgres>>::encode(self.0, buf)
    }
}

impl<'r> Decode<'r, Postgres> for UtcInstant {
    fn decode(value: PgValueRef<'r>) -> Result<UtcInstant, BoxDynError> {
        use sqlx::{TypeInfo, ValueRef};
        if value.type_info().name() == "TIMESTAMP" {
            let local = <time::PrimitiveDateTime as Decode<Postgres>>::decode(value)?;
            return Ok(UtcInstant(local.assume_utc()));
        }
        Ok(UtcInstant(<OffsetDateTime as Decode<Postgres>>::decode(value)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_instant_keeps_its_microseconds_and_loses_its_nanoseconds() {
        let instant = OffsetDateTime::from_unix_timestamp_nanos(1_760_000_000_123_456_789).unwrap();
        assert_eq!(to_microseconds(instant).unix_timestamp_nanos(), 1_760_000_000_123_456_000);
        assert_eq!(now().nanosecond() % 1_000, 0);
    }

    #[test]
    fn a_uuid_is_its_hyphenated_lower_case_text() {
        let id = TextUuid(Uuid::from_u128(0x0123_4567_89ab_cdef_0123_4567_89ab_cdef));
        assert_eq!(id.to_string(), "01234567-89ab-cdef-0123-456789abcdef");
        assert_eq!(parse("01234567-89AB-CDEF-0123-456789ABCDEF").unwrap(), id);
        assert!(parse("0123456789abcdef0123456789abcdef").is_err(), "the simple form is not what the column holds");
    }
}
