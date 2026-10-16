//! A migration's text cut into the statements sent to the server, one at a time, as Flyway's parsers
//! cut it.
//!
//! **Only what changes where a statement ends is understood**: comments, quoted strings and
//! identifiers, PostgreSQL's dollar-quoted bodies, and MySQL's `DELIMITER` directive (V65 uses it to
//! create a procedure). Everything else is passed to the server as written. The cut is checked on every
//! migration of both engines by applying them to real servers (`tests/engines.rs`) and comparing the
//! schema with the one Flyway produced.
//!
//! **A statement PostgreSQL refuses inside a transaction is refused here** (`CREATE INDEX
//! CONCURRENTLY`, `VACUUM`, …). Flyway detects those and runs the migration outside a transaction; no
//! migration of this project has one, and the first to need one should be ported on purpose rather
//! than run with a transaction it cannot have.

use crate::Error;
use crate::dialect::Engine;

/// The statements of `sql`, in order, without their delimiters and without the ones that hold only
/// comments and blanks.
pub fn statements(engine: Engine, script: &str, sql: &str) -> Result<Vec<String>, Error> {
    let statements = match engine {
        Engine::MySql => split(sql, Dialect::MySql),
        Engine::PostgreSql => split(sql, Dialect::PostgreSql),
    };
    let statements = statements.map_err(|reason| Error::Unparsable { script: script.to_owned(), reason })?;
    if engine == Engine::PostgreSql
        && let Some(statement) = statements.iter().find(|statement| outside_transaction_only(statement))
    {
        return Err(Error::NonTransactional { script: script.to_owned(), statement: first_line(statement) });
    }
    Ok(statements)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Dialect {
    MySql,
    PostgreSql,
}

fn split(sql: &str, dialect: Dialect) -> Result<Vec<String>, String> {
    let mut statements = Vec::new();
    let mut current = String::new();
    let mut delimiter = String::from(";");
    let mut chars = sql.char_indices().peekable();
    let mut at_line_start = true;

    while let Some((index, c)) = chars.next() {
        // MySQL's client directive, not SQL: `DELIMITER //` on its own line changes what ends a
        // statement, and the line itself is never sent.
        if dialect == Dialect::MySql && at_line_start && only_comments(&current, dialect) {
            let line_end = sql[index..].find('\n').map_or(sql.len(), |offset| index + offset);
            let line = &sql[index..line_end];
            if let Some(rest) = strip_keyword(line.trim_start(), "delimiter") {
                let new = rest.trim();
                if new.is_empty() {
                    return Err("DELIMITER without a delimiter".to_owned());
                }
                delimiter = new.to_owned();
                current.clear();
                while chars.peek().is_some_and(|(next, _)| *next < line_end) {
                    chars.next();
                }
                at_line_start = false;
                continue;
            }
        }
        at_line_start = c == '\n';

        match c {
            '-' if sql[index..].starts_with("--") && comment_dash_allowed(sql, index, dialect) => {
                copy_to_line_end(&mut current, &mut chars, sql, index);
                at_line_start = true;
            }
            '#' if dialect == Dialect::MySql => {
                copy_to_line_end(&mut current, &mut chars, sql, index);
                at_line_start = true;
            }
            '/' if sql[index..].starts_with("/*") => {
                let end = block_comment_end(sql, index, dialect).ok_or("an unterminated /* comment")?;
                current.push_str(&sql[index..end]);
                while chars.peek().is_some_and(|(next, _)| *next < end) {
                    chars.next();
                }
            }
            '\'' => quoted(&mut current, &mut chars, index, '\'', dialect == Dialect::MySql)?,
            '"' => quoted(&mut current, &mut chars, index, '"', dialect == Dialect::MySql)?,
            '`' if dialect == Dialect::MySql => quoted(&mut current, &mut chars, index, '`', false)?,
            '$' if dialect == Dialect::PostgreSql && dollar_tag(sql, index).is_some() => {
                let tag = dollar_tag(sql, index).unwrap_or_default();
                let body_start = index + tag.len();
                let close = sql[body_start..].find(&tag).ok_or("an unterminated dollar-quoted body")?;
                let end = body_start + close + tag.len();
                current.push_str(&sql[index..end]);
                while chars.peek().is_some_and(|(next, _)| *next < end) {
                    chars.next();
                }
            }
            _ if sql[index..].starts_with(delimiter.as_str()) => {
                let end = index + delimiter.len();
                while chars.peek().is_some_and(|(next, _)| *next < end) {
                    chars.next();
                }
                push(&mut statements, &mut current, dialect);
            }
            _ => current.push(c),
        }
    }
    push(&mut statements, &mut current, dialect);
    Ok(statements)
}

/// `-- x` is a comment on both engines; MySQL also requires the dashes to be followed by a blank or
/// the end of the line, which is what keeps `a--1` an expression there.
fn comment_dash_allowed(sql: &str, index: usize, dialect: Dialect) -> bool {
    match dialect {
        Dialect::PostgreSql => true,
        Dialect::MySql => sql[index + 2..].chars().next().is_none_or(char::is_whitespace),
    }
}

/// Where a `/* … */` comment starting at `index` ends; PostgreSQL's nest, MySQL's do not.
fn block_comment_end(sql: &str, index: usize, dialect: Dialect) -> Option<usize> {
    let mut depth = 0usize;
    let mut position = index;
    while position < sql.len() {
        let rest = &sql[position..];
        if rest.starts_with("/*") && (depth == 0 || dialect == Dialect::PostgreSql) {
            depth += 1;
            position += 2;
        } else if rest.starts_with("*/") {
            depth -= 1;
            position += 2;
            if depth == 0 {
                return Some(position);
            }
        } else {
            position += rest.chars().next().map_or(1, char::len_utf8);
        }
    }
    None
}

/// `$tag$` or `$$` at `index`, if one starts there.
fn dollar_tag(sql: &str, index: usize) -> Option<String> {
    let rest = &sql[index + 1..];
    let end = rest.find('$')?;
    let tag = &rest[..end];
    let valid = tag.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        && !tag.chars().next().is_some_and(|c| c.is_ascii_digit());
    valid.then(|| format!("${tag}$"))
}

/// Copies a line comment, leaving its `\n` to be read next so that it still starts a line.
fn copy_to_line_end(
    current: &mut String,
    chars: &mut std::iter::Peekable<std::str::CharIndices<'_>>,
    sql: &str,
    index: usize,
) {
    let stop = sql[index..].find('\n').map_or(sql.len(), |offset| index + offset);
    current.push_str(&sql[index..stop]);
    while chars.peek().is_some_and(|(next, _)| *next < stop) {
        chars.next();
    }
}

/// A quoted string or identifier, its closing quote doubled to escape it; on MySQL a backslash also
/// escapes the next character inside `'…'` and `"…"`.
fn quoted(
    current: &mut String,
    chars: &mut std::iter::Peekable<std::str::CharIndices<'_>>,
    index: usize,
    quote: char,
    backslash_escapes: bool,
) -> Result<(), String> {
    current.push(quote);
    loop {
        let Some((_, c)) = chars.next() else {
            return Err(format!("an unterminated {quote}…{quote} starting at byte {index}"));
        };
        current.push(c);
        if backslash_escapes && c == '\\' {
            if let Some((_, escaped)) = chars.next() {
                current.push(escaped);
            }
            continue;
        }
        if c == quote {
            if chars.peek().is_some_and(|(_, next)| *next == quote) {
                if let Some((_, doubled)) = chars.next() {
                    current.push(doubled);
                }
                continue;
            }
            return Ok(());
        }
    }
}

fn push(statements: &mut Vec<String>, current: &mut String, dialect: Dialect) {
    let statement = std::mem::take(current);
    if !only_comments(&statement, dialect) {
        statements.push(statement.trim().to_owned());
    }
}

/// Whether a statement is nothing but blanks and comments, which no server needs to see.
fn only_comments(statement: &str, dialect: Dialect) -> bool {
    let mut rest = statement.trim_start();
    loop {
        if rest.is_empty() {
            return true;
        }
        if rest.starts_with("--") || (dialect == Dialect::MySql && rest.starts_with('#')) {
            rest = rest.find('\n').map_or("", |end| &rest[end..]).trim_start();
        } else if rest.starts_with("/*") && !rest.starts_with("/*!") {
            let Some(end) = block_comment_end(rest, 0, dialect) else { return false };
            rest = rest[end..].trim_start();
        } else {
            return false;
        }
    }
}

fn strip_keyword<'a>(line: &'a str, keyword: &str) -> Option<&'a str> {
    let head = line.get(..keyword.len())?;
    let rest = &line[keyword.len()..];
    (head.eq_ignore_ascii_case(keyword) && rest.starts_with(char::is_whitespace)).then_some(rest)
}

/// The statements PostgreSQL runs only outside a transaction block.
fn outside_transaction_only(statement: &str) -> bool {
    let words: Vec<String> = code_words(statement).take(5).collect();
    let starts = |prefix: &[&str]| prefix.iter().enumerate().all(|(i, word)| words.get(i).is_some_and(|w| w == word));
    starts(&["create", "index", "concurrently"])
        || starts(&["create", "unique", "index", "concurrently"])
        || starts(&["drop", "index", "concurrently"])
        || starts(&["reindex"]) && words.iter().any(|word| word == "concurrently")
        || starts(&["vacuum"])
        || starts(&["create", "database"])
        || starts(&["drop", "database"])
        || starts(&["create", "tablespace"])
        || starts(&["drop", "tablespace"])
        || starts(&["alter", "system"])
}

/// The statement's words in lower case, comments skipped.
fn code_words(statement: &str) -> impl Iterator<Item = String> + '_ {
    let mut text = String::new();
    let mut rest = statement;
    while !rest.is_empty() {
        if rest.starts_with("--") {
            rest = rest.find('\n').map_or("", |end| &rest[end..]);
        } else if rest.starts_with("/*") {
            rest = block_comment_end(rest, 0, Dialect::PostgreSql).map_or("", |end| &rest[end..]);
        } else {
            let c = rest.chars().next().unwrap_or(' ');
            text.push(c);
            rest = &rest[c.len_utf8()..];
        }
    }
    text.split(|c: char| !(c.is_alphanumeric() || c == '_'))
        .filter(|word| !word.is_empty())
        .map(str::to_lowercase)
        .collect::<Vec<_>>()
        .into_iter()
}

fn first_line(statement: &str) -> String {
    statement.lines().find(|line| !line.trim().is_empty()).unwrap_or_default().trim().to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mysql(sql: &str) -> Vec<String> {
        statements(Engine::MySql, "V1__t.sql", sql).unwrap()
    }

    fn postgres(sql: &str) -> Vec<String> {
        statements(Engine::PostgreSql, "V1__t.sql", sql).unwrap()
    }

    #[test]
    fn statements_end_at_the_delimiter_and_comments_alone_are_dropped() {
        assert_eq!(mysql("create table a (id int);\n-- a note;\ninsert into a values (1);\n"), [
            "create table a (id int)",
            "-- a note;\ninsert into a values (1)"
        ]);
        assert_eq!(postgres("/* only a comment; */\n-- and another;\n"), Vec::<String>::new());
    }

    #[test]
    fn a_delimiter_inside_a_string_or_identifier_does_not_end_a_statement() {
        assert_eq!(mysql("insert into a values ('x;y', 'it''s; fine', \"q;\", 'a\\';b');\nselect `w;x`;"), [
            "insert into a values ('x;y', 'it''s; fine', \"q;\", 'a\\';b')",
            "select `w;x`"
        ]);
        assert_eq!(postgres("insert into \"a;b\" values ('x;y', 'it''s');"), ["insert into \"a;b\" values ('x;y', 'it''s')"]);
    }

    #[test]
    fn mysql_reads_the_delimiter_directive_and_never_sends_it() {
        let sql = "drop procedure if exists p;\n-- why a procedure\nDELIMITER //\ncreate procedure p()\nbegin\n  select 1;\n  select 2;\nend //\nDELIMITER ;\n\ncall p();\n";
        assert_eq!(mysql(sql), [
            "drop procedure if exists p",
            "create procedure p()\nbegin\n  select 1;\n  select 2;\nend",
            "call p()"
        ]);
    }

    #[test]
    fn postgres_keeps_a_dollar_quoted_body_whole_and_nests_comments() {
        assert_eq!(postgres("do $body$ begin perform 1; end $body$;\n/* a /* nested; */ comment; */ select 1;"), [
            "do $body$ begin perform 1; end $body$",
            "/* a /* nested; */ comment; */ select 1"
        ]);
    }

    #[test]
    fn mysql_double_dash_is_a_comment_only_before_a_blank() {
        assert_eq!(mysql("select 1--1;\n-- note\nselect 2;"), ["select 1--1", "-- note\nselect 2"]);
    }

    #[test]
    fn a_statement_postgres_cannot_run_in_a_transaction_is_refused() {
        let refused = statements(Engine::PostgreSql, "V1__t.sql", "-- why\ncreate index concurrently i on a (x);");
        assert!(matches!(refused, Err(Error::NonTransactional { .. })));
        assert!(statements(Engine::PostgreSql, "V1__t.sql", "create index i on a (x);").is_ok());
    }

    #[test]
    fn an_unterminated_string_is_refused() {
        assert!(matches!(statements(Engine::MySql, "V1__t.sql", "select 'x;"), Err(Error::Unparsable { .. })));
    }
}
