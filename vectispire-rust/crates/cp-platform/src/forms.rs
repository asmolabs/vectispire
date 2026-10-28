//! The shapes a save checks values against that belong to modules not ported yet — each Java's to the character,
//! and pure, so they are here rather than behind a seam.

/// `String.trim`: every leading and trailing character up to U+0020.
pub fn java_trim(value: &str) -> &str {
    value.trim_matches(|c: char| c <= ' ')
}

/// `SettingsAdministrationService.isTruthy`: what switching four-eyes on is, for the checks that it can be honoured.
pub fn is_truthy(value: &str) -> bool {
    value.eq_ignore_ascii_case("true") || value == "1"
}

/// `TicketProvider.fromWireName(value) == GITHUB`: trimmed as `String.trim` does, any case.
pub fn is_github(provider: &str) -> bool {
    java_trim(provider).to_lowercase() == "github"
}

/// `Tickets.githubRepositoryPath(project).isPresent()`: `owner/repository` — letters, digits and hyphens for the
/// owner; letters, digits, dots, underscores and hyphens for the repository — and nothing after it; `.` and `..`,
/// which the pattern admits and a server would resolve as a step up the path, refused. ASCII only, as Java's
/// character classes are.
pub fn is_github_repository(project: &str) -> bool {
    let Some((owner, repository)) = java_trim(project).split_once('/') else { return false };
    let owner_ok = !owner.is_empty() && owner.chars().all(|c| c.is_ascii_alphanumeric() || c == '-');
    let repository_ok = !repository.is_empty()
        && repository.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        && repository != "."
        && repository != "..";
    owner_ok && repository_ok
}

/// `TokenExpiry.ofDate(value).isPresent()` for a non-blank value: `LocalDate.parse` of the trimmed text, which is
/// `ISO_LOCAL_DATE` resolved strictly — a year of exactly four digits, or a sign and more (`+` only past four,
/// up to 999,999,999), a two-digit month and day, the day existing in that month of the proleptic Gregorian year.
pub fn is_iso_local_date(value: &str) -> bool {
    let text = java_trim(value);
    let (sign, rest) = match text.as_bytes().first() {
        Some(b'+') => (Some('+'), text.get(1..).unwrap_or("")),
        Some(b'-') => (Some('-'), text.get(1..).unwrap_or("")),
        _ => (None, text),
    };
    let mut parts = rest.split('-');
    let (Some(year), Some(month), Some(day), None) = (parts.next(), parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    let digits = |part: &str| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit());
    if !digits(year) || !digits(month) || !digits(day) || month.len() != 2 || day.len() != 2 {
        return false;
    }
    let width_ok = match sign {
        None => year.len() == 4,
        Some('+') => (5..=10).contains(&year.len()),
        Some(_) => (4..=10).contains(&year.len()),
    };
    let (Ok(year), Ok(month), Ok(day)) = (year.parse::<i64>(), month.parse::<u32>(), day.parse::<u32>()) else {
        return false;
    };
    if !width_ok || year > 999_999_999 {
        return false;
    }
    let year = if sign == Some('-') { year.saturating_neg() } else { year };
    let leap = year.rem_euclid(4) == 0 && (year.rem_euclid(100) != 0 || year.rem_euclid(400) == 0);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    (1..=days).contains(&day)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `LocalDate.parse`'s answers, read off a JDK 25 for each input.
    #[test]
    fn a_date_is_what_local_date_parses() {
        for (input, java_accepts) in [
            ("2027-01-31", true),
            ("  2027-01-31\t", true),
            ("2027-02-29", false),
            ("2028-02-29", true),
            ("1900-02-29", false),
            ("2000-02-29", true),
            ("+2027-01-31", false),
            ("+12027-01-31", true),
            ("12027-01-31", false),
            ("-2027-01-31", true),
            ("-12027-01-31", true),
            ("0000-01-01", true),
            ("2027-1-31", false),
            ("2027-01-32", false),
            ("2027-01-00", false),
            ("2027-13-01", false),
            ("2027-00-10", false),
            ("2027-04-31", false),
            ("2027-06-30", true),
            ("+999999999-12-31", true),
            ("+1000000000-01-01", false),
            ("２０２７-01-31", false),
            ("2027-01-31T00:00", false),
            ("-0001-02-29", false),
            ("-0004-02-29", true),
            ("+99999-02-29", false),
            ("2027-01", false),
            ("", false),
        ] {
            assert_eq!(is_iso_local_date(input), java_accepts, "{input:?}");
        }
    }

    #[test]
    fn a_github_repository_is_owner_slash_name_and_nothing_else() {
        for (input, accepted) in [
            ("asmolabs/vectispire", true),
            (" asmolabs/vectispire.git ", true),
            ("a-b/c_d.e-f", true),
            ("asmolabs/.", false),
            ("asmolabs/..", false),
            ("asmolabs/...", true),
            ("asmolabs", false),
            ("asmolabs/vectispire/issues", false),
            ("asmo_labs/vectispire", false),
            ("/vectispire", false),
            ("asmolabs/", false),
            ("asmolabs/vectispire?x=1", false),
            ("asmolabé/vectispire", false),
        ] {
            assert_eq!(is_github_repository(input), accepted, "{input:?}");
        }
    }

    #[test]
    fn the_provider_and_the_switch_read_as_java_reads_them() {
        assert!(is_github(" GitHub "));
        assert!(!is_github("gitlab"));
        assert!(!is_github(""));
        assert!(is_truthy("TRUE") && is_truthy("1") && !is_truthy("yes") && !is_truthy("false"));
    }
}
