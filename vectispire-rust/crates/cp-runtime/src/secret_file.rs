//! A secret read from a file — `SecretFile`.
//!
//! **Refusing to start rather than continuing with no key**: a deployment with no key still reads what
//! it stored and still serves every screen, so a failed secret mount would be indistinguishable from a
//! fresh installation. Missing, a directory, unreadable by this user, or **present and empty** — a secret
//! volume attached before its contents exist is the ordinary race on a cluster, and it is
//! indistinguishable from a correct mount by anything except reading the file — each is an error that
//! says which variable named the file.

const REMEDY: &str = "Refusing to start rather than continuing with no key: a deployment with no key still reads \
what it stored and still serves every screen, so a failed secret mount would be indistinguishable from a fresh \
installation. Fix the path or unset the variable.";

/// The secret in `path`, trimmed (`String.trim`: every character up to U+0020), or why it cannot be.
pub fn read(path: &str, what: &str) -> Result<String, String> {
    let file = std::path::Path::new(path.trim_matches(|c: char| c <= ' '));
    let content = std::fs::read(file).map_err(|unreadable| {
        let absolute = std::path::absolute(file).unwrap_or_else(|_| file.to_path_buf());
        format!("{what} points at {}, which cannot be read: {unreadable}. {REMEDY}", absolute.display())
    })?;
    let content = String::from_utf8_lossy(&content);
    let secret = content.trim_matches(|c: char| c <= ' ');
    if secret.is_empty() {
        let absolute = std::path::absolute(file).unwrap_or_else(|_| file.to_path_buf());
        return Err(format!("{what} points at {}, which is empty. {REMEDY}", absolute.display()));
    }
    Ok(secret.to_owned())
}

/// A value and a file for the same secret are refused, rather than one of them chosen: nothing here can
/// say which is in force without choosing one the operator did not.
pub fn refuse_both(has_value: bool, has_file: bool, value_name: &str, file_name: &str) -> Result<(), String> {
    if has_value && has_file {
        return Err(format!(
            "{value_name} and {file_name} are both set. Nothing here can say which secret is in force without \
             choosing one you did not, so it refuses rather than picking. Unset {value_name} once the file is in place."
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_file_is_read_and_trimmed() {
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("key");
        std::fs::write(&file, "\n  s3cret \r\n").unwrap();
        assert_eq!(read(file.to_str().unwrap(), "ENCRYPTION_KEY_FILE"), Ok("s3cret".to_owned()));
    }

    #[test]
    fn a_missing_a_directory_and_an_empty_file_are_each_refused_by_name() {
        let directory = tempfile::tempdir().unwrap();
        let missing = directory.path().join("absent");
        let message = read(missing.to_str().unwrap(), "ENCRYPTION_KEY_FILE").unwrap_err();
        assert!(message.starts_with("ENCRYPTION_KEY_FILE points at "), "{message}");
        assert!(
            message.contains("which cannot be read") && message.ends_with("Fix the path or unset the variable."),
            "{message}"
        );
        assert!(read(directory.path().to_str().unwrap(), "X").unwrap_err().contains("which cannot be read"));
        let empty = directory.path().join("empty");
        std::fs::write(&empty, " \n").unwrap();
        assert!(read(empty.to_str().unwrap(), "X_FILE").unwrap_err().starts_with("X_FILE points at "));
        assert!(read(empty.to_str().unwrap(), "X_FILE").unwrap_err().contains("which is empty."));
    }

    #[test]
    fn a_value_and_a_file_together_are_refused() {
        assert!(refuse_both(true, false, "A", "A_FILE").is_ok());
        assert!(refuse_both(false, true, "A", "A_FILE").is_ok());
        let message = refuse_both(true, true, "ENCRYPTION_KEY", "ENCRYPTION_KEY_FILE").unwrap_err();
        assert!(message.starts_with("ENCRYPTION_KEY and ENCRYPTION_KEY_FILE are both set."), "{message}");
        assert!(message.ends_with("Unset ENCRYPTION_KEY once the file is in place."), "{message}");
    }
}
