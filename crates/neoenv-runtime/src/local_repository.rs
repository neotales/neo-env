//! Lexical local Git identities. No filesystem access or link following occurs.

#[cfg(not(windows))]
use std::path::{Component, Path, PathBuf};

/// Returns the sole repository identity for a native absolute path.
pub(crate) fn normalize(value: &str) -> Option<String> {
    #[cfg(windows)]
    {
        normalize_windows(value).map(|path| format!("file://{path}"))
    }
    #[cfg(not(windows))]
    {
        if value.is_empty() || value.contains(['?', '#', '\\']) {
            return None;
        }
        let path = Path::new(value);
        if !path.is_absolute() {
            return None;
        }
        let mut normalized = PathBuf::new();
        for component in path.components() {
            match component {
                Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                    normalized.push(component.as_os_str());
                }
                Component::CurDir | Component::ParentDir => return None,
            }
        }
        Some(format!("file://{}", normalized.to_str()?))
    }
}

/// Accept only drive paths whose Windows spellings have no namespace or
/// component aliases. Preserve drive and component case in the identity.
#[cfg(any(windows, test))]
fn normalize_windows(value: &str) -> Option<String> {
    let value = value.strip_prefix(r"\\?\").unwrap_or(value);
    let bytes = value.as_bytes();
    if bytes.len() < 3
        || !bytes[0].is_ascii_alphabetic()
        || bytes[1] != b':'
        || !matches!(bytes[2], b'\\' | b'/')
    {
        return None;
    }
    let rest = &value[3..];
    let mut result = format!("{}:/", &value[..1]);
    if rest.is_empty() {
        return Some(result);
    }
    for (index, part) in rest.split(['/', '\\']).enumerate() {
        if part.is_empty()
            || part.ends_with(['.', ' '])
            || part.chars().any(|c| {
                c.is_control()
                    || matches!(c, ':' | '?' | '#' | '%' | '*' | '"' | '<' | '>' | '|' | '@')
            })
        {
            return None;
        }
        let base = part
            .split('.')
            .next()
            .unwrap()
            .trim_end()
            .to_ascii_uppercase();
        if matches!(
            base.as_str(),
            "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
        ) || ["COM", "LPT"].iter().any(|prefix| {
            base.strip_prefix(prefix).is_some_and(|suffix| {
                matches!(
                    suffix,
                    "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
                )
            })
        }) {
            return None;
        }
        if index != 0 {
            result.push('/');
        }
        result.push_str(part);
    }
    Some(result)
}

pub(crate) fn validate_identity(value: &str) -> bool {
    value.strip_prefix("file://").and_then(normalize).as_deref() == Some(value)
}

#[cfg(test)]
mod tests {
    use super::normalize_windows;

    #[test]
    fn windows_drive_spellings_normalize_and_ambiguous_paths_fail() {
        let expected = Some("C:/work/repo".to_owned());
        assert_eq!(normalize_windows(r"C:\work\repo"), expected);
        assert_eq!(normalize_windows(r"\\?\C:\work\repo"), expected);
        assert_eq!(normalize_windows("C:/work/repo"), expected);
        for path in [
            r"\\server\share",
            r"\\?\UNC\server\share",
            r"\\.\C:\repo",
            r"C:\work\..\repo",
            r"C:\work\.\repo",
            r"C:\work\repo:stream",
            r"C:\work\NUL.txt",
            r"C:\work\COM¹",
            r"C:\work\repo.",
            r"C:\work\repo ",
            r"C:\work\%72epo",
            r"C:\work\repo?x",
            r"C:\work\\repo",
            r"C:repo",
            r"C:\work\repo#x",
        ] {
            assert_eq!(normalize_windows(path), None, "{path:?}");
        }
    }
}
