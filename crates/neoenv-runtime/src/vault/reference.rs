//! The `nsv://` reference grammar.
//!
//! A reference is `nsv://<vault>/<path>[?<query>][#<fragment>]`. The parser is
//! deliberately stricter than a general URL parser: segments are not
//! percent-decoded, a path must have at least one non-empty segment, unknown or
//! repeated query keys are refused, and interpolated names must exist. A silent
//! empty segment or a silently ignored option would resolve the wrong entry or
//! report a behaviour the user did not get.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use super::REFERENCE_PREFIX;

/// The maximum length of a generated value accepted by `size=`.
pub const MAX_GENERATED_SIZE: u32 = 4096;

/// Options parsed from a reference's query string.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Query {
    /// Generate and store the value when it is missing.
    pub ensure: bool,
    /// Whether `ensure` was written at all, even as `false`.
    ///
    /// `set` refuses the option by presence, not by truthiness: `?ensure=false`
    /// is still a resolution option on a write path and would otherwise be an
    /// inert spelling.
    pub ensure_specified: bool,
    /// Generated value size in bytes. Only valid with `ensure=true`.
    pub size: Option<u32>,
    /// Whether generated values include uppercase letters. Only valid with
    /// `ensure=true`.
    pub upper: Option<bool>,
    /// An inline age ciphertext, percent-decoded.
    pub value: Option<String>,
}

/// A parsed reference. All fields are provider inputs.
#[derive(Clone, Eq, PartialEq)]
pub struct Reference {
    /// The configured vault name.
    pub vault: String,
    /// The non-empty path segments, in order.
    pub path: Vec<String>,
    /// The optional `#fragment`, a provider-defined selector.
    pub fragment: Option<String>,
    /// The optional query options.
    pub query: Query,
}

impl Reference {
    /// Parses `value`, expanding `${NAME}` from `environment` first.
    ///
    /// # Errors
    ///
    /// Returns a [`ReferenceError`] for a missing scheme, an empty or invalid
    /// vault name or path, an invalid fragment or query, an undefined
    /// interpolation name, or a duplicate query key.
    pub fn parse(
        value: &str,
        environment: &BTreeMap<String, String>,
    ) -> Result<Self, ReferenceError> {
        let expanded = interpolate(value, environment)?;
        let remainder = expanded
            .strip_prefix(REFERENCE_PREFIX)
            .ok_or_else(|| ReferenceError::new("reference must start with nsv://"))?;

        // Accept both `path?query#fragment` and `path#fragment?query`. Both are
        // unambiguous; the canonical form is the first. A reader who writes the
        // fragment first should not get a parse error that is about ordering.
        let hash = remainder.find('#');
        let question = remainder.find('?');
        let (body, query, fragment) = match (hash, question) {
            (Some(hash), Some(question)) if hash < question => {
                let body = &remainder[..hash];
                let fragment = &remainder[hash + 1..question];
                let query = &remainder[question + 1..];
                (body, Some(query), Some(fragment))
            }
            (Some(hash), Some(question)) => {
                let body = &remainder[..question];
                let query = &remainder[question + 1..hash];
                let fragment = &remainder[hash + 1..];
                (body, Some(query), Some(fragment))
            }
            (Some(hash), None) => (&remainder[..hash], None, Some(&remainder[hash + 1..])),
            (None, Some(question)) => (
                &remainder[..question],
                Some(&remainder[question + 1..]),
                None,
            ),
            (None, None) => (remainder, None, None),
        };

        let mut segments = body.split('/');
        let vault = segments
            .next()
            .filter(|vault| !vault.is_empty())
            .ok_or_else(|| ReferenceError::new("reference must name a vault"))?;
        if !is_identifier(vault) {
            return Err(ReferenceError::new(
                "vault name must be a lowercase identifier",
            ));
        }
        let path: Vec<String> = segments.map(ToOwned::to_owned).collect();
        if path.is_empty() || path.iter().any(String::is_empty) {
            return Err(ReferenceError::new(
                "reference must have at least one non-empty path segment",
            ));
        }
        for segment in &path {
            if segment.contains(['?', '#']) {
                return Err(ReferenceError::new("a path segment cannot contain ? or #"));
            }
        }

        let fragment = match fragment {
            Some("") => {
                return Err(ReferenceError::new("reference fragment cannot be empty"));
            }
            Some(fragment) if !is_identifier(fragment) => {
                return Err(ReferenceError::new(
                    "reference fragment must be a lowercase identifier",
                ));
            }
            Some(fragment) => Some(fragment.to_owned()),
            None => None,
        };

        let query = parse_query(query.unwrap_or_default())?;
        Ok(Self {
            vault: vault.to_owned(),
            path,
            fragment,
            query,
        })
    }

    /// The path joined with `/`, which is what a `KeePass` path query and an age
    /// `values:` key both use.
    #[must_use]
    pub fn path_string(&self) -> String {
        self.path.join("/")
    }

    /// A stable key for cycle detection.
    #[must_use]
    pub fn canonical(&self) -> String {
        let mut key = format!("{}:{}", self.vault, self.path_string());
        if let Some(fragment) = &self.fragment {
            key.push('#');
            key.push_str(fragment);
        }
        key
    }
}

impl fmt::Debug for Reference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The path and the inline value are caller-supplied. A path can name a
        // sensitive entry, and the value is ciphertext, which is still not
        // something to print. The vault name and the presence of options are
        // enough to diagnose a malformed reference.
        formatter
            .debug_struct("Reference")
            .field("vault", &self.vault)
            .field("path", &"[redacted]")
            .field("fragment", &self.fragment.as_ref().map(|_| "[redacted]"))
            .field("ensure", &self.query.ensure)
            .field("size", &self.query.size)
            .field("upper", &self.query.upper)
            .field("value", &self.query.value.as_ref().map(|_| "[redacted]"))
            .finish()
    }
}

/// A reason a reference cannot be interpreted safely.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReferenceError {
    message: String,
}

impl ReferenceError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// The safe diagnostic message.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for ReferenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for ReferenceError {}

fn is_identifier(value: &str) -> bool {
    let mut characters = value.chars();
    characters
        .next()
        .is_some_and(|character| character.is_ascii_lowercase() || character.is_ascii_digit())
        && characters.all(|character| {
            character.is_ascii_lowercase()
                || character.is_ascii_digit()
                || character == '-'
                || character == '_'
        })
}

fn parse_query(query: &str) -> Result<Query, ReferenceError> {
    let mut parsed = Query::default();
    let mut seen = BTreeSet::new();
    if query.is_empty() {
        return Ok(parsed);
    }
    for pair in query.split('&') {
        if pair.is_empty() {
            return Err(ReferenceError::new(
                "reference query has an empty parameter",
            ));
        }
        let (key, value) = pair
            .split_once('=')
            .ok_or_else(|| ReferenceError::new("reference query parameter has no value"))?;
        let key = percent_decode(key)?;
        let value = percent_decode(value)?;
        if !seen.insert(key.clone()) {
            return Err(ReferenceError::new("reference query repeats an option"));
        }
        match key.as_str() {
            "ensure" => {
                parsed.ensure = parse_bool(&value)?;
                parsed.ensure_specified = true;
            }
            "upper" => parsed.upper = Some(parse_bool(&value)?),
            "size" => {
                let size = value.parse::<u32>().map_err(|_| {
                    ReferenceError::new("reference size must be a positive decimal number")
                })?;
                if size == 0 || size > MAX_GENERATED_SIZE {
                    return Err(ReferenceError::new(format!(
                        "reference size must be between 1 and {MAX_GENERATED_SIZE}"
                    )));
                }
                parsed.size = Some(size);
            }
            "value" => {
                if value.is_empty() {
                    return Err(ReferenceError::new("reference value must not be empty"));
                }
                parsed.value = Some(value);
            }
            _ => {
                return Err(ReferenceError::new(
                    "reference query contains an unsupported option",
                ));
            }
        }
    }
    if parsed.ensure && parsed.value.is_some() {
        return Err(ReferenceError::new(
            "ensure=true supplies a value and cannot be combined with an inline value",
        ));
    }
    if !parsed.ensure && parsed.size.is_some() {
        return Err(ReferenceError::new(
            "size is only meaningful with ensure=true",
        ));
    }
    if !parsed.ensure && parsed.upper.is_some() {
        return Err(ReferenceError::new(
            "upper is only meaningful with ensure=true",
        ));
    }
    Ok(parsed)
}

fn parse_bool(value: &str) -> Result<bool, ReferenceError> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(ReferenceError::new(
            "a reference boolean option must be true or false",
        )),
    }
}

fn percent_decode(value: &str) -> Result<String, ReferenceError> {
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let high =
                bytes.get(index + 1).copied().and_then(hex).ok_or_else(|| {
                    ReferenceError::new("reference has an invalid percent escape")
                })?;
            let low =
                bytes.get(index + 2).copied().and_then(hex).ok_or_else(|| {
                    ReferenceError::new("reference has an invalid percent escape")
                })?;
            output.push((high << 4) | low);
            index += 3;
        } else {
            output.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(output).map_err(|_| ReferenceError::new("reference query is not valid UTF-8"))
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Expands only the braced `${NAME}` form and refuses an undefined name.
///
/// `$NAME` is literal. A reference path is more likely to contain a literal `$`
/// than to mean an unbraced variable, and a missing name that expands to an
/// empty string can turn `nsv://vault/${MISSING}/token` into a different path.
fn interpolate(
    value: &str,
    environment: &BTreeMap<String, String>,
) -> Result<String, ReferenceError> {
    let mut output = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(dollar) = rest.find('$') {
        output.push_str(&rest[..dollar]);
        let after = &rest[dollar + 1..];
        let Some(braced) = after.strip_prefix('{') else {
            output.push('$');
            rest = after;
            continue;
        };
        let Some(end) = braced.find('}') else {
            return Err(ReferenceError::new(
                "reference has an unterminated ${...} interpolation",
            ));
        };
        let name = &braced[..end];
        if name.is_empty() || !is_variable_name(name) {
            return Err(ReferenceError::new(
                "reference has an invalid interpolation name",
            ));
        }
        let resolved = environment.get(name).ok_or_else(|| {
            ReferenceError::new("reference interpolation names a variable that is not set")
        })?;
        output.push_str(resolved);
        rest = &braced[end + 1..];
    }
    output.push_str(rest);
    Ok(output)
}

fn is_variable_name(value: &str) -> bool {
    let mut characters = value.chars();
    characters
        .next()
        .is_some_and(|character| character == '_' || character.is_ascii_alphabetic())
        && characters.all(|character| character == '_' || character.is_ascii_alphanumeric())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{MAX_GENERATED_SIZE, Reference, ReferenceError};

    fn environment() -> BTreeMap<String, String> {
        BTreeMap::from([
            ("VAULT".into(), "work".into()),
            ("ENTRY".into(), "db".into()),
        ])
    }

    #[test]
    fn a_plain_reference_splits_vault_path_fragment_and_query() {
        let reference = Reference::parse(
            "nsv://work/group/entry#username?ensure=true&size=12&upper=false",
            &BTreeMap::new(),
        )
        .unwrap();
        assert_eq!(reference.vault, "work");
        assert_eq!(reference.path, ["group", "entry"]);
        assert_eq!(reference.fragment.as_deref(), Some("username"));
        assert!(reference.query.ensure);
        assert_eq!(reference.query.size, Some(12));
        assert_eq!(reference.query.upper, Some(false));
    }

    #[test]
    fn the_fragment_before_the_query_is_accepted_too() {
        let reference =
            Reference::parse("nsv://work/entry?ensure=true#username", &BTreeMap::new()).unwrap();
        assert_eq!(reference.fragment.as_deref(), Some("username"));
        assert!(reference.query.ensure);
    }

    #[test]
    fn interpolation_expands_the_braced_form_and_keeps_a_bare_dollar_literal() {
        let reference = Reference::parse("nsv://${VAULT}/${ENTRY}/a$b", &environment()).unwrap();
        assert_eq!(reference.vault, "work");
        assert_eq!(reference.path, ["db", "a$b"]);
    }

    #[test]
    fn an_undefined_interpolation_name_is_an_error_not_an_empty_segment() {
        let error = Reference::parse("nsv://${MISSING}/token", &environment()).unwrap_err();
        assert!(error.message().contains("not set"));
    }

    #[test]
    fn an_empty_segment_is_refused() {
        assert!(Reference::parse("nsv://work//token", &BTreeMap::new()).is_err());
        assert!(Reference::parse("nsv://work/", &BTreeMap::new()).is_err());
    }

    #[test]
    fn an_unknown_or_repeated_query_option_is_refused() {
        assert!(Reference::parse("nsv://work/token?nope=1", &BTreeMap::new()).is_err());
        assert!(
            Reference::parse("nsv://work/token?upper=true&upper=false", &BTreeMap::new()).is_err()
        );
    }

    #[test]
    fn size_and_upper_without_ensure_are_refused_as_inert() {
        assert!(Reference::parse("nsv://work/token?size=32", &BTreeMap::new()).is_err());
        assert!(Reference::parse("nsv://work/token?upper=true", &BTreeMap::new()).is_err());
    }

    #[test]
    fn size_is_bounded_in_both_directions() {
        assert!(Reference::parse("nsv://work/token?ensure=true&size=0", &BTreeMap::new()).is_err());
        assert!(
            Reference::parse(
                &format!(
                    "nsv://work/token?ensure=true&size={}",
                    MAX_GENERATED_SIZE + 1
                ),
                &BTreeMap::new()
            )
            .is_err()
        );
    }

    #[test]
    fn an_inline_value_is_percent_decoded() {
        let reference =
            Reference::parse("nsv://work/token?value=hello%20world%2B", &BTreeMap::new()).unwrap();
        assert_eq!(reference.query.value.as_deref(), Some("hello world+"));
    }

    #[test]
    fn a_debug_reference_does_not_print_the_path_or_value() {
        let reference =
            Reference::parse("nsv://work/secret/entry?value=aGVsbG8=", &BTreeMap::new()).unwrap();
        let debug = format!("{reference:?}");
        assert!(!debug.contains("secret"));
        assert!(!debug.contains("aGVsbG8="));
        assert!(debug.contains("work"));
    }

    #[test]
    fn the_reference_parser_refuses_the_old_scheme_and_the_broker_scheme() {
        for value in ["sv://work/token", "nsb://work/secret/token"] {
            let error = Reference::parse(value, &BTreeMap::new()).unwrap_err();
            assert_eq!(
                error,
                ReferenceError::new("reference must start with nsv://")
            );
        }
    }
}
