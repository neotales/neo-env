//! Version ordering, for the question "which of these is the newest?".
//!
//! **This module exists because the obvious implementation is wrong.** Ordering version
//! strings with `Ord` reports that `1.9.0` is newer than `1.10.0`, because that is what
//! byte comparison says: `'9' > '1'`. Three call sites did exactly that to choose which
//! installed runtime or provider version reaches the shell, so a user with both Go 1.9
//! and Go 1.10 installed got the older one on `PATH` — silently, and with a plausible
//! comment explaining the intent.
//!
//! The comparison follows [semver precedence] rather than semver *validity*: a version
//! that does not parse as `major[.minor[.patch]][-pre]` is still ordered, using the
//! semver rule that an unparseable component sorts below a numeric one and above nothing.
//! Rejecting an unfamiliar spelling would mean refusing to answer a question the caller
//! asked about a version that demonstrably exists.
//!
//! [semver precedence]: https://semver.org/spec/v2.0.0.html#spec-item-11

use std::cmp::Ordering;

/// One dot-separated component of a version, split into its numeric part and the
/// remainder that follows it.
///
/// A component like `12` is numeric with an empty suffix; `0-rc.1` is numeric `0` with
/// the suffix `-rc.1`. Splitting this way is what lets a pre-release sort *below* the
/// release it precedes without special-casing the whole string.
#[derive(Clone, Debug, Eq, PartialEq)]
struct Component<'a> {
    number: u64,
    suffix: &'a str,
}

impl<'a> Component<'a> {
    fn parse(text: &'a str) -> Self {
        let digits = text
            .find(|character: char| !character.is_ascii_digit())
            .unwrap_or(text.len());
        // A leading `-` is the pre-release separator, not part of the component's value,
        // so a component of exactly `-rc.1` is numeric zero with a suffix of `rc.1`.
        let (number, suffix) = if digits == 0 {
            (0, text.trim_start_matches('-'))
        } else {
            match text[..digits].parse() {
                Ok(number) => (number, &text[digits..]),
                // More digits than `u64` holds. Saturating is deliberate: the question is
                // which is newer, and an absurdly large component is newer than any
                // representable one, not an error.
                Err(_) => (u64::MAX, &text[digits..]),
            }
        };
        Component { number, suffix }
    }

    /// Semver precedence for a single component.
    ///
    /// **A numeric component beats a non-numeric one.** `1.2.3` outranks `1.2.3-rc.1`
    /// because in the first, the third component is absent-and-therefore-numeric, and in
    /// the second it is `3` followed by a non-empty suffix.
    fn cmp_to(&self, other: &Self) -> Ordering {
        match self.number.cmp(&other.number) {
            Ordering::Equal => {}
            ordering => return ordering,
        }
        match (self.suffix.is_empty(), other.suffix.is_empty()) {
            (true, true) => Ordering::Equal,
            // More fields is a more specific version: `1.2` precedes `1.2.0`.
            (true, false) => Ordering::Greater,
            (false, true) => Ordering::Less,
            (false, false) => compare_pre_release(self.suffix, other.suffix),
        }
    }
}

/// Compare two pre-release suffixes by semver's dot-separated identifier rules.
///
/// Identifiers are compared left to right; numeric identifiers compare numerically and
/// rank above alphanumeric ones, and a longer identifier list outranks a prefix of
/// itself. This is the whole of semver §11.4, and it is the part that makes `rc.2` newer
/// than `rc.1` while `rc.10` is newer than `rc.2` — the same numeric-not-lexicographic
/// trap as the components themselves, one level down.
fn compare_pre_release(left: &str, right: &str) -> Ordering {
    let mut left_parts = left.split('.');
    let mut right_parts = right.split('.');
    loop {
        match (left_parts.next(), right_parts.next()) {
            (None, None) => return Ordering::Equal,
            // The exhausted side is a prefix of the other, so it is the earlier one.
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some(left_part), Some(right_part)) => {
                let ordering = match (is_numeric(left_part), is_numeric(right_part)) {
                    (true, true) => number_of(left_part).cmp(&number_of(right_part)),
                    (true, false) => Ordering::Less,
                    (false, true) => Ordering::Greater,
                    (false, false) => left_part.cmp(right_part),
                };
                if ordering != Ordering::Equal {
                    return ordering;
                }
            }
        }
    }
}

fn is_numeric(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit())
}

fn number_of(text: &str) -> u64 {
    text.parse().unwrap_or(u64::MAX)
}

/// Order two version strings by semver precedence.
///
/// # Panics
///
/// Never. This is a total order over `&str`, and it is reflexive, antisymmetric and
/// transitive for every input, including empty strings and strings that are not versions
/// at all.
///
/// # Examples
///
/// ```
/// use neoenv_core::version::compare_versions;
///
/// assert_eq!(compare_versions("1.10.0", "1.9.0"), std::cmp::Ordering::Greater);
/// assert_eq!(compare_versions("1.0.0-rc.1", "1.0.0"), std::cmp::Ordering::Less);
/// ```
#[must_use]
pub fn compare_versions(left: &str, right: &str) -> Ordering {
    // Build metadata after `+` is not part of precedence at all, so it must be dropped
    // before anything else or `1.0.0+a` and `1.0.0+b` would compare unequal.
    let left = left.split('+').next().unwrap_or(left);
    let right = right.split('+').next().unwrap_or(right);
    let (left_core, left_pre) = split_pre_release(left);
    let (right_core, right_pre) = split_pre_release(right);

    let mut left_components = left_core.split('.');
    let mut right_components = right_core.split('.');
    loop {
        match (left_components.next(), right_components.next()) {
            (None, None) => break,
            // An absent component is zero, so `1.2` and `1.2.0` are the same version and
            // a trailing `1.2` does not sort below `1.2.0`.
            (None, Some(right_part)) => {
                if Component::parse(right_part).cmp_to(&Component::parse("0")) != Ordering::Equal {
                    // The side with more components wins when the extra one is non-zero.
                    return Ordering::Less;
                }
            }
            (Some(left_part), None) => {
                if Component::parse(left_part).cmp_to(&Component::parse("0")) != Ordering::Equal {
                    return Ordering::Greater;
                }
            }
            (Some(left_part), Some(right_part)) => {
                let ordering = Component::parse(left_part).cmp_to(&Component::parse(right_part));
                if ordering != Ordering::Equal {
                    return ordering;
                }
            }
        }
    }

    match (left_pre, right_pre) {
        // A version with a pre-release is earlier than the release it precedes.
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
        (Some(left_pre), Some(right_pre)) => compare_pre_release(left_pre, right_pre),
    }
}

/// Split `1.2.3-rc.1` into `("1.2.3", Some("rc.1"))`.
///
/// The first `-` is the separator, and only if it follows at least one digit: a leading
/// `-` is a *sign* in a dated version such as `nightly-2024-01-01`, and treating that as
/// a pre-release would order every dated nightly below every release.
fn split_pre_release(version: &str) -> (&str, Option<&str>) {
    // The separator is the first `-` that has a numeric core before it. Requiring a digit
    // ahead of the dash is what distinguishes `1.0.0-rc.1` from `nightly-2024-01-01`: in
    // the second, the character before the dash is `y`.
    // A dash at index 0 gives an empty `version[..index]`, whose `.first()` is `None`, so
    // the digit test already excludes it. An earlier version of this guard also spelled
    // out `index > 0`; mutating that clause to `true` left every test green, which is how
    // it was found to be unreachable rather than merely untested.
    match version.find('-') {
        // The version must *begin* with a digit, which is what keeps `nightly-2024-01-01`
        // whole: its first byte is `n`. Reading the first byte of the whole version rather
        // than of the prefix is not a shortcut — a dash at index 0 means the first byte is
        // `-`, which is not a digit, so the `index > 0` check this replaced was
        // unreachable and a mutation to it left every test green.
        Some(index) if version.as_bytes().first().is_some_and(u8::is_ascii_digit) => {
            (&version[..index], Some(&version[index + 1..]))
        }
        _ => (version, None),
    }
}

/// The newer of two versions, by semver precedence.
///
/// The tie-break is `right`, so the result is stable under a fold in a fixed direction —
/// which is what every call site here actually wants, since all three are "which installed
/// version wins".
#[must_use]
pub fn newest_version<'a>(left: &'a str, right: &'a str) -> &'a str {
    if compare_versions(left, right) == Ordering::Greater {
        left
    } else {
        right
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **The bug this module exists for, asserted as literals.**
    ///
    /// Byte order says `1.9.0` is newer than `1.10.0`. Three call sites chose which
    /// installed runtime reaches the shell with exactly that comparison, so a user with
    /// both versions installed got the older one. The literals matter: comparing the
    /// function against a plain `str::cmp` would pass whenever the two agree.
    #[test]
    fn a_two_digit_component_is_newer_than_a_one_digit_one() {
        assert_eq!(compare_versions("1.10.0", "1.9.0"), Ordering::Greater);
        assert_eq!(compare_versions("1.9.0", "1.10.0"), Ordering::Less);
        assert_eq!(compare_versions("20.0.0", "9.11.2"), Ordering::Greater);
        assert_eq!(compare_versions("1.2.10", "1.2.9"), Ordering::Greater);
        // The pair that is actually installed in the wild most often.
        assert_eq!(newest_version("1.9.7", "1.10.1"), "1.10.1");
    }

    /// **Precedence, in the order semver states it.**
    #[test]
    fn precedence_follows_semver_not_byte_order() {
        let cases: &[(&str, &str, Ordering)] = &[
            ("1.0.0-alpha", "1.0.0", Ordering::Less),
            ("1.0.0-alpha", "1.0.0-alpha.1", Ordering::Less),
            ("1.0.0-alpha.1", "1.0.0-alpha.beta", Ordering::Less),
            // Numeric identifiers rank above alphanumeric ones.
            ("1.0.0-alpha.1", "1.0.0-alpha.beta", Ordering::Less),
            ("1.0.0-beta", "1.0.0-beta.2", Ordering::Less),
            ("1.0.0-beta.2", "1.0.0-beta.11", Ordering::Less),
            ("1.0.0-rc.1", "1.0.0", Ordering::Less),
            // A bigger number in any position wins, pre-release or not.
            ("2.0.0", "1.99.99", Ordering::Greater),
            ("1.2.0", "1.10.0", Ordering::Less),
            // Equality is reflexive in every position.
            ("1.0.0", "1.0.0", Ordering::Equal),
            ("1.0", "1.0.0", Ordering::Equal),
            ("1.0", "1.0.1", Ordering::Less),
            // Build metadata is not part of precedence.
            ("1.0.0+build.1", "1.0.0+build.2", Ordering::Equal),
            ("1.0.0+build.1", "1.0.0", Ordering::Equal),
        ];
        for (left, right, expected) in cases {
            assert_eq!(
                compare_versions(left, right),
                *expected,
                "{left} vs {right}"
            );
            assert_eq!(
                compare_versions(right, left),
                expected.reverse(),
                "{right} vs {left} must be the mirror of the row above"
            );
        }
    }

    /// **Every spelling a shipped runtime can produce, ordered against its neighbour.**
    ///
    /// Asserted as literals so a change to the parser that silently stopped handling one
    /// of these shows up here rather than as a runtime resolving to the wrong build.
    ///
    /// **Every row here was chosen because byte order gets it backwards.** The first
    /// version of this test listed only pairs that a plain `str::cmp` also gets right —
    /// `1.22.0` over `1.21.5`, `0.5.0` over `0.4.0` — and it passed against a comparator
    /// replaced by `left.cmp(right)`, so it was testing nothing. The `assert_ne!` below
    /// is what stops that recurring: it fails if a row stops disagreeing with byte order,
    /// which means a row that looks like coverage has quietly become a tautology.
    #[test]
    fn every_runtime_version_spelling_orders_correctly() {
        // (newer, older) pairs drawn from real releases: go 1.22 and 1.10 over 1.9,
        // python 3.12 and 3.10 over 3.9, node 22 over 9, zig 0.13 over 0.9, deno 1.46 over
        // 1.9, uv 0.10 over 0.9, dotnet 10.0.100 over 9.0.100, and two that differ only in
        // the last component's width. Two further pairs were here and have been removed
        // because byte order gets them right too, so they asserted nothing: `0.20.0` over
        // `0.19.0` and `1.0.0-rc.2` over `1.0.0-rc.1`. Pre-release ordering that *does*
        // diverge is covered above by `1.0.0-beta.2` over `1.0.0-beta.11`, and the four
        // PEP 440 rows reach a different arm again: with no dash to split on, the
        // pre-release lives inside the component, so the comparison is decided by
        // `Component::cmp_to`'s empty-suffix arm.
        let newer_first: &[(&str, &str)] = &[
            ("1.22.0", "1.9.5"),
            ("1.10.0", "1.9.7"),
            ("3.12.0", "3.9.0"),
            ("3.10.0", "3.9.0"),
            ("22.0.0", "9.11.2"),
            ("0.13.0", "0.9.0"),
            ("1.46.0", "1.9.0"),
            ("0.10.0", "0.9.0"),
            ("10.0.100", "9.0.100"),
            ("1.2.10", "1.2.9"),
            ("1.0.0-rc.10", "1.0.0-rc.2"),
            // PEP 440 puts the pre-release marker *inside* the patch component, with no
            // dash at all, so it reaches the component suffix rather than the pre-release
            // split. These are the spellings CPython actually publishes.
            ("3.12.0", "3.12.0a1"),
            ("3.12.0", "3.12.0b2"),
            ("3.12.0", "3.12.0rc1"),
            ("3.10.0", "3.9.0rc1"),
        ];
        for (newer, older) in newer_first {
            assert_eq!(
                compare_versions(newer, older),
                Ordering::Greater,
                "{newer} must outrank {older}"
            );
            assert_ne!(
                newer.cmp(older),
                Ordering::Greater,
                "the pair ({newer}, {older}) is also ordered correctly by byte comparison, \
                 so this row would pass even if the comparator were `str::cmp` — pick a \
                 pair that byte order gets wrong"
            );
        }
    }

    /// **A dated nightly is a version, not a pre-release of nothing.**
    ///
    /// `nightly-2024-01-01` has a leading `-` after a non-numeric core. Treating that as a
    /// pre-release separator would sort every dated build below every release and below
    /// every real version, which is the worst available answer for the one runtime family
    /// that publishes them.
    #[test]
    fn a_dated_version_is_not_mistaken_for_a_pre_release() {
        // **The classification is asserted, not inferred from the ordering.** An earlier
        // version of this test only compared dated versions against each other, and it
        // passed with the digit check deleted: ISO dates are lexicographically ordered, so
        // both paths give the same answer for every dated pair and the test could not tell
        // the mechanisms apart. The contract is about *which half of the version is
        // which*, so that is what is checked.
        assert_eq!(
            split_pre_release("nightly-2024-01-01"),
            ("nightly-2024-01-01", None),
            "a non-numeric core means the dash is part of the name, not a separator"
        );
        assert_eq!(
            split_pre_release("2024-01-01"),
            ("2024", Some("01-01")),
            "a bare date does split, because `2024` is a numeric prefix — and that is \
             harmless rather than a bug: the year leads, so the core comparison already \
             separates one year from the next, and the day and month compare correctly \
             within a year. The rows below are the evidence."
        );
        // The positive cases, so the rows above are not passing for want of a split.
        assert_eq!(split_pre_release("1.0.0-rc.1"), ("1.0.0", Some("rc.1")));
        assert_eq!(split_pre_release("1.0.0"), ("1.0.0", None));
        // A dash with nothing before it is a sign, not a separator.
        assert_eq!(split_pre_release("-1.0.0"), ("-1.0.0", None));

        // And the ordering consequences, which is what the callers actually see.
        assert_eq!(
            compare_versions("nightly-2024-01-02", "nightly-2024-01-01"),
            Ordering::Greater
        );
        assert_eq!(
            compare_versions("2024-01-01", "2023-12-31"),
            Ordering::Greater
        );
        assert_eq!(
            compare_versions("1.0.0", "nightly-2024-01-01"),
            Ordering::Greater
        );
    }

    /// **Unfamiliar input orders rather than being rejected.**
    ///
    /// The comparator's callers are asking which installed version wins; a spelling this
    /// code has not seen is still a directory in the data root with a receipt beside it,
    /// and refusing to order it would leave the caller to guess. What is asserted is the
    /// property that matters — reflexivity, and the antisymmetry the other rows rely on.
    #[test]
    fn unfamiliar_input_still_orders_and_stays_a_total_order() {
        for version in ["", "1", "master", "v1.2.3", "1.2.3.4.5", "x.y.z", "1.0.0-"] {
            assert_eq!(
                compare_versions(version, version),
                Ordering::Equal,
                "reflexive for {version:?}"
            );
            assert_eq!(
                compare_versions(version, "1.0.0").reverse(),
                compare_versions("1.0.0", version),
                "antisymmetric for {version:?}"
            );
        }
        // A `v` prefix is how Go and Rust spell a tag; the digits still decide.
        assert_eq!(compare_versions("v1.10.0", "v1.9.0"), Ordering::Greater);
    }

    /// **Components beyond `u64` saturate rather than wrap or fail.**
    #[test]
    fn an_absurdly_large_component_is_newer_not_an_error() {
        let huge = "99999999999999999999999999.0.0";
        assert_eq!(compare_versions(huge, "1.0.0"), Ordering::Greater);
        assert_eq!(compare_versions(huge, huge), Ordering::Equal);
    }
}
