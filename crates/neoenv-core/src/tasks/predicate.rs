//! The side-effect-free task predicate language.
//!
//! Supported: truthy values, `env.NAME`, `os`, `arch`, `context`, `input.NAME`,
//! `outcome.TASK`, `output.NAME`/`outputs.NAME`, `args`, `args.N`, `success`,
//! `!`, `==`, `!=`, `<`, `<=`, `>`, `>=`, `%`, `&&`, `||`, parentheses, and
//! quoted string literals.
//!
//! The language stays closed: nothing here starts a process, renders a template,
//! expands a shell expression, or evaluates a string as code. Adding a reference
//! means adding a field the engine supplies, never a way to reach the host.

use super::planning::valid_environment_key;
use std::collections::BTreeSet;

use super::{BTreeMap, PredicateContext, TaskOutcome};

/// Evaluates the deliberately small, side-effect-free task predicate language.
///
/// Predicates may use truthy values, `env.NAME`, `os`, `arch`, `!`, `==`, `!=`,
/// `&&`, `||`, parentheses, and quoted string literals. No command, template, or
/// shell evaluation is performed.
///
/// # Errors
///
/// Returns an error for malformed expressions or unsupported environment paths.
pub fn evaluate_predicate(
    predicate: &str,
    environment: &BTreeMap<String, String>,
) -> Result<bool, String> {
    evaluate_predicate_with_context(predicate, PredicateContext::empty(environment))
}

/// Evaluates a task predicate against the engine-provided, closed data context.
///
/// In addition to `env.NAME`, predicates can reference `context`,
/// `input.NAME`, `outcome.TASK`, and the public `output.NAME` handoff values.
/// All references are plain strings and missing values resolve to an empty
/// string.
///
/// # Errors
///
/// Returns an error for malformed expressions or unsupported references.
pub fn evaluate_predicate_with_context(
    predicate: &str,
    context: PredicateContext<'_>,
) -> Result<bool, String> {
    let tokens = tokenize_predicate(predicate)?;
    let mut parser = PredicateParser {
        tokens: &tokens,
        position: 0,
        context,
        skip_eval: false,
    };
    let value = parser.parse_or()?;
    if parser.peek() != &PredicateToken::End {
        return Err(format!("unexpected token {}", parser.peek().display()));
    }
    Ok(value)
}

/// Returns the environment keys a predicate may read.
///
/// **A conservative dependency list, not an evaluation.** A plan cannot know a
/// value that a vault reference would produce, so it has to know which names the
/// predicate could consult before deciding whether the outcome is knowable at
/// all. Quoted text that looks like an `env.` reference is included too; a false
/// positive makes a plan conditional where it might have been decidable, which is
/// the safe direction.
///
/// # Errors
///
/// Returns the tokenizer's error for a malformed predicate.
pub fn predicate_environment_dependencies(predicate: &str) -> Result<BTreeSet<String>, String> {
    let tokens = tokenize_predicate(predicate)?;
    let mut dependencies = BTreeSet::new();
    for token in tokens {
        if let PredicateToken::Value(value) = token
            && let Some(key) = value.strip_prefix("env.")
        {
            if key.is_empty() || !valid_environment_key(key) {
                return Err(format!("invalid environment reference {value:?}"));
            }
            dependencies.insert(key.to_owned());
        }
    }
    Ok(dependencies)
}

/// Returns the task names whose `outcome.NAME` a predicate may read.
///
/// A conditional predecessor has no real outcome. A predicate that asks for it
/// is conditional too, regardless of what the dry-run placeholder says.
///
/// # Errors
///
/// Returns the tokenizer's error for a malformed predicate.
pub fn predicate_outcome_dependencies(predicate: &str) -> Result<BTreeSet<String>, String> {
    let tokens = tokenize_predicate(predicate)?;
    let mut dependencies = BTreeSet::new();
    for token in tokens {
        if let PredicateToken::Value(value) = token
            && let Some(task) = value.strip_prefix("outcome.")
        {
            if task.is_empty() {
                return Err(format!("invalid task outcome reference {value:?}"));
            }
            dependencies.insert(task.to_owned());
        }
    }
    Ok(dependencies)
}

/// Whether a predicate reads aggregate state that a conditional task makes
/// uncertain: the overall `success` value, or an `output.NAME`/`outputs.NAME`.
///
/// The dry-run planner cannot know whether a conditional task will succeed or
/// what it will publish. Treating either aggregate as decidable would let a
/// dependent `if: success` or `if: output.X == ...` report a false skip.
///
/// # Errors
///
/// Returns the tokenizer's error for a malformed predicate.
pub fn predicate_reads_uncertain_aggregate(predicate: &str) -> Result<bool, String> {
    let tokens = tokenize_predicate(predicate)?;
    Ok(tokens.into_iter().any(|token| {
        matches!(
            token,
            PredicateToken::Value(value)
                if value == "success"
                    || value.starts_with("output.")
                    || value.starts_with("outputs.")
        )
    }))
}

pub(super) fn validate_predicate(predicate: &str) -> Result<(), String> {
    evaluate_predicate(predicate, &BTreeMap::new()).map(|_| ())
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum PredicateToken {
    Value(String),
    Not,
    Equal,
    NotEqual,
    Less,
    LessOrEqual,
    Greater,
    GreaterOrEqual,
    Modulo,
    And,
    Or,
    LeftParen,
    RightParen,
    End,
}

impl PredicateToken {
    fn display(&self) -> String {
        match self {
            Self::Value(value) => format!("{value:?}"),
            Self::Not => "!".into(),
            Self::Equal => "==".into(),
            Self::NotEqual => "!=".into(),
            Self::Less => "<".into(),
            Self::LessOrEqual => "<=".into(),
            Self::Greater => ">".into(),
            Self::GreaterOrEqual => ">=".into(),
            Self::Modulo => "%".into(),
            Self::And => "&&".into(),
            Self::Or => "||".into(),
            Self::LeftParen => "(".into(),
            Self::RightParen => ")".into(),
            Self::End => "end of predicate".into(),
        }
    }
}

fn tokenize_predicate(input: &str) -> Result<Vec<PredicateToken>, String> {
    let mut tokens = Vec::new();
    let characters: Vec<_> = input.chars().collect();
    let mut position = 0;
    while position < characters.len() {
        let character = *characters
            .get(position)
            .ok_or_else(|| "predicate ended unexpectedly".to_owned())?;
        if character.is_whitespace() {
            position += 1;
            continue;
        }
        let token = match character {
            '(' => PredicateToken::LeftParen,
            ')' => PredicateToken::RightParen,
            '!' if characters.get(position + 1) == Some(&'=') => {
                position += 1;
                PredicateToken::NotEqual
            }
            '<' if characters.get(position + 1) == Some(&'=') => {
                position += 1;
                PredicateToken::LessOrEqual
            }
            '<' => PredicateToken::Less,
            '>' if characters.get(position + 1) == Some(&'=') => {
                position += 1;
                PredicateToken::GreaterOrEqual
            }
            '>' => PredicateToken::Greater,
            '%' => PredicateToken::Modulo,
            '!' => PredicateToken::Not,
            '=' if characters.get(position + 1) == Some(&'=') => {
                position += 1;
                PredicateToken::Equal
            }
            '&' if characters.get(position + 1) == Some(&'&') => {
                position += 1;
                PredicateToken::And
            }
            '|' if characters.get(position + 1) == Some(&'|') => {
                position += 1;
                PredicateToken::Or
            }
            quote @ ('\'' | '"') => {
                let opening = position;
                position += 1;
                let mut value = String::new();
                let mut closed = false;
                while let Some(&character) = characters.get(position) {
                    position += 1;
                    if character == quote {
                        closed = true;
                        break;
                    }
                    if character == '\\' {
                        let Some(&escaped) = characters.get(position) else {
                            return Err("unterminated string literal".into());
                        };
                        position += 1;
                        value.push(escaped);
                    } else {
                        value.push(character);
                    }
                }
                if !closed {
                    // Without this, a quote that ends the input parses as an
                    // empty literal, so `if: os == '` would silently skip the
                    // task instead of reporting the typo.
                    let _ = opening;
                    return Err("unterminated string literal".into());
                }
                PredicateToken::Value(value)
            }
            _ => {
                let start = position;
                while let Some(&character) = characters.get(position) {
                    // A single `=`, `<`, or `>` is part of a word; only the
                    // doubled forms are operators. Splitting on the character
                    // would make `a=b` unwriteable as a literal, where the
                    // reference reads it as one word.
                    // Always a delimiter, whatever follows.
                    if character.is_whitespace() || "()%\"'".contains(character) {
                        break;
                    }
                    // A comparison or logic character ends a word only as a
                    // *pair*. Splitting on the character would make `a=b`
                    // unwriteable as a literal, where the reference reads it as
                    // one word.
                    if "=<>&|!".contains(character)
                        && characters.get(position + 1) != Some(&character)
                    {
                        break;
                    }
                    position += 1;
                }
                if start == position {
                    return Err(format!("unexpected character {character:?}"));
                }
                position -= 1;
                PredicateToken::Value(characters[start..=position].iter().collect())
            }
        };
        tokens.push(token);
        position += 1;
    }
    tokens.push(PredicateToken::End);
    Ok(tokens)
}

struct PredicateParser<'a> {
    tokens: &'a [PredicateToken],
    position: usize,
    context: PredicateContext<'a>,
    /// Set once a `&&` or `||` has already decided the result, so the other
    /// operand is *parsed* but not resolved.
    ///
    /// Parsing still has to happen: the token stream has to be consumed to
    /// report an unexpected trailing token. What is suppressed is the work that
    /// can fail — resolving a reference, converting to a number, dividing by
    /// zero, parsing an `args` index — so `false && env.COUNT > nope` is false
    /// rather than an error. The reference has the same rule, and without it a
    /// Go predicate the reference accepts is rejected here.
    skip_eval: bool,
}

impl PredicateParser<'_> {
    fn peek(&self) -> &PredicateToken {
        &self.tokens[self.position]
    }

    fn take(&mut self, expected: &PredicateToken) -> bool {
        if self.peek() == expected {
            self.position += 1;
            true
        } else {
            false
        }
    }

    fn parse_or(&mut self) -> Result<bool, String> {
        let mut value = self.parse_and()?;
        while self.take(&PredicateToken::Or) {
            // `||` with the left side true decides the operand. Merged with
            // `previous` rather than assigned: an operand can already be inside
            // a decided branch, and overwriting the flag would re-arm
            // evaluation for the rest of it.
            let previous = self.skip_eval;
            self.skip_eval = previous || value;
            let right = self.parse_and();
            self.skip_eval = previous;
            // The `?` is applied *before* `||`, not inside it. `value || right?`
            // would let a decided `value` short-circuit the `?` and silently
            // discard a structural error in the operand.
            let right = right?;
            value = value || right;
        }
        Ok(value)
    }

    fn parse_and(&mut self) -> Result<bool, String> {
        let mut value = self.parse_unary()?;
        while self.take(&PredicateToken::And) {
            // See `parse_or`: merged with `previous`, never assigned over it.
            let previous = self.skip_eval;
            self.skip_eval = previous || !value;
            let right = self.parse_unary();
            self.skip_eval = previous;
            // See `parse_or`: the `?` must not sit inside `&&`, or a decided
            // left side would discard a structural error in the operand.
            let right = right?;
            value = value && right;
        }
        Ok(value)
    }

    fn parse_unary(&mut self) -> Result<bool, String> {
        if self.take(&PredicateToken::Not) {
            return Ok(!self.parse_unary()?);
        }
        if self.take(&PredicateToken::LeftParen) {
            let value = self.parse_or()?;
            if !self.take(&PredicateToken::RightParen) {
                return Err("expected )".into());
            }
            return Ok(value);
        }
        self.parse_comparison()
    }

    /// One comparison, or a bare value's truthiness.
    ///
    /// `%` binds tighter than a comparison operator, so the operands here are
    /// modulo expressions rather than plain values.
    fn parse_comparison(&mut self) -> Result<bool, String> {
        let left = self.parse_modulo()?;
        if let Some(operator) = self.take_comparison() {
            let right = self.parse_modulo()?;
            if self.skip_eval {
                return Ok(false);
            }
            return compare_predicate_values(&left, &operator, &right);
        }
        // A skipped bare value is `false` without consulting truthiness, which is
        // what the reference does. Applying `predicate_truthy` to the unresolved
        // token would make an unset `env.FOO` read as true.
        if self.skip_eval {
            return Ok(false);
        }
        Ok(predicate_truthy(&left))
    }

    fn take_comparison(&mut self) -> Option<PredicateToken> {
        let operator = self.peek().clone();
        let is_comparison = matches!(
            operator,
            PredicateToken::Equal
                | PredicateToken::NotEqual
                | PredicateToken::Less
                | PredicateToken::LessOrEqual
                | PredicateToken::Greater
                | PredicateToken::GreaterOrEqual
        );
        if is_comparison {
            self.position += 1;
            return Some(operator);
        }
        None
    }

    /// Left-associative modulo, so `a % b % c` is `(a % b) % c`.
    // `float_cmp` is allowed on the zero test only: zero is the one value with no
    // reciprocal, so comparing it exactly is the correct test rather than a smell.
    #[allow(clippy::float_cmp)]
    fn parse_modulo(&mut self) -> Result<String, String> {
        let mut left = self.parse_value()?;
        while self.take(&PredicateToken::Modulo) {
            let right = self.parse_value()?;
            if self.skip_eval {
                // The operand is still consumed, but not converted: a
                // short-circuited `x % 0` must not be an error.
                left = right;
                continue;
            }
            let divisor = numeric_predicate_value(&right)?;
            if divisor == 0.0 {
                return Err("modulo by zero".into());
            }
            let dividend = numeric_predicate_value(&left)?;
            left = format_modulo(dividend, divisor);
        }
        Ok(left)
    }

    /// One positional passthrough argument, empty when out of range.
    ///
    /// An out-of-range index is empty rather than an error, matching the
    /// reference: a predicate that guards an optional argument has to be
    /// expressible.
    fn argument(&self, index: &str, reference: &str) -> Result<String, String> {
        let Ok(index) = index.parse::<usize>() else {
            return Err(format!("invalid args reference {reference:?}"));
        };
        Ok(self.context.args.get(index).cloned().unwrap_or_default())
    }

    fn parse_value(&mut self) -> Result<String, String> {
        let PredicateToken::Value(value) = self.peek() else {
            return Err(format!("expected value, got {}", self.peek().display()));
        };
        let value = value.clone();
        self.position += 1;
        if self.skip_eval {
            return Ok(value);
        }
        Ok(match value.as_str() {
            "os" => std::env::consts::OS.into(),
            "arch" => std::env::consts::ARCH.into(),
            "context" => self.context.context.to_owned(),
            _ if value.starts_with("env.") => {
                let key = &value[4..];
                if key.is_empty() || !valid_environment_key(key) {
                    return Err(format!("invalid environment reference {value:?}"));
                }
                self.context
                    .environment
                    .get(key)
                    .cloned()
                    .unwrap_or_default()
            }
            _ if value.starts_with("input.") => {
                let key = &value[6..];
                if key.is_empty() || !valid_environment_key(key) {
                    return Err(format!("invalid task input reference {value:?}"));
                }
                self.context
                    .inputs
                    .get(key)
                    .map_or_else(String::new, |values| values.join(","))
            }
            _ if value.starts_with("outcome.") => {
                let key = &value[8..];
                if key.is_empty() {
                    return Err(format!("invalid task outcome reference {value:?}"));
                }
                self.context
                    .outcomes
                    .get(key)
                    .map_or_else(String::new, |outcome| {
                        match outcome {
                            TaskOutcome::Planned => "planned",
                            TaskOutcome::Conditional => "conditional",
                            TaskOutcome::Running => "running",
                            TaskOutcome::Succeeded => "succeeded",
                            TaskOutcome::Failed => "failed",
                            TaskOutcome::Skipped => "skipped",
                            TaskOutcome::Blocked => "blocked",
                            TaskOutcome::Cancelled => "cancelled",
                            TaskOutcome::TimedOut => "timed_out",
                        }
                        .to_owned()
                    })
            }
            // The Go reference spells this `outputs.`; the singular form is the
            // Rust one. Both resolve to the same handoff map.
            _ if value.starts_with("output.") || value.starts_with("outputs.") => {
                let key = value.split_once('.').map_or("", |(_, key)| key);
                if key.is_empty() || !valid_environment_key(key) {
                    return Err(format!("invalid task output reference {value:?}"));
                }
                self.context.outputs.get(key).cloned().unwrap_or_default()
            }
            "args" => self.context.args.join(" "),
            // Both `args.0` (the reference's spelling) and `args[0]` are
            // accepted, because the two read the same in a task file and a
            // user should not have to know which one the parser prefers.
            _ if value.starts_with("args.") => self.argument(&value[5..], &value)?,
            _ if value.starts_with("args[") && value.ends_with(']') => {
                self.argument(&value[5..value.len() - 1], &value)?
            }
            "success" => self.context.success().to_string(),
            _ => value,
        })
    }
}

/// Applies one comparison operator to two already-resolved values.
///
/// `==` and `!=` compare numerically when *both* sides are numbers, so `1 == 1.0`
/// holds as it does in the reference, and fall back to a string comparison
/// otherwise. The ordered operators are numeric only: comparing `apple` with
/// `banana` is a mistake worth reporting rather than silently answering false.
// `float_cmp` is allowed here, and only here, because every comparison in this
// function is between two values the user wrote as decimal literals. Exact
// comparison is the intended semantics -- `1 == 1.0` holds, and `0.1 == 0.1 + 0`
// is not something the language can express -- so an epsilon would change the
// answer a user expects rather than make it safer.
#[allow(clippy::float_cmp)]
fn compare_predicate_values(
    left: &str,
    operator: &PredicateToken,
    right: &str,
) -> Result<bool, String> {
    match operator {
        PredicateToken::Equal | PredicateToken::NotEqual => {
            let (Ok(left_number), Ok(right_number)) = (
                numeric_predicate_value(left),
                numeric_predicate_value(right),
            ) else {
                let same = left == right;
                return Ok(if *operator == PredicateToken::NotEqual {
                    !same
                } else {
                    same
                });
            };
            let same = left_number == right_number;
            Ok(if *operator == PredicateToken::NotEqual {
                !same
            } else {
                same
            })
        }
        _ => {
            let left_number = numeric_predicate_value(left)?;
            let right_number = numeric_predicate_value(right)?;
            Ok(match operator {
                PredicateToken::Greater => left_number > right_number,
                PredicateToken::GreaterOrEqual => left_number >= right_number,
                PredicateToken::Less => left_number < right_number,
                PredicateToken::LessOrEqual => left_number <= right_number,
                // Unreachable: `take_comparison` yields only the six operators
                // handled above, and modulo binds tighter so it never arrives.
                _ => return Err(format!("unsupported operator {}", operator.display())),
            })
        }
    }
}

fn numeric_predicate_value(value: &str) -> Result<f64, String> {
    value
        .trim()
        .parse::<f64>()
        .map_err(|_| "expected numeric value".to_owned())
}

/// Formats a modulo result so it compares equal to the literal a user writes.
///
/// Rust's `f64` `Display` never uses scientific notation and prints a whole
/// number without a fractional part, so `7 % 2` renders as `1` and therefore
/// satisfies `7 % 2 == 1` as well as `== 1.0`.
fn format_modulo(dividend: f64, divisor: f64) -> String {
    format!("{}", dividend % divisor)
}

fn predicate_truthy(value: &str) -> bool {
    !matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "" | "0" | "false" | "no" | "off" | "null" | "nil"
    )
}
