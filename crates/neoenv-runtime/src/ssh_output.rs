//! Bounded, host-prefixed console groups with streaming secret redaction.

use std::{
    collections::VecDeque,
    io::Write,
    time::{Duration, Instant},
};
use zeroize::Zeroize as _;

const GROUP: usize = 4096;
const LATENCY: Duration = Duration::from_millis(100);
const RESET: &[u8] = b"\x1b[0m";

/// The remote stream a payload arrived on.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputChannel {
    /// Remote standard output (routed to stderr in JSON mode).
    Stdout,
    /// Remote extended data with SSH stderr type code 1.
    Stderr,
}

#[derive(Clone)]
enum Token {
    Byte(u8),
    Sgr(Vec<u8>),
}

impl zeroize::Zeroize for Token {
    fn zeroize(&mut self) {
        match self {
            Self::Byte(byte) => byte.zeroize(),
            Self::Sgr(bytes) => bytes.zeroize(),
        }
    }
}

enum Parsed {
    Text([u8; 4], usize),
    Sgr(Vec<u8>),
}

#[derive(Default)]
enum Escape {
    #[default]
    Ground,
    Start,
    Csi(Vec<u8>),
    DiscardCsi,
    Osc(bool),
}

struct Stream {
    pending: VecDeque<Token>,
    plain: VecDeque<u8>,
    sgr_bytes: usize,
    group: Vec<Token>,
    group_bytes: usize,
    started: Option<Instant>,
    escape: Escape,
    style: Vec<u8>,
    mask: Option<(Vec<usize>, usize)>,
    utf8: Vec<u8>,
}

impl Drop for Stream {
    fn drop(&mut self) {
        self.group.zeroize();
        self.style.zeroize();
        self.utf8.zeroize();
        self.clear_hidden();
    }
}

impl Stream {
    fn new() -> Self {
        Self {
            pending: VecDeque::with_capacity(2304),
            plain: VecDeque::with_capacity(256),
            sgr_bytes: 0,
            group: Vec::with_capacity(GROUP + 128),
            group_bytes: 0,
            started: None,
            escape: Escape::Ground,
            style: Vec::new(),
            mask: None,
            utf8: Vec::with_capacity(4),
        }
    }

    // Wipe before removal: popping a ring alone leaves the old byte in its slot.
    fn pop_token(&mut self) -> Option<Token> {
        if let Some(Token::Byte(byte)) = self.pending.front_mut() {
            let value = *byte;
            byte.zeroize();
            self.pending.pop_front();
            Some(Token::Byte(value))
        } else {
            self.pending.pop_front()
        }
    }

    fn pop_plain(&mut self) {
        if let Some(byte) = self.plain.front_mut() {
            byte.zeroize();
        }
        self.plain.pop_front();
    }

    fn wipe_hidden(&mut self) {
        for token in &mut self.pending {
            token.zeroize();
        }
        for byte in &mut self.plain {
            byte.zeroize();
        }
    }

    fn clear_hidden(&mut self) {
        self.wipe_hidden();
        self.pending.clear();
        self.plain.clear();
        self.sgr_bytes = 0;
    }

    fn plain_token(&mut self, byte: u8) -> Option<Parsed> {
        if !self.utf8.is_empty() {
            if byte & 0xc0 == 0x80 {
                self.utf8.push(byte);
                let expected = match self.utf8[0] {
                    0xc2..=0xdf => 2,
                    0xe0..=0xef => 3,
                    _ => 4,
                };
                if self.utf8.len() < expected {
                    return None;
                }
                let mut bytes = [0; 4];
                let count = self.utf8.len();
                let valid = std::str::from_utf8(&self.utf8)
                    .is_ok_and(|text| !text.chars().any(char::is_control));
                bytes[..count].copy_from_slice(&self.utf8);
                self.utf8.zeroize();
                return valid.then_some(Parsed::Text(bytes, count));
            }
            self.utf8.zeroize();
        }
        match byte {
            27 => {
                self.escape = Escape::Start;
                None
            }
            b'\r' => Some(Parsed::Text([b'\n', 0, 0, 0], 1)),
            b'\n' | b'\t' | 32..=126 => Some(Parsed::Text([byte, 0, 0, 0], 1)),
            0xc2..=0xf4 => {
                self.utf8.push(byte);
                None
            }
            128..=255 => Some(Parsed::Text([b'?', 0, 0, 0], 1)),
            _ => None,
        }
    }

    fn tokenize(&mut self, byte: u8) -> Option<Parsed> {
        match std::mem::take(&mut self.escape) {
            Escape::Ground => self.plain_token(byte),
            Escape::Start => {
                self.escape = match byte {
                    b'[' => Escape::Csi(vec![27, b'[']),
                    b']' => Escape::Osc(false),
                    _ => Escape::Ground,
                };
                None
            }
            Escape::Osc(previous_escape) => {
                if byte != 7 && !(previous_escape && byte == b'\\') {
                    self.escape = Escape::Osc(byte == 27);
                }
                None
            }
            Escape::DiscardCsi => {
                if !(0x40..=0x7e).contains(&byte) {
                    self.escape = Escape::DiscardCsi;
                }
                None
            }
            Escape::Csi(mut sequence) => {
                sequence.push(byte);
                if (0x40..=0x7e).contains(&byte) {
                    if byte == b'm'
                        && sequence[2..sequence.len() - 1]
                            .iter()
                            .all(|byte| byte.is_ascii_digit() || *byte == b';')
                    {
                        return Some(Parsed::Sgr(sequence));
                    }
                } else if sequence.len() < 64 {
                    self.escape = Escape::Csi(sequence);
                } else {
                    self.escape = Escape::DiscardCsi;
                }
                None
            }
        }
    }

    fn enqueue(&mut self, token: Token, now: Instant, secrets: &[Vec<u8>]) {
        if let Some((candidates, position)) = self.mask.take() {
            if let Token::Byte(byte) = token {
                let matching = candidates
                    .into_iter()
                    .filter(|index| secrets[*index].get(position) == Some(&byte))
                    .collect::<Vec<_>>();
                if !matching.is_empty() {
                    let remaining = matching
                        .into_iter()
                        .filter(|index| secrets[*index].len() > position + 1)
                        .collect::<Vec<_>>();
                    self.mask = (!remaining.is_empty()).then_some((remaining, position + 1));
                    return;
                }
            } else {
                self.mask = Some((candidates, position));
                return;
            }
        }
        self.started.get_or_insert(now);
        match &token {
            Token::Byte(byte) => self.plain.push_back(*byte),
            Token::Sgr(bytes) => {
                // A peer sending endless SGR with no text must not grow the
                // redactor's lookbehind. Discard older formatting, not text.
                if self.sgr_bytes + bytes.len() > 2048 {
                    let text =
                        zeroize::Zeroizing::new(self.plain.iter().copied().collect::<Vec<_>>());
                    self.clear_hidden();
                    self.plain.extend(text.iter().copied());
                    self.pending.extend(text.iter().copied().map(Token::Byte));
                    self.sgr_bytes = 0;
                }
                self.sgr_bytes += bytes.len();
            }
        }
        self.pending.push_back(token);
    }

    fn release(&mut self, secrets: &[Vec<u8>], keep: usize, final_flush: bool) {
        while !self.pending.is_empty() {
            if matches!(self.pending.front(), Some(Token::Sgr(_))) {
                if let Some(Token::Sgr(bytes)) = self.pop_token() {
                    self.sgr_bytes -= bytes.len();
                    self.group_bytes += bytes.len();
                    self.group.push(Token::Sgr(bytes));
                }
                continue;
            }
            if !final_flush
                && self.plain.len() <= keep
                && secrets.iter().any(|secret| {
                    self.plain.len() < secret.len()
                        && self
                            .plain
                            .iter()
                            .copied()
                            .eq(secret.iter().take(self.plain.len()).copied())
                })
            {
                break;
            }
            let matched = secrets
                .iter()
                .filter(|secret| secret.len() <= self.plain.len())
                .filter(|secret| self.plain.front() == secret.first())
                .filter(|secret| {
                    self.plain
                        .iter()
                        .take(secret.len())
                        .copied()
                        .eq(secret.iter().copied())
                })
                .map(Vec::len)
                .max();
            if let Some(count) = matched {
                let mut removed = 0;
                while removed < count {
                    match self.pop_token() {
                        Some(Token::Byte(_)) => {
                            self.pop_plain();
                            removed += 1;
                        }
                        Some(Token::Sgr(bytes)) => self.sgr_bytes -= bytes.len(),
                        None => break,
                    }
                }
                for byte in b"[REDACTED]" {
                    self.group.push(Token::Byte(*byte));
                }
                self.group_bytes += 10;
            } else if let Some(Token::Byte(byte)) = self.pop_token() {
                self.pop_plain();
                self.group.push(Token::Byte(byte));
                self.group_bytes += 1;
            }
            // Caller invokes release after every token. At most one small
            // token/replacement can overflow a group before it is written.
            if self.group_bytes >= GROUP {
                break;
            }
        }
    }

    // At a flush deadline/EOF, withhold even a possible secret prefix instead
    // of choosing between leaking it and unbounded latency. Consume any matching
    // remainder on later packets. This can conservatively censor nonsecret text.
    fn mask_ambiguous(&mut self, secrets: &[Vec<u8>]) {
        if self.plain.is_empty() {
            return;
        }
        let candidates = secrets
            .iter()
            .enumerate()
            .filter(|(_, secret)| {
                self.plain.len() < secret.len()
                    && self
                        .plain
                        .iter()
                        .copied()
                        .eq(secret.iter().take(self.plain.len()).copied())
            })
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        if candidates.is_empty() {
            return;
        }
        self.mask = Some((candidates, self.plain.len()));
        self.clear_hidden();
        for byte in b"[REDACTED]" {
            self.group.push(Token::Byte(*byte));
        }
        self.group_bytes += 10;
    }

    fn flush(&mut self, writer: &mut dyn Write, prefix: &[u8], now: Instant) -> Result<(), String> {
        if self.group.is_empty() {
            return Ok(());
        }
        let mut frame = zeroize::Zeroizing::new(Vec::with_capacity(8192));
        frame.extend_from_slice(RESET);
        frame.extend_from_slice(prefix);
        frame.extend_from_slice(&self.style);
        let mut newline = false;
        for token in self.group.drain(..) {
            if newline {
                frame.extend_from_slice(RESET);
                frame.extend_from_slice(prefix);
                frame.extend_from_slice(&self.style);
                newline = false;
            }
            match token {
                Token::Byte(byte) => {
                    frame.push(byte);
                    newline = byte == b'\n';
                }
                Token::Sgr(bytes) => {
                    let parameters = &bytes[2..bytes.len() - 1];
                    if parameters.is_empty() || parameters == b"0" || parameters.starts_with(b"0;")
                    {
                        self.style.clear();
                    }
                    if self.style.len() + bytes.len() > 128 {
                        self.style.clear();
                        frame.extend_from_slice(RESET);
                    }
                    self.style.extend_from_slice(&bytes);
                    frame.extend_from_slice(&bytes);
                }
            }
            if frame.len() >= 7168 {
                writer
                    .write_all(&frame)
                    .map_err(|_| "SSH console output failed")?;
                frame.zeroize();
            }
        }
        frame.extend_from_slice(RESET);
        if !newline {
            frame.push(b'\n');
        }
        writer
            .write_all(&frame)
            .and_then(|()| writer.flush())
            .map_err(|_| "SSH console output failed")?;
        self.group_bytes = 0;
        self.started = (!self.pending.is_empty()).then_some(now);
        Ok(())
    }
}

/// Groups output for one host; no background thread or unbounded queue.
///
/// Groups contain at most 4 KiB plus one SGR/replacement token. Call `tick` at
/// least every 100 ms and `finish` on every exit path. Up to 64 nonempty known
/// secrets of at most 256 bytes each are matched across pushes, ignoring safe
/// SGR. Other controls/OSC are discarded. Secrets containing controls are refused.
/// Stdout/stderr have independent groups; `stderr_only` routes both to stderr.
/// Writes synchronously apply backpressure and may block if the consumer stalls.
/// This type is single-threaded: callers must serialize writes across hosts.
pub struct GroupedOutput<W: Write, E: Write> {
    streams: [Stream; 2],
    secrets: zeroize::Zeroizing<Vec<Vec<u8>>>,
    keep: usize,
    prefixes: [Vec<u8>; 2],
    stdout: W,
    stderr: E,
    stderr_only: bool,
    reverse: bool,
}

impl<W: Write, E: Write> GroupedOutput<W, E> {
    /// Creates bounded groups without writing. Alias controls are escaped.
    ///
    /// # Errors
    /// Refuses redaction sets exceeding the documented limits, without values.
    pub fn new(
        alias: &str,
        secrets: &[String],
        stdout: W,
        stderr: E,
        stderr_only: bool,
    ) -> Result<Self, String> {
        Self::from_values(
            alias,
            secrets.iter().map(String::as_str),
            stdout,
            stderr,
            stderr_only,
        )
    }

    pub(crate) fn from_values<'a>(
        alias: &str,
        values: impl IntoIterator<Item = &'a str>,
        stdout: W,
        stderr: E,
        stderr_only: bool,
    ) -> Result<Self, String> {
        let invalid = || {
            "SSH console redaction limits exceeded; output cannot be safely displayed".to_owned()
        };
        if alias.len() > 128 {
            return Err(invalid());
        }
        let mut secrets: zeroize::Zeroizing<Vec<Vec<u8>>> =
            zeroize::Zeroizing::new(Vec::with_capacity(64));
        let mut sensitive_alias = false;
        for secret in values {
            if secret.is_empty() {
                continue;
            }
            // Validate borrowed input before copying any secret bytes.
            if secret.len() > 256 || secret.chars().any(char::is_control) {
                return Err(invalid());
            }
            if secrets
                .iter()
                .any(|pattern| pattern.as_slice() == secret.as_bytes())
            {
                continue;
            }
            if secrets.len() == 64 {
                return Err(invalid());
            }
            sensitive_alias |= alias.contains(secret);
            secrets.push(secret.as_bytes().to_vec());
        }
        let keep = secrets.iter().map(Vec::len).max().unwrap_or(1) - 1;
        let mut escaped = String::new();
        for byte in (if sensitive_alias {
            "redacted-host"
        } else {
            alias
        })
        .bytes()
        {
            use std::fmt::Write as _;
            if byte.is_ascii_alphanumeric() || b"._-".contains(&byte) {
                escaped.push(char::from(byte));
            } else {
                write!(escaped, "\\x{byte:02x}").map_err(|_| "SSH alias formatting failed")?;
            }
        }
        Ok(Self {
            streams: [Stream::new(), Stream::new()],
            secrets,
            keep,
            prefixes: [
                format!("[{escaped} stdout] ").into_bytes(),
                format!("[{escaped} stderr] ").into_bytes(),
            ],
            stdout,
            stderr,
            stderr_only,
            reverse: false,
        })
    }

    /// Consumes a packet incrementally, never buffering the whole execution.
    ///
    /// # Errors
    /// Returns a redacted writer error; call `finish` even after a failure.
    pub fn push(
        &mut self,
        channel: OutputChannel,
        bytes: &[u8],
        now: Instant,
    ) -> Result<(), String> {
        let index = usize::from(channel == OutputChannel::Stderr);
        for quantum in bytes.chunks(GROUP) {
            for byte in quantum {
                if let Some(parsed) = self.streams[index].tokenize(*byte) {
                    match parsed {
                        Parsed::Text(bytes, count) => {
                            for byte in &bytes[..count] {
                                self.streams[index].enqueue(Token::Byte(*byte), now, &self.secrets);
                                self.streams[index].release(&self.secrets, self.keep, false);
                            }
                        }
                        Parsed::Sgr(bytes) => {
                            self.streams[index].enqueue(Token::Sgr(bytes), now, &self.secrets);
                            self.streams[index].release(&self.secrets, self.keep, false);
                        }
                    }
                    if self.streams[index].group_bytes >= GROUP {
                        self.flush(index, now)?;
                    }
                }
            }
            if bytes.len() > GROUP {
                self.tick(Instant::now())?;
            }
        }
        self.tick(now)
    }

    fn flush(&mut self, index: usize, now: Instant) -> Result<(), String> {
        let writer: &mut dyn Write = if index == 1 || self.stderr_only {
            &mut self.stderr
        } else {
            &mut self.stdout
        };
        self.streams[index].flush(writer, &self.prefixes[index], now)
    }

    /// Flushes ready groups after 100 ms, alternating stream priority. Ambiguous
    /// secret prefixes are conservatively censored at this boundary.
    ///
    /// # Errors
    /// Returns a redacted writer error.
    pub fn tick(&mut self, now: Instant) -> Result<(), String> {
        let ready = [0, 1].map(|index| {
            self.streams[index]
                .started
                .is_some_and(|started| now.saturating_duration_since(started) >= LATENCY)
        });
        if !ready[0] && !ready[1] {
            return Ok(());
        }
        self.reverse = !self.reverse;
        let first = usize::from(self.reverse);
        for index in [first, 1 - first] {
            if ready[index] {
                self.streams[index].mask_ambiguous(&self.secrets);
                self.flush(index, now)?;
            }
        }
        Ok(())
    }

    /// Flushes both final groups and redaction tails, discarding incomplete
    /// escapes. Attempts both streams even if one writer fails; preserves first error.
    ///
    /// # Errors
    /// Returns a redacted writer error. No remote/secret values are echoed.
    pub fn finish(&mut self) -> Result<(), String> {
        let now = Instant::now();
        let mut error = None;
        for index in 0..2 {
            self.streams[index].escape = Escape::Ground;
            self.streams[index].utf8.zeroize();
            self.streams[index].mask_ambiguous(&self.secrets);
            while !self.streams[index].pending.is_empty() {
                self.streams[index].release(&self.secrets, self.keep, true);
                if let Err(message) = self.flush(index, now) {
                    error.get_or_insert(message);
                    break;
                }
            }
            if let Err(message) = self.flush(index, now) {
                error.get_or_insert(message);
            }
        }
        error.map_or(Ok(()), Err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Critical memory-boundary assertions cannot be observed through a writer.
    #[test]
    fn hidden_prefix_storage_is_bounded_and_wiped_before_logical_clear() {
        let secret = "x".repeat(256);
        let mut output = GroupedOutput::from_values(
            "fixture",
            [secret.as_str()],
            std::io::sink(),
            std::io::sink(),
            false,
        )
        .unwrap();
        let now = Instant::now();
        output
            .push(OutputChannel::Stdout, &vec![b'x'; 255], now)
            .unwrap();
        let stream = &mut output.streams[0];
        assert_eq!(stream.plain.len(), 255);
        assert_eq!(stream.pending.len(), 255);
        let capacities = (stream.plain.capacity(), stream.pending.capacity());
        stream.wipe_hidden();
        assert!(stream.plain.iter().all(|byte| *byte == 0));
        assert!(
            stream
                .pending
                .iter()
                .all(|token| matches!(token, Token::Byte(0)))
        );
        stream.clear_hidden();
        assert_eq!(
            capacities,
            (stream.plain.capacity(), stream.pending.capacity())
        );
        // Long output reuses the same rings; it does not retain the execution.
        output
            .push(OutputChannel::Stdout, &vec![b'x'; 128 * 1024], now)
            .unwrap();
        assert_eq!(
            capacities,
            (
                output.streams[0].plain.capacity(),
                output.streams[0].pending.capacity()
            )
        );
        assert!(output.streams[0].plain.len() <= 255);
        assert!(output.streams[0].pending.len() <= 255);
    }

    // Exact allocation/redaction bounds are a critical hot-path contract.
    #[test]
    fn borrowed_patterns_are_deduplicated_bounded_and_zeroizing() {
        let values = (0..64)
            .map(|index| format!("{index:03}{}", "x".repeat(253)))
            .collect::<Vec<_>>();
        let mut output = GroupedOutput::from_values(
            "fixture",
            values.iter().map(String::as_str).cycle().take(128),
            std::io::sink(),
            std::io::sink(),
            false,
        )
        .unwrap();
        assert_eq!(output.secrets.len(), 64);
        assert_eq!(
            output.secrets.iter().map(Vec::len).sum::<usize>(),
            16 * 1024
        );
        assert!(
            GroupedOutput::from_values(
                "fixture",
                values.iter().map(String::as_str).chain(["another"]),
                std::io::sink(),
                std::io::sink(),
                false,
            )
            .is_err()
        );
        assert!(
            GroupedOutput::from_values(
                "fixture",
                ["x".repeat(257).as_str()],
                std::io::sink(),
                std::io::sink(),
                false,
            )
            .is_err()
        );
        output.secrets.zeroize();
        assert!(output.secrets.is_empty());
    }
}
