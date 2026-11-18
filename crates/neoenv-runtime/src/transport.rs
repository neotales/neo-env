//! Shared network transport deadlines, response limits, and diagnostic redaction.

use std::{
    env, fmt,
    io::{self, Read},
    sync::Arc,
    time::Duration,
};

use url::Url;

use crate::budget::{BudgetReader, ResourceBudget, ResourceLimit};

const DEFAULT_CONNECT_TIMEOUT_SECONDS: u64 = 10;
const MAXIMUM_CONNECT_TIMEOUT_SECONDS: u64 = 60;
const DEFAULT_READ_IDLE_TIMEOUT_SECONDS: u64 = 30;
const MAXIMUM_READ_IDLE_TIMEOUT_SECONDS: u64 = 120;
const DEFAULT_TOTAL_TIMEOUT_SECONDS: u64 = 600;
const MAXIMUM_TOTAL_TIMEOUT_SECONDS: u64 = 1_800;
const DEFAULT_GIT_TIMEOUT_SECONDS: u64 = 120;
const MAXIMUM_GIT_TIMEOUT_SECONDS: u64 = 600;
const BODY_READ_BUFFER_BYTES: usize = 8 * 1024;

/// The default cap for metadata and other buffered HTTP response bodies.
pub const DEFAULT_HTTP_BODY_LIMIT_BYTES: usize = 8 * 1024 * 1024;

/// A rejected timeout environment variable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TimeoutPolicyError {
    variable: &'static str,
    maximum_seconds: u64,
}

impl fmt::Display for TimeoutPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} must be a positive integer no greater than {} seconds",
            self.variable, self.maximum_seconds
        )
    }
}

impl std::error::Error for TimeoutPolicyError {}

/// The one HTTP policy used by every `nenv` HTTP request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HttpPolicy {
    connect_timeout: Duration,
    read_idle_timeout: Duration,
    total_timeout: Duration,
    body_limit: usize,
}

impl HttpPolicy {
    /// Loads HTTP deadlines from the process environment.
    ///
    /// # Errors
    ///
    /// Returns a validation error when a configured value is not a positive
    /// integer or exceeds the documented maximum.
    pub fn from_environment() -> Result<Self, TimeoutPolicyError> {
        let connect = environment_value("NEOENV_HTTP_CONNECT_TIMEOUT")?;
        let read_idle = environment_value("NEOENV_HTTP_READ_IDLE_TIMEOUT")?;
        let total = environment_value("NEOENV_HTTP_TOTAL_TIMEOUT")?;
        Self::from_values(connect.as_deref(), read_idle.as_deref(), total.as_deref())
    }

    /// Performs a GET without following redirects.
    ///
    /// # Errors
    ///
    /// Returns a credential-safe request error.
    pub fn get(&self, url: &str) -> Result<ureq::Response, HttpError> {
        self.call(url, 0, None)
    }

    /// Performs a GET with one explicit header and without following redirects.
    ///
    /// # Errors
    ///
    /// Returns a credential-safe request error.
    pub fn get_with_header(
        &self,
        url: &str,
        name: &str,
        value: &str,
    ) -> Result<ureq::Response, HttpError> {
        self.call(url, 0, Some((name, value)))
    }

    /// Performs a GET with an explicit redirect limit.
    ///
    /// This exists only for call sites with a documented redirect requirement;
    /// ordinary requests must use [`Self::get`].
    ///
    /// # Errors
    ///
    /// Returns a credential-safe request error.
    pub fn get_with_redirects(
        &self,
        url: &str,
        redirects: u32,
    ) -> Result<ureq::Response, HttpError> {
        self.call(url, redirects, None)
    }

    /// Reads and caps one buffered response body.
    ///
    /// # Errors
    ///
    /// Returns a credential-safe read, size, or UTF-8 error. No byte beyond
    /// `body_limit` is retained in the returned buffer.
    pub fn read_body(&self, url: &str, response: ureq::Response) -> Result<Vec<u8>, HttpError> {
        read_body_bytes(redacted_url(url), response.into_reader(), self.body_limit)
    }

    /// Reads and caps one buffered response body, then validates UTF-8.
    ///
    /// # Errors
    ///
    /// Returns a credential-safe read, size, or UTF-8 error.
    pub fn read_text(&self, url: &str, response: ureq::Response) -> Result<String, HttpError> {
        String::from_utf8(self.read_body(url, response)?).map_err(|source| HttpError::InvalidUtf8 {
            target: redacted_url(url),
            source: Arc::new(source),
        })
    }

    /// Wraps a streaming response body with sanitized I/O diagnostics.
    ///
    /// Streaming bodies remain uncapped for callers that only need transport
    /// deadlines.  Artifact callers must use [`Self::streaming_reader_limited`]
    /// so a download cannot grow without bound.
    #[must_use]
    pub fn streaming_reader(&self, url: &str, response: ureq::Response) -> HttpBodyReader {
        HttpBodyReader {
            target: redacted_url(url),
            reader: response.into_reader(),
        }
    }

    /// Rejects a declared artifact response length before reading its body.
    ///
    /// # Errors
    ///
    /// Returns a stable artifact-limit error when `Content-Length` is larger
    /// than `limit`.
    pub fn validate_artifact_length(
        &self,
        url: &str,
        response: &ureq::Response,
        limit: u64,
    ) -> Result<(), HttpError> {
        if response
            .header("Content-Length")
            .and_then(|value| value.parse::<u64>().ok())
            .is_some_and(|length| length > limit)
        {
            return Err(HttpError::ArtifactTooLarge {
                target: redacted_url(url),
                limit,
            });
        }
        Ok(())
    }

    /// Wraps a streaming response body with a byte limit enforced by the
    /// reader itself.  No bytes beyond `limit` are returned to the caller.
    #[must_use]
    pub fn streaming_reader_limited(
        &self,
        url: &str,
        response: ureq::Response,
        limit: u64,
    ) -> BudgetReader<HttpBodyReader> {
        BudgetReader::new(
            self.streaming_reader(url, response),
            ResourceLimit::Artifact,
            limit,
        )
    }

    fn from_values(
        connect: Option<&str>,
        read_idle: Option<&str>,
        total: Option<&str>,
    ) -> Result<Self, TimeoutPolicyError> {
        Ok(Self {
            connect_timeout: parse_timeout(
                "NEOENV_HTTP_CONNECT_TIMEOUT",
                connect,
                DEFAULT_CONNECT_TIMEOUT_SECONDS,
                MAXIMUM_CONNECT_TIMEOUT_SECONDS,
            )?,
            read_idle_timeout: parse_timeout(
                "NEOENV_HTTP_READ_IDLE_TIMEOUT",
                read_idle,
                DEFAULT_READ_IDLE_TIMEOUT_SECONDS,
                MAXIMUM_READ_IDLE_TIMEOUT_SECONDS,
            )?,
            total_timeout: parse_timeout(
                "NEOENV_HTTP_TOTAL_TIMEOUT",
                total,
                DEFAULT_TOTAL_TIMEOUT_SECONDS,
                MAXIMUM_TOTAL_TIMEOUT_SECONDS,
            )?,
            body_limit: usize::try_from(ResourceBudget::defaults().http_body_bytes)
                .unwrap_or(DEFAULT_HTTP_BODY_LIMIT_BYTES),
        })
    }

    fn call(
        &self,
        url: &str,
        redirects: u32,
        header: Option<(&str, &str)>,
    ) -> Result<ureq::Response, HttpError> {
        let target = redacted_url(url);
        let request = ureq::AgentBuilder::new()
            .timeout_connect(self.connect_timeout)
            .timeout_read(self.read_idle_timeout)
            .timeout(self.total_timeout)
            .redirects(redirects)
            .user_agent(concat!("nenv/", env!("CARGO_PKG_VERSION")))
            .build()
            .get(url);
        let request = match header {
            Some((name, value)) => request.set(name, value),
            None => request,
        };
        request
            .call()
            .map_err(|error| HttpError::request(target, error))
    }
}

#[derive(Clone, Debug)]
pub enum HttpError {
    Request {
        target: String,
        kind: ureq::ErrorKind,
        status: Option<u16>,
        source: Arc<ureq::Error>,
    },
    BodyTooLarge {
        target: String,
        limit: usize,
    },
    ArtifactTooLarge {
        target: String,
        limit: u64,
    },
    BodyRead {
        target: String,
        source: Arc<io::Error>,
    },
    InvalidUtf8 {
        target: String,
        source: Arc<std::string::FromUtf8Error>,
    },
}

impl HttpError {
    fn request(target: String, error: ureq::Error) -> Self {
        let kind = error.kind();
        let status = match &error {
            ureq::Error::Status(status, _) => Some(*status),
            ureq::Error::Transport(_) => None,
        };
        Self::Request {
            target,
            kind,
            status,
            source: Arc::new(error),
        }
    }

    fn body_read(target: String, source: io::Error) -> Self {
        Self::BodyRead {
            target,
            source: Arc::new(source),
        }
    }
}

impl PartialEq for HttpError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                Self::Request {
                    target,
                    kind,
                    status,
                    ..
                },
                Self::Request {
                    target: other_target,
                    kind: other_kind,
                    status: other_status,
                    ..
                },
            ) => target == other_target && kind == other_kind && status == other_status,
            (
                Self::BodyTooLarge { target, limit },
                Self::BodyTooLarge {
                    target: other_target,
                    limit: other_limit,
                },
            ) => target == other_target && limit == other_limit,
            (
                Self::ArtifactTooLarge { target, limit },
                Self::ArtifactTooLarge {
                    target: other_target,
                    limit: other_limit,
                },
            ) => target == other_target && limit == other_limit,
            (
                Self::BodyRead { target, .. },
                Self::BodyRead {
                    target: other_target,
                    ..
                },
            )
            | (
                Self::InvalidUtf8 { target, .. },
                Self::InvalidUtf8 {
                    target: other_target,
                    ..
                },
            ) => target == other_target,
            _ => false,
        }
    }
}

impl Eq for HttpError {}

impl fmt::Display for HttpError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Request {
                target,
                status: Some(status),
                ..
            } => write!(
                formatter,
                "HTTP request to {target} returned status {status}"
            ),
            Self::Request {
                target,
                kind,
                status: None,
                ..
            } => write!(formatter, "HTTP request to {target} failed: {kind}"),
            Self::BodyTooLarge { target, limit } => write!(
                formatter,
                "resource budget exceeded: HTTP response body from {target} exceeds the {limit}-byte limit"
            ),
            Self::ArtifactTooLarge { target, limit } => write!(
                formatter,
                "resource budget exceeded: downloaded artifact from {target} exceeds the {limit}-byte limit"
            ),
            Self::BodyRead { target, .. } => {
                write!(formatter, "failed to read HTTP response body from {target}")
            }
            Self::InvalidUtf8 { target, .. } => {
                write!(formatter, "HTTP response body from {target} is not UTF-8")
            }
        }
    }
}

impl std::error::Error for HttpError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Request { source, .. } => Some(source.as_ref()),
            Self::BodyRead { source, .. } => Some(source.as_ref()),
            Self::InvalidUtf8 { source, .. } => Some(source.as_ref()),
            Self::BodyTooLarge { .. } | Self::ArtifactTooLarge { .. } => None,
        }
    }
}

/// A streaming HTTP response body whose I/O errors contain only a redacted target.
pub struct HttpBodyReader {
    target: String,
    reader: Box<dyn Read + Send + Sync + 'static>,
}

impl Read for HttpBodyReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.reader
            .read(buffer)
            .map_err(|source| io::Error::other(HttpError::body_read(self.target.clone(), source)))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct GitPolicy {
    pub(crate) timeout: Duration,
}

impl GitPolicy {
    pub(crate) fn from_environment() -> Result<Self, TimeoutPolicyError> {
        let timeout = environment_value("NEOENV_GIT_TIMEOUT")?;
        Self::from_value(timeout.as_deref())
    }

    fn from_value(value: Option<&str>) -> Result<Self, TimeoutPolicyError> {
        Ok(Self {
            timeout: parse_timeout(
                "NEOENV_GIT_TIMEOUT",
                value,
                DEFAULT_GIT_TIMEOUT_SECONDS,
                MAXIMUM_GIT_TIMEOUT_SECONDS,
            )?,
        })
    }
}

fn environment_value(name: &'static str) -> Result<Option<String>, TimeoutPolicyError> {
    match env::var_os(name) {
        None => Ok(None),
        Some(value) => value.into_string().map(Some).map_err(|_| invalid(name)),
    }
}

fn invalid(name: &'static str) -> TimeoutPolicyError {
    TimeoutPolicyError {
        variable: name,
        maximum_seconds: maximum_for(name),
    }
}

fn parse_timeout(
    name: &'static str,
    value: Option<&str>,
    default: u64,
    maximum: u64,
) -> Result<Duration, TimeoutPolicyError> {
    let seconds = value.map_or(Ok(default), |value| {
        if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(invalid(name));
        }
        value
            .parse::<u64>()
            .ok()
            .filter(|seconds| *seconds > 0 && *seconds <= maximum)
            .ok_or_else(|| invalid(name))
    })?;
    Ok(Duration::from_secs(seconds))
}

const fn maximum_for(name: &'static str) -> u64 {
    match name.as_bytes() {
        b"NEOENV_HTTP_CONNECT_TIMEOUT" => MAXIMUM_CONNECT_TIMEOUT_SECONDS,
        b"NEOENV_HTTP_READ_IDLE_TIMEOUT" => MAXIMUM_READ_IDLE_TIMEOUT_SECONDS,
        b"NEOENV_HTTP_TOTAL_TIMEOUT" => MAXIMUM_TOTAL_TIMEOUT_SECONDS,
        b"NEOENV_GIT_TIMEOUT" => MAXIMUM_GIT_TIMEOUT_SECONDS,
        _ => 0,
    }
}

fn read_body_bytes(
    target: String,
    mut reader: impl Read,
    limit: usize,
) -> Result<Vec<u8>, HttpError> {
    let mut output = Vec::with_capacity(limit.min(BODY_READ_BUFFER_BYTES));
    let mut buffer = [0_u8; BODY_READ_BUFFER_BYTES];
    let mut remaining = limit;
    loop {
        let count = reader
            .read(&mut buffer)
            .map_err(|source| HttpError::body_read(target.clone(), source))?;
        if count == 0 {
            return Ok(output);
        }
        if count > remaining {
            return Err(HttpError::BodyTooLarge { target, limit });
        }
        output.extend_from_slice(&buffer[..count]);
        remaining -= count;
    }
}

/// Returns an HTTP URL containing only its scheme, host, and path.
///
/// Userinfo, query parameters, and fragments are removed because redirect
/// targets and signed URLs can carry credentials in those components.
#[must_use]
pub fn redacted_url(value: &str) -> String {
    let Ok(mut url) = Url::parse(value) else {
        return "<invalid HTTP URL>".into();
    };
    let _ = url.set_username("");
    let _ = url.set_password(None);
    url.set_query(None);
    url.set_fragment(None);
    url.to_string()
}

/// Removes URL secrets from arbitrary diagnostic text while retaining stderr context.
pub(crate) fn redact_url_secrets(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    let mut cursor = 0;
    while let Some(relative_colon) = value[cursor..].find("://") {
        let colon = cursor + relative_colon;
        let mut scheme_start = colon;
        while scheme_start > cursor {
            let byte = value.as_bytes()[scheme_start - 1];
            if byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.') {
                scheme_start -= 1;
            } else {
                break;
            }
        }
        if scheme_start == colon {
            cursor = colon + 3;
            continue;
        }
        let authority_start = colon + 3;
        let url_end = value[authority_start..]
            .find(|character: char| {
                character.is_ascii_whitespace()
                    || character.is_ascii_control()
                    || matches!(character, '<' | '>' | '"' | '\'' | ')' | ']' | '}')
            })
            .map_or(value.len(), |offset| authority_start + offset);
        let authority_end = value[authority_start..url_end]
            .find(['/', '?', '#'])
            .map_or(url_end, |offset| authority_start + offset);
        let safe_end = value[authority_start..url_end]
            .find(['?', '#'])
            .map_or(url_end, |offset| authority_start + offset);
        let userinfo_end = value[authority_start..authority_end]
            .rfind('@')
            .map_or(authority_start, |offset| authority_start + offset + 1);

        if userinfo_end > authority_start || safe_end < url_end {
            output.push_str(&value[cursor..authority_start]);
            output.push_str(&value[userinfo_end..safe_end]);
        } else {
            output.push_str(&value[cursor..url_end]);
        }
        cursor = url_end;
    }
    output.push_str(&value[cursor..]);
    output
}

#[cfg(test)]
mod tests {
    use std::{
        error::Error as _,
        io::{Cursor, Read as _, Write as _},
        net::TcpListener,
        panic::AssertUnwindSafe,
        sync::mpsc,
        thread,
        time::{Duration, Instant},
    };

    use super::{DEFAULT_HTTP_BODY_LIMIT_BYTES, GitPolicy, HttpError, HttpPolicy, redacted_url};

    #[test]
    fn timeout_defaults_and_rejected_values_are_explicit() {
        let defaults = HttpPolicy::from_values(None, None, None).unwrap();
        assert_eq!(defaults.connect_timeout, Duration::from_secs(10));
        assert_eq!(defaults.read_idle_timeout, Duration::from_secs(30));
        assert_eq!(defaults.total_timeout, Duration::from_secs(600));
        assert_eq!(defaults.body_limit, DEFAULT_HTTP_BODY_LIMIT_BYTES);
        assert_eq!(
            GitPolicy::from_value(None).unwrap().timeout,
            Duration::from_secs(120)
        );

        for invalid in ["", "0", "-1", "1.5", " 1", "+1"] {
            assert!(HttpPolicy::from_values(Some(invalid), None, None).is_err());
            assert!(HttpPolicy::from_values(None, Some(invalid), None).is_err());
            assert!(HttpPolicy::from_values(None, None, Some(invalid)).is_err());
            assert!(GitPolicy::from_value(Some(invalid)).is_err());
        }
        assert!(HttpPolicy::from_values(Some("61"), None, None).is_err());
        assert!(HttpPolicy::from_values(None, Some("121"), None).is_err());
        assert!(HttpPolicy::from_values(None, None, Some("1801")).is_err());
        assert!(GitPolicy::from_value(Some("601")).is_err());

        let maximums = HttpPolicy::from_values(Some("60"), Some("120"), Some("1800")).unwrap();
        assert_eq!(maximums.connect_timeout, Duration::from_secs(60));
        assert_eq!(maximums.read_idle_timeout, Duration::from_secs(120));
        assert_eq!(maximums.total_timeout, Duration::from_mins(30));
        assert_eq!(
            GitPolicy::from_value(Some("600")).unwrap().timeout,
            Duration::from_secs(600)
        );
    }

    #[test]
    fn stalled_loopback_times_out_without_public_name_resolution() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (release_sender, release_receiver) = mpsc::channel();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request).unwrap();
            release_receiver.recv().unwrap();
        });
        let policy = HttpPolicy {
            connect_timeout: Duration::from_secs(1),
            read_idle_timeout: Duration::from_secs(5),
            total_timeout: Duration::from_secs(1),
            body_limit: DEFAULT_HTTP_BODY_LIMIT_BYTES,
        };

        let started = Instant::now();
        let result = policy.get(&format!("http://{address}/stalled"));
        let elapsed = started.elapsed();
        release_sender.send(()).unwrap();
        server.join().unwrap();

        assert!(result.is_err());
        assert!(
            elapsed < Duration::from_secs(2),
            "HTTP call exceeded its total deadline plus grace: {elapsed:?}"
        );
    }

    #[test]
    fn ordinary_requests_do_not_follow_redirects() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request).unwrap();
            write!(
                stream,
                "HTTP/1.1 302 Found\r\nLocation: http://{address}/redirected\r\nContent-Length: 0\r\n\r\n"
            )
            .unwrap();
        });
        let response = HttpPolicy::from_values(None, None, None)
            .unwrap()
            .get(&format!("http://{address}/start"))
            .unwrap();
        server.join().unwrap();
        assert_eq!(response.status(), 302);
    }

    #[test]
    fn malformed_http_response_retains_the_transport_source() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request).unwrap();
            let _ = stream.write_all(b"not-an-http-response\r\n\r\n");
        });

        let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
            HttpPolicy::from_values(None, None, None)
                .unwrap()
                .get(&format!("http://{address}/malformed"))
        }));
        server.join().unwrap();
        let error = result
            .expect("malformed HTTP response must not panic")
            .unwrap_err();

        assert!(
            error
                .source()
                .and_then(|source| source.downcast_ref::<ureq::Error>())
                .is_some()
        );
    }

    #[test]
    fn buffered_body_limit_fails_without_retaining_the_overflow() {
        let error =
            super::read_body_bytes("http://127.0.0.1/body".into(), Cursor::new(b"123456789"), 8)
                .unwrap_err();
        assert!(matches!(error, HttpError::BodyTooLarge { limit: 8, .. }));
    }

    #[test]
    fn git_stderr_redaction_preserves_clean_urls() {
        let clean = "fatal: unable to access 'https://github.com/owner/repo.git/'";
        assert_eq!(super::redact_url_secrets(clean), clean);
    }

    #[test]
    fn diagnostic_targets_remove_userinfo_query_and_fragment() {
        let redacted = redacted_url("https://alice:secret@example.test/path?token=value#fragment");
        assert_eq!(redacted, "https://example.test/path");
        let diagnostic = format!("request failed: {redacted}");
        assert!(!diagnostic.contains("alice"));
        assert!(!diagnostic.contains("secret"));
        assert!(!diagnostic.contains("token"));
    }
}
