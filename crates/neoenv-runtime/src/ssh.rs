//! Strict, non-interactive SSH/SCP. Authorization belongs to the caller.

use crate::ssh_output::{GroupedOutput, OutputChannel};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use neoenv_config::{Inventory, InventoryHost};
use neotales_ssh::{ClientAuthMethod, ClientConfig, ClientSessions, SshClient};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use std::{
    cell::RefCell,
    collections::BTreeMap,
    io::{self, Read, Write},
    net::{IpAddr, SocketAddr, TcpStream},
    path::{Component, Path, PathBuf},
    rc::Rc,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

type Console = Rc<RefCell<GroupedOutput<Box<dyn Write>, Box<dyn Write>>>>;

/// Legacy subject for agent or password authentication. Identity-file
/// declarations return a non-executable sentinel; use [`Endpoint::subject`] or
/// [`endpoint_subject_with_context`] with the same resolution inputs.
#[deprecated(note = "use Endpoint::subject or endpoint_subject_with_context")]
#[must_use]
pub fn endpoint_subject(inventory: &Inventory, name: &str) -> String {
    let identity = inventory
        .hosts
        .get(name)
        .and_then(|host| host.identity_file.as_ref())
        .or(inventory.defaults.identity_file.as_ref());
    if identity.is_some() {
        return neoenv_policy::RESERVED_SSH_IDENTITY_SUBJECT.to_owned();
    }
    endpoint_subject_fields(inventory, name, None)
}

/// Binds the grant to the exact resolved identity path without exposing it.
///
/// # Errors
/// Refuses invalid identity paths and missing home values.
pub fn endpoint_subject_with_context(
    inventory: &Inventory,
    name: &str,
    environment: &BTreeMap<String, String>,
    project_root: &Path,
) -> Result<String, String> {
    let host = inventory.hosts.get(name);
    let identity = host
        .and_then(|host| host.identity_file.as_ref())
        .or(inventory.defaults.identity_file.as_ref());
    let identity_hash = identity
        .map(|path| resolve_identity_path(path, environment, project_root))
        .transpose()?
        .map(|path| format!("{:x}", Sha256::digest(path.as_os_str().as_encoded_bytes())));
    Ok(endpoint_subject_fields(inventory, name, identity_hash))
}

fn endpoint_subject_fields(
    inventory: &Inventory,
    name: &str,
    identity_hash: Option<String>,
) -> String {
    let host = inventory.hosts.get(name);
    let optional =
        |value: Option<&String>| value.map_or(Value::Null, |value| Value::String(value.clone()));
    let fields = Value::Array(vec![
        Value::String(name.to_owned()),
        Value::String(inventory.address_of(name)),
        optional(
            host.and_then(|host| host.user.as_ref())
                .or(inventory.defaults.user.as_ref()),
        ),
        Value::from(
            host.and_then(|host| host.port)
                .or(inventory.defaults.port)
                .unwrap_or(22),
        ),
        optional(host.and_then(|host| host.host_key.as_ref())),
        optional(host.and_then(|host| host.password_env.as_ref())),
        identity_hash.map_or(Value::Null, Value::String),
        Value::Bool(host.is_some_and(|host| host.password_auth)),
    ]);
    format!(
        "ssh-endpoint:{:x}",
        Sha256::digest(fields.to_string().as_bytes())
    )
}

/// A validated endpoint and explicit credential. Debug intentionally omits all
/// fields. Passwords are wiped when this value drops. SSH configuration is not
/// discovered. Numeric addresses avoid unbounded synchronous DNS resolution.
pub struct Endpoint {
    address: SocketAddr,
    user: String,
    pin: neotales_ssh::hostkey::Ed25519PublicKey,
    authentication: Authentication,
    subject: String,
}

enum Authentication {
    Identity {
        path: PathBuf,
        passphrase: Option<Zeroizing<String>>,
    },
    Agent,
    Password(Zeroizing<String>),
}

impl Authentication {
    fn secret(&self) -> Option<&str> {
        match self {
            Self::Identity { passphrase, .. } => passphrase.as_deref().map(String::as_str),
            Self::Password(password) => Some(password.as_str()),
            Self::Agent => None,
        }
    }
}

impl std::fmt::Debug for Endpoint {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("Endpoint").finish_non_exhaustive()
    }
}

impl Endpoint {
    /// The exact opaque capability subject paired with this resolved endpoint.
    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// Resolves one host relative to the process working directory.
    ///
    /// For project-relative behavior, use [`Self::resolve_with_root`].
    ///
    /// # Errors
    /// Returns static redacted messages for invalid/missing configuration.
    pub fn resolve(
        inventory: &Inventory,
        name: &str,
        environment: &BTreeMap<String, String>,
    ) -> Result<Self, String> {
        let root = std::env::current_dir().map_err(|_| "SSH current directory is unavailable")?;
        Self::resolve_with_root(inventory, name, environment, &root)
    }

    /// Resolves one host using explicit values, never the process environment.
    /// Only numeric IPs and Ed25519 host pins are implemented. An explicit
    /// identity file wins; otherwise the SSH agent is used by default.
    /// Password login requires `password_auth: true`.
    /// Relative identities are anchored at the absolute project root; `~` and
    /// `~/` use HOME in the provided environment (USERPROFILE on Windows).
    ///
    /// # Errors
    /// Returns static redacted messages for invalid/missing configuration.
    pub fn resolve_with_root(
        inventory: &Inventory,
        name: &str,
        environment: &BTreeMap<String, String>,
        project_root: &Path,
    ) -> Result<Self, String> {
        let host = inventory
            .hosts
            .get(name)
            .ok_or("SSH host is not declared")?;
        let address: IpAddr = inventory
            .address_of(name)
            .parse()
            .map_err(|_| "SSH address must be a numeric IPv4 or IPv6 address")?;
        let user = host
            .user
            .as_ref()
            .or(inventory.defaults.user.as_ref())
            .filter(|user| {
                !user.is_empty() && user.len() <= 256 && !user.chars().any(char::is_control)
            })
            .ok_or("SSH requires an explicit user")?
            .clone();
        let port = host.port.or(inventory.defaults.port).unwrap_or(22);
        if port == 0 {
            return Err("SSH port must be positive".into());
        }
        let pin = host.host_key.as_ref().ok_or("SSH requires host_key")?;
        let blob = STANDARD
            .decode(pin)
            .map_err(|_| "SSH host_key is not valid base64")?;
        let pin = neotales_ssh::hostkey::Ed25519PublicKey::from_blob(&blob)
            .map_err(|_| "SSH host_key must be an Ed25519 public key blob")?;
        let identity = host
            .identity_file
            .as_ref()
            .or(inventory.defaults.identity_file.as_ref());
        let authentication = if let Some(path) = identity {
            if path.is_empty() || path.chars().any(char::is_control) {
                return Err("SSH identity_file is invalid".into());
            }
            let passphrase = host
                .password_env
                .as_ref()
                .map(|key| environment_value(key, environment))
                .transpose()?;
            Authentication::Identity {
                path: resolve_identity_path(path, environment, project_root)?,
                passphrase,
            }
        } else if host.password_auth {
            Authentication::Password(password(host, environment)?)
        } else {
            Authentication::Agent
        };
        let subject = endpoint_subject_with_context(inventory, name, environment, project_root)?;
        Ok(Self {
            address: SocketAddr::new(address, port),
            user,
            pin,
            authentication,
            subject,
        })
    }
}

fn resolve_identity_path(
    value: &str,
    environment: &BTreeMap<String, String>,
    project_root: &Path,
) -> Result<PathBuf, String> {
    if value.is_empty() || value.chars().any(char::is_control) {
        return Err("SSH identity_file is invalid".into());
    }
    let path = if value == "~" || value.starts_with("~/") {
        #[cfg(windows)]
        let home_key = "USERPROFILE";
        #[cfg(not(windows))]
        let home_key = "HOME";
        let home = environment
            .get(home_key)
            .filter(|value| !value.is_empty())
            .ok_or("SSH identity home is unavailable")?;
        let home = Path::new(home);
        if !home.is_absolute() {
            return Err("SSH identity home must be absolute".into());
        }
        if value == "~" {
            home.to_path_buf()
        } else {
            let suffix = Path::new(&value[2..]);
            if suffix.components().any(|component| {
                matches!(
                    component,
                    Component::RootDir | Component::Prefix(_) | Component::ParentDir
                )
            }) {
                return Err("SSH identity home suffix is invalid".into());
            }
            home.join(suffix)
        }
    } else if value.starts_with('~') {
        return Err("SSH identity ~user paths are not supported".into());
    } else {
        let path = Path::new(value);
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            if !project_root.is_absolute() {
                return Err("SSH project root must be absolute".into());
            }
            project_root.join(path)
        }
    };
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err("SSH identity path cannot contain ..".into());
    }
    Ok(path.components().collect())
}

fn password(
    host: &InventoryHost,
    environment: &BTreeMap<String, String>,
) -> Result<Zeroizing<String>, String> {
    let key = host
        .password_env
        .as_ref()
        .filter(|key| neoenv_core::tasks::valid_environment_key(key))
        .ok_or("SSH requires a valid password_env name")?;
    environment
        .get(key)
        .filter(|value| !value.is_empty())
        .map(|value| Zeroizing::new(value.clone()))
        .ok_or("SSH password_env is unset or empty".into())
}

fn environment_value(
    key: &str,
    environment: &BTreeMap<String, String>,
) -> Result<Zeroizing<String>, String> {
    if !neoenv_core::tasks::valid_environment_key(key) {
        return Err("SSH password_env name is invalid".into());
    }
    environment
        .get(key)
        .map(|value| Zeroizing::new(value.clone()))
        .ok_or("SSH password_env is unset".into())
}

// A shrinking overall deadline, not a timeout that resets after every packet.
// The total wire budget bounds buffered convenience-client output too.
struct DeadlineStream {
    stream: TcpStream,
    deadline: Instant,
    remaining: usize,
    cancellation: Option<crate::tasks::TaskCancellation>,
    console: Option<Console>,
}
impl DeadlineStream {
    fn remaining_time(&self) -> io::Result<Duration> {
        if let Some(console) = &self.console {
            console
                .borrow_mut()
                .tick(Instant::now())
                .map_err(|_| io::Error::other("SSH console output failed"))?;
        }
        if self
            .cancellation
            .as_ref()
            .is_some_and(crate::tasks::TaskCancellation::is_cancelled)
        {
            return Err(io::Error::other("SSH cancelled"));
        }
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|time| !time.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "SSH deadline exceeded"))
    }
}
impl Read for DeadlineStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        loop {
            self.stream
                .set_read_timeout(Some(self.remaining_time()?.min(Duration::from_millis(100))))?;
            if self.remaining == 0 {
                return Err(io::Error::other("SSH wire budget exceeded"));
            }
            let limit = buffer.len().min(self.remaining);
            match self.stream.read(&mut buffer[..limit]) {
                Ok(count) => {
                    self.remaining -= count;
                    return Ok(count);
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                    ) => {}
                Err(error) => return Err(error),
            }
        }
    }
}
impl Write for DeadlineStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        loop {
            self.stream
                .set_write_timeout(Some(self.remaining_time()?.min(Duration::from_millis(100))))?;
            match self.stream.write(buffer) {
                Ok(count) => return Ok(count),
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                    ) => {}
                Err(error) => return Err(error),
            }
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

// The agent signer owns clones of this stream, so every enumeration and sign
// operation shares the same absolute deadline and cancellation flag.
#[cfg(target_os = "linux")]
struct DeadlineAgent {
    stream: std::os::unix::net::UnixStream,
    deadline: Instant,
    cancellation: Option<crate::tasks::TaskCancellation>,
}

#[cfg(target_os = "linux")]
impl DeadlineAgent {
    fn try_clone(&self) -> io::Result<Self> {
        Ok(Self {
            stream: self.stream.try_clone()?,
            deadline: self.deadline,
            cancellation: self.cancellation.clone(),
        })
    }

    fn wait(&self) -> io::Result<()> {
        if self
            .cancellation
            .as_ref()
            .is_some_and(crate::tasks::TaskCancellation::is_cancelled)
        {
            return Err(io::Error::other("SSH cancelled"));
        }
        let remaining = self
            .deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "SSH deadline exceeded"))?;
        std::thread::sleep(remaining.min(Duration::from_millis(10)));
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl Read for DeadlineAgent {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        loop {
            if self
                .cancellation
                .as_ref()
                .is_some_and(crate::tasks::TaskCancellation::is_cancelled)
                || Instant::now() >= self.deadline
            {
                return self.wait().and(Err(io::Error::other("SSH agent stopped")));
            }
            match self.stream.read(buffer) {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => self.wait()?,
                result => return result,
            }
        }
    }
}

#[cfg(target_os = "linux")]
impl Write for DeadlineAgent {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        loop {
            if self
                .cancellation
                .as_ref()
                .is_some_and(crate::tasks::TaskCancellation::is_cancelled)
                || Instant::now() >= self.deadline
            {
                return self.wait().and(Err(io::Error::other("SSH agent stopped")));
            }
            match self.stream.write(buffer) {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => self.wait()?,
                result => return result,
            }
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn complete_agent_connect<Fd: std::os::fd::AsFd>(
    socket: &Fd,
    initial: rustix::io::Result<()>,
    deadline: Instant,
    cancellation: Option<&crate::tasks::TaskCancellation>,
) -> io::Result<()> {
    match initial {
        Ok(()) => return Ok(()),
        Err(rustix::io::Errno::INPROGRESS | rustix::io::Errno::ALREADY) => {}
        Err(error) => return Err(io::Error::from(error)),
    }
    loop {
        if cancellation.is_some_and(crate::tasks::TaskCancellation::is_cancelled) {
            return Err(io::Error::other("SSH cancelled"));
        }
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|time| !time.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "SSH deadline exceeded"))?;
        let timeout = remaining.min(Duration::from_millis(10));
        let timeout = rustix::event::Timespec {
            tv_sec: 0,
            tv_nsec: i64::from(timeout.subsec_nanos()),
        };
        let mut fds = [rustix::event::PollFd::new(
            socket,
            rustix::event::PollFlags::OUT,
        )];
        match rustix::event::poll(&mut fds, Some(&timeout)) {
            Ok(0) | Err(rustix::io::Errno::INTR) => {}
            Err(error) => return Err(io::Error::from(error)),
            Ok(_) => {
                // Poll readiness alone can also mean a failed connect.
                return rustix::net::sockopt::socket_error(socket)
                    .map_err(io::Error::from)?
                    .map_err(io::Error::from);
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn connect_agent_socket(
    path: &Path,
    deadline: Instant,
    cancellation: Option<&crate::tasks::TaskCancellation>,
) -> io::Result<std::os::unix::net::UnixStream> {
    use rustix::net::{
        AddressFamily, SocketAddrUnix, SocketFlags, SocketType, connect, socket_with,
    };
    let addr = SocketAddrUnix::new(path).map_err(io::Error::from)?;
    let socket = loop {
        if cancellation.is_some_and(crate::tasks::TaskCancellation::is_cancelled) {
            return Err(io::Error::other("SSH cancelled"));
        }
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|time| !time.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "SSH deadline exceeded"))?;
        let socket = socket_with(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
            None,
        )
        .map_err(io::Error::from)?;
        let initial = connect(&socket, &addr);
        // On Linux, a full Unix listener backlog means this socket did not
        // start connecting. Retry with a fresh socket, not SO_ERROR polling.
        if let Err(rustix::io::Errno::AGAIN | rustix::io::Errno::INTR) = initial {
            std::thread::sleep(remaining.min(Duration::from_millis(10)));
        } else {
            complete_agent_connect(&socket, initial, deadline, cancellation)?;
            break socket;
        }
    };
    Ok(std::os::unix::net::UnixStream::from(socket))
}

#[cfg(target_os = "linux")]
fn bounded_agent_methods(
    deadline: Instant,
    cancellation: Option<crate::tasks::TaskCancellation>,
) -> Result<Vec<ClientAuthMethod>, String> {
    let path = std::env::var_os("SSH_AUTH_SOCK")
        .filter(|path| !path.is_empty())
        .ok_or("SSH agent unavailable")?;
    let socket = connect_agent_socket(Path::new(&path), deadline, cancellation.as_ref())
        .map_err(|_| "SSH agent unavailable")?;
    let stream = DeadlineAgent {
        stream: socket,
        deadline,
        cancellation,
    };
    neotales_ssh::agent_auth_methods_from_client(
        neotales_ssh::agent::AgentClient::new(stream),
        DeadlineAgent::try_clone,
    )
    .map_err(|_| "SSH agent unavailable".into())
}

#[cfg(not(target_os = "linux"))]
fn bounded_agent_methods(
    _deadline: Instant,
    _cancellation: Option<crate::tasks::TaskCancellation>,
) -> Result<Vec<ClientAuthMethod>, String> {
    Err("bounded SSH agent is unavailable on this platform".into())
}

fn connect_sessions(
    endpoint: &Endpoint,
    timeout: Duration,
    cancellation: Option<crate::tasks::TaskCancellation>,
    console: Option<Console>,
    streaming: bool,
) -> Result<ClientSessions<neotales_ssh::ClientTransport<DeadlineStream>>, String> {
    if timeout.is_zero() || timeout > Duration::from_secs(3600) {
        return Err("SSH timeout must be positive and at most one hour".into());
    }
    if cancellation
        .as_ref()
        .is_some_and(crate::tasks::TaskCancellation::is_cancelled)
    {
        return Err("task cancelled".into());
    }
    let deadline = Instant::now() + timeout;
    let stream = TcpStream::connect_timeout(&endpoint.address, timeout)
        .map_err(|_| "SSH connection failed")?;
    let stream = DeadlineStream {
        stream,
        deadline,
        remaining: if streaming {
            usize::MAX
        } else {
            16 * 1024 * 1024
        },
        cancellation: cancellation.clone(),
        console,
    };
    let mut transport = ClientConfig::new()
        .connect(stream, |key| {
            if *key == endpoint.pin {
                Ok(())
            } else {
                Err(())
            }
        })
        .map_err(|_| "SSH handshake or host-key verification failed")?;
    let methods = match &endpoint.authentication {
        Authentication::Identity { path, passphrase } => {
            vec![
                neotales_ssh::identity_auth_method(
                    path,
                    passphrase.as_deref().map(String::as_bytes),
                )
                .map_err(|_| "SSH identity file is invalid or unavailable")?,
            ]
        }
        Authentication::Agent => bounded_agent_methods(deadline, cancellation)
            .map_err(|_| "SSH agent is unavailable or has no supported identities")?,
        Authentication::Password(password) => {
            vec![ClientAuthMethod::password(password.to_string())]
        }
    };
    // Public-key offers use one query and can use a second signed request.
    // Limit the number of agent identities before calculating the budget.
    if methods.len() > 32 {
        return Err("SSH agent has too many supported identities".into());
    }
    neotales_ssh::authenticate_client(&mut transport, &endpoint.user, &methods, methods.len() * 2)
        .map_err(|_| "SSH authentication failed")?;
    Ok(ClientSessions::new(transport))
}

fn connect(
    endpoint: &Endpoint,
    timeout: Duration,
) -> Result<SshClient<neotales_ssh::ClientTransport<DeadlineStream>>, String> {
    connect_sessions(endpoint, timeout, None, None, false)
        .map(SshClient::from_authenticated_sessions)
}

/// Executes an exact remote shell script, suppressing all output (it may contain
/// secrets). Returns the remote status. Overall deadline includes authentication;
/// disconnect does not promise to stop remote processes or roll back effects.
///
/// # Errors
/// Returns redacted errors. Caller must authorize before resolving/connecting.
pub fn execute(endpoint: &Endpoint, script: &str, timeout: Duration) -> Result<u32, String> {
    execute_inner(endpoint, script, timeout, None, None)
}

/// Console policy for one host. The caller supplies additional known secret
/// values; the endpoint's authentication password is always included.
pub struct ConsoleOptions<'a> {
    /// Display alias, safely escaped before prefixing output.
    pub alias: &'a str,
    /// Route both remote streams to stderr, preserving stdout for JSON.
    pub stderr_only: bool,
    /// Additional known nonempty secrets (see `GroupedOutput` limits).
    pub secrets: &'a [&'a str],
    /// Cooperative task cancellation, checked during packet I/O.
    pub cancellation: Option<crate::tasks::TaskCancellation>,
}

/// Executes with bounded, prefixed stdout/stderr groups and known-secret
/// redaction. Flushes final groups on every success/error/cancellation path.
/// Local writer backpressure is synchronous and not interruptible.
///
/// # Errors
/// Returns redacted configuration, transport or writer errors.
pub fn execute_console(
    endpoint: &Endpoint,
    script: &str,
    timeout: Duration,
    options: ConsoleOptions<'_>,
) -> Result<u32, String> {
    prepare_console(endpoint, options)?.execute(script, timeout)
}

/// Validated, endpoint-bound console state. Owns only bounded zeroizing
/// redaction patterns; never retains borrowed additional-secret values.
/// Construction performs no network or console writes. Drop wipes lookbehind.
/// One-shot: prepare the whole batch before consuming consoles in execution order.
pub struct PreparedConsole<'a> {
    endpoint: &'a Endpoint,
    console: Console,
    cancellation: Option<crate::tasks::TaskCancellation>,
}

impl PreparedConsole<'_> {
    /// Executes on the exact endpoint used during preparation, flushing output
    /// on success/error/cancellation. Never switches credentials after preflight.
    ///
    /// # Errors
    /// Returns redacted script, transport, timeout or writer errors.
    pub fn execute(self, script: &str, timeout: Duration) -> Result<u32, String> {
        let result = execute_inner(
            self.endpoint,
            script,
            timeout,
            self.cancellation.clone(),
            Some(&self.console),
        );
        let flushed = self.console.borrow_mut().finish();
        match result {
            Ok(status) => flushed.map(|()| status),
            Err(message) => Err(message),
        }
    }
}

/// Validates a host's complete output policy, including its authentication
/// password, before any effects. Additional secrets are borrowed and validated
/// before copying; at most 64 distinct 256-byte patterns are retained and wiped.
///
/// # Errors
/// Rejects over-budget/control-bearing secrets or invalid aliases without values.
pub fn prepare_console<'a>(
    endpoint: &'a Endpoint,
    options: ConsoleOptions<'_>,
) -> Result<PreparedConsole<'a>, String> {
    let values = options
        .secrets
        .iter()
        .copied()
        .chain(endpoint.authentication.secret());
    let console: Console = Rc::new(RefCell::new(GroupedOutput::from_values(
        options.alias,
        values,
        Box::new(io::stdout()) as Box<dyn Write>,
        Box::new(io::stderr()) as Box<dyn Write>,
        options.stderr_only,
    )?));
    Ok(PreparedConsole {
        endpoint,
        console,
        cancellation: options.cancellation,
    })
}

fn execute_inner(
    endpoint: &Endpoint,
    script: &str,
    timeout: Duration,
    cancellation: Option<crate::tasks::TaskCancellation>,
    console: Option<&Console>,
) -> Result<u32, String> {
    if script.is_empty() || script.len() > 1024 * 1024 || script.contains('\0') {
        return Err("SSH script must be nonempty and at most one MiB without NUL".into());
    }
    let mut sessions = connect_sessions(endpoint, timeout, cancellation, console.cloned(), true)?;
    run_streamed(&mut sessions, script, console)
        .map_err(|_| "SSH command failed or exceeded its deadline or console budget".into())
}

fn run_streamed(
    sessions: &mut ClientSessions<neotales_ssh::ClientTransport<DeadlineStream>>,
    script: &str,
    console: Option<&Console>,
) -> Result<u32, String> {
    use neotales_ssh::session::SessionEvent;
    let session = sessions.open_session().map_err(|_| "SSH session failed")?;
    match sessions.dispatch_one().map_err(|_| "SSH session failed")? {
        SessionEvent::Opened { session: opened } if opened == session => {}
        _ => return Err("SSH session failed".into()),
    }
    sessions
        .request_exec(session, script.as_bytes(), true)
        .map_err(|_| "SSH exec request failed")?;
    let mut status = None;
    loop {
        match sessions.dispatch_one().map_err(|_| "SSH packet failed")? {
            SessionEvent::Data { session: id, data } if id == session => {
                if let Some(console) = console {
                    console
                        .borrow_mut()
                        .push(OutputChannel::Stdout, &data, Instant::now())?;
                }
                sessions
                    .increase_local_window(
                        session,
                        u32::try_from(data.len()).map_err(|_| "SSH packet too large")?,
                    )
                    .map_err(|_| "SSH window failed")?;
            }
            SessionEvent::ExtendedData {
                session: id,
                data_type_code: 1,
                data,
            } if id == session => {
                if let Some(console) = console {
                    console
                        .borrow_mut()
                        .push(OutputChannel::Stderr, &data, Instant::now())?;
                }
                sessions
                    .increase_local_window(
                        session,
                        u32::try_from(data.len()).map_err(|_| "SSH packet too large")?,
                    )
                    .map_err(|_| "SSH window failed")?;
            }
            SessionEvent::ExitStatus {
                session: id,
                status: received,
            } if id == session => {
                status = Some(received);
            }
            SessionEvent::Eof { session: id } if id == session => {
                if let Some(console) = console {
                    console.borrow_mut().finish()?;
                }
            }
            SessionEvent::Close { session: id } if id == session => {
                return status.ok_or("SSH exited without a status".into());
            }
            SessionEvent::RequestSucceeded { session: id }
            | SessionEvent::WindowAdjusted { session: id, .. }
                if id == session => {}
            _ => return Err("SSH unexpected session event".into()),
        }
    }
}

/// Uploads one file (at most 8 MiB). Partial writes may remain after errors.
/// Remote paths are strict relative ASCII components, never shell expressions.
///
/// # Errors
/// Refuses unsafe paths and returns redacted transport errors.
pub fn upload(
    endpoint: &Endpoint,
    remote: &str,
    bytes: &[u8],
    timeout: Duration,
) -> Result<(), String> {
    validate_remote_path(remote)?;
    if bytes.len() > 8 * 1024 * 1024 {
        return Err("SCP file exceeds eight MiB".into());
    }
    connect(endpoint, timeout)?
        .upload(remote, bytes, |_| {})
        .map_err(|error| format!("SCP upload failed: {}", copy_error(error.as_ref())))
}

/// Downloads one file into memory under the transport's 16 MiB wire budget.
/// The shared SCP codec additionally bounds advertised file sizes.
///
/// # Errors
/// Refuses unsafe paths and returns redacted transport errors.
pub fn download(endpoint: &Endpoint, remote: &str, timeout: Duration) -> Result<Vec<u8>, String> {
    validate_remote_path(remote)?;
    connect(endpoint, timeout)?
        .download(remote, |_| {})
        .map_err(|error| format!("SCP download failed: {}", copy_error(error.as_ref())))
}

// Only these inspected typed errors contain static messages/enums and numeric
// protocol metadata. Never render arbitrary I/O or peer-provided cause strings.
fn copy_error(error: &(dyn std::error::Error + 'static)) -> String {
    if let Some(error) = error.downcast_ref::<neotales_ssh::session::SessionError>() {
        if matches!(error, neotales_ssh::session::SessionError::Channel(_)) {
            "SSH channel protocol or transport failed".into()
        } else {
            error.to_string()
        }
    } else if let Some(error) = error.downcast_ref::<neotales_ssh::scp::ScpError>() {
        format!("{error:?}")
    } else {
        "transport failed or exceeded deadline/size budget".into()
    }
}

/// Validates literal relative POSIX file paths without options, traversal,
/// whitespace, control characters, or shell metacharacters.
///
/// # Errors
/// Rejects paths outside the deliberately narrow SCP surface.
pub fn validate_remote_path(path: &str) -> Result<(), String> {
    if path.is_empty()
        || path.len() > 4096
        || path.split('/').any(|part| {
            part.is_empty()
                || part == "."
                || part == ".."
                || part.starts_with('-')
                || !part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
        })
    {
        return Err("SCP remote path must contain safe relative components".into());
    }
    Ok(())
}

/// Resolves an existing local file or a new destination within the canonical
/// project root. Rejects final symlinks and canonical parent escapes.
///
/// # Errors
/// Returns redacted errors for traversal, links and missing parents/files.
pub fn local_file(root: &Path, path: &str, destination: bool) -> Result<PathBuf, String> {
    let invalid = || "SCP local path must stay within the project without links".to_owned();
    let path = Path::new(path);
    if path.as_os_str().is_empty()
        || path
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err(invalid());
    }
    let root = root.canonicalize().map_err(|_| invalid())?;
    let candidate = root.join(path);
    let parent = candidate
        .parent()
        .ok_or_else(invalid)?
        .canonicalize()
        .map_err(|_| invalid())?;
    if !parent.starts_with(&root) {
        return Err(invalid());
    }
    let file = parent.join(candidate.file_name().ok_or_else(invalid)?);
    match std::fs::symlink_metadata(&file) {
        Ok(metadata) if !metadata.is_file() || metadata.file_type().is_symlink() => {
            return Err(invalid());
        }
        Ok(_) => {}
        Err(error) if destination && error.kind() == io::ErrorKind::NotFound => {}
        Err(_) => return Err(invalid()),
    }
    Ok(file)
}

#[cfg(test)]
mod authentication_selection_tests {
    use super::{Authentication, Endpoint, PathBuf};
    use neoenv_config::{Inventory, InventoryDefaults, InventoryHost};
    use std::collections::BTreeMap;

    #[cfg(target_os = "linux")]
    fn stalled_agent(
        timeout: std::time::Duration,
        cancellation: Option<crate::tasks::TaskCancellation>,
    ) -> (super::DeadlineAgent, std::os::unix::net::UnixStream) {
        let (stream, peer) = std::os::unix::net::UnixStream::pair().expect("fixture socket pair");
        stream.set_nonblocking(true).expect("nonblocking fixture");
        (
            super::DeadlineAgent {
                stream,
                deadline: std::time::Instant::now() + timeout,
                cancellation,
            },
            peer,
        )
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn pending_agent_connect_waits_for_readiness_and_checks_socket_error() {
        let (stream, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
        super::complete_agent_connect(
            &stream,
            Err(rustix::io::Errno::INPROGRESS),
            std::time::Instant::now() + std::time::Duration::from_secs(1),
            None,
        )
        .expect("pending fixture socket becomes writable with no socket error");
        assert!(
            super::complete_agent_connect(
                &stream,
                Err(rustix::io::Errno::CONNREFUSED),
                std::time::Instant::now() + std::time::Duration::from_secs(1),
                None,
            )
            .is_err()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn pending_connect_reports_socket_error_instead_of_accepting_poll_readiness() {
        use rustix::net::{AddressFamily, SocketFlags, SocketType, connect, socket_with};
        let reservation = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = reservation.local_addr().unwrap();
        drop(reservation);
        let socket = socket_with(
            AddressFamily::INET,
            SocketType::STREAM,
            SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
            None,
        )
        .unwrap();
        let initial = connect(&socket, &address);
        assert_eq!(initial, Err(rustix::io::Errno::INPROGRESS));
        let error = super::complete_agent_connect(
            &socket,
            initial,
            std::time::Instant::now() + std::time::Duration::from_secs(1),
            None,
        )
        .expect_err("refused connection must not pass on writability");
        assert_eq!(error.kind(), std::io::ErrorKind::ConnectionRefused);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn pending_agent_connect_obeys_deadline_and_cancellation() {
        use std::io::Write;
        let (mut stream, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
        stream.set_nonblocking(true).unwrap();
        let data = [0u8; 16384];
        loop {
            match stream.write(&data) {
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => panic!("fixture write: {error}"),
            }
        }
        let start = std::time::Instant::now();
        assert_eq!(
            super::complete_agent_connect(
                &stream,
                Err(rustix::io::Errno::INPROGRESS),
                start + std::time::Duration::from_millis(80),
                None,
            )
            .unwrap_err()
            .kind(),
            std::io::ErrorKind::TimedOut
        );
        assert!(start.elapsed() < std::time::Duration::from_secs(2));
        let cancellation = crate::tasks::TaskCancellation::new();
        let other = cancellation.clone();
        let thread = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(80));
            other.cancel();
        });
        let start = std::time::Instant::now();
        assert!(
            super::complete_agent_connect(
                &stream,
                Err(rustix::io::Errno::INPROGRESS),
                start + std::time::Duration::from_secs(3),
                Some(&cancellation),
            )
            .is_err()
        );
        assert!(start.elapsed() < std::time::Duration::from_secs(2));
        thread.join().unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn saturated_unix_agent_backlog_retries_until_released_or_stopped() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("agent.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        rustix::net::listen(&listener, 1).unwrap();
        let _first = std::os::unix::net::UnixStream::connect(&path).unwrap();
        let _second = std::os::unix::net::UnixStream::connect(&path).unwrap();
        let now = std::time::Instant::now();
        let error =
            super::connect_agent_socket(&path, now + std::time::Duration::from_millis(80), None)
                .expect_err("full backlog must wait for the deadline");
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert!(now.elapsed() < std::time::Duration::from_secs(2));
        let cancellation = crate::tasks::TaskCancellation::new();
        let trigger = cancellation.clone();
        let cancel = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(80));
            trigger.cancel();
        });
        let now = std::time::Instant::now();
        assert!(
            super::connect_agent_socket(
                &path,
                now + std::time::Duration::from_secs(3),
                Some(&cancellation)
            )
            .is_err()
        );
        assert!(now.elapsed() < std::time::Duration::from_secs(2));
        cancel.join().unwrap();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let release = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(80));
            let accepted = listener.accept().unwrap();
            done_rx
                .recv_timeout(std::time::Duration::from_secs(3))
                .unwrap();
            accepted
        });
        let now = std::time::Instant::now();
        let _connected =
            super::connect_agent_socket(&path, now + std::time::Duration::from_secs(2), None)
                .expect("connect retries after backlog space is released");
        assert!(now.elapsed() >= std::time::Duration::from_millis(50));
        done_tx.send(()).unwrap();
        release.join().unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn stalled_agent_enumeration_obeys_overall_deadline() {
        let (stream, _peer) = stalled_agent(std::time::Duration::from_millis(80), None);
        let start = std::time::Instant::now();
        assert!(
            neotales_ssh::agent_auth_methods_from_client(
                neotales_ssh::agent::AgentClient::new(stream),
                super::DeadlineAgent::try_clone,
            )
            .is_err()
        );
        assert!(start.elapsed() < std::time::Duration::from_secs(2));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn stalled_agent_enumeration_obeys_cancellation() {
        let cancellation = crate::tasks::TaskCancellation::new();
        let (stream, _peer) = stalled_agent(
            std::time::Duration::from_secs(3),
            Some(cancellation.clone()),
        );
        let cancel = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(80));
            cancellation.cancel();
        });
        let start = std::time::Instant::now();
        assert!(
            neotales_ssh::agent_auth_methods_from_client(
                neotales_ssh::agent::AgentClient::new(stream),
                super::DeadlineAgent::try_clone,
            )
            .is_err()
        );
        assert!(start.elapsed() < std::time::Duration::from_secs(2));
        cancel.join().expect("fixture cancellation thread");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn stalled_agent_signing_obeys_cancellation() {
        let cancellation = crate::tasks::TaskCancellation::new();
        let (stream, _peer) = stalled_agent(
            std::time::Duration::from_secs(3),
            Some(cancellation.clone()),
        );
        let blob = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            "AAAAC3NzaC1lZDI1NTE5AAAAINdamAGCsQq31Uv+08lkBzoO4XLz2qYjJa8CGmj3B1Ea",
        )
        .expect("fixture public key");
        let signer =
            neotales_ssh::AgentKeySigner::new(neotales_ssh::agent::AgentClient::new(stream), &blob)
                .expect("fixture signer");
        let cancel = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(80));
            cancellation.cancel();
        });
        let start = std::time::Instant::now();
        assert!(signer.sign(b"fixture message").is_err());
        assert!(start.elapsed() < std::time::Duration::from_secs(2));
        cancel.join().expect("fixture cancellation thread");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn stalled_agent_signing_obeys_overall_deadline() {
        let (stream, _peer) = stalled_agent(std::time::Duration::from_millis(80), None);
        let blob = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            "AAAAC3NzaC1lZDI1NTE5AAAAINdamAGCsQq31Uv+08lkBzoO4XLz2qYjJa8CGmj3B1Ea",
        )
        .expect("fixture public key");
        let signer =
            neotales_ssh::AgentKeySigner::new(neotales_ssh::agent::AgentClient::new(stream), &blob)
                .expect("fixture signer");
        let start = std::time::Instant::now();
        assert!(signer.sign(b"fixture message").is_err());
        assert!(start.elapsed() < std::time::Duration::from_secs(2));
    }

    fn fixture() -> Inventory {
        Inventory {
            hosts: indexmap::IndexMap::from([(
                "web".into(),
                InventoryHost {
                    address: Some("127.0.0.1".into()),
                    user: Some("fixture".into()),
                    host_key: Some(
                        "AAAAC3NzaC1lZDI1NTE5AAAAINdamAGCsQq31Uv+08lkBzoO4XLz2qYjJa8CGmj3B1Ea"
                            .into(),
                    ),
                    ..InventoryHost::default()
                },
            )]),
            order: vec!["web".into()],
            defaults: InventoryDefaults::default(),
        }
    }

    #[test]
    fn legacy_endpoint_resolve_signature_remains_available() {
        assert!(Endpoint::resolve(&fixture(), "web", &BTreeMap::new()).is_ok());
    }

    #[test]
    fn password_env_is_not_password_login_without_explicit_password_auth() {
        let mut inventory = fixture();
        inventory.hosts["web"].password_env = Some("LOGIN_PASSWORD".into());
        let environment = BTreeMap::from([("LOGIN_PASSWORD".into(), "fixture-only".into())]);
        assert!(matches!(
            Endpoint::resolve_with_root(
                &inventory,
                "web",
                &environment,
                std::path::Path::new("/project")
            )
            .expect("agent default does not need password env")
            .authentication,
            Authentication::Agent
        ));
        inventory.hosts["web"].password_auth = true;
        match Endpoint::resolve_with_root(
            &inventory,
            "web",
            &environment,
            std::path::Path::new("/project"),
        )
        .expect("explicit password mode")
        .authentication
        {
            Authentication::Password(secret) => assert_eq!(secret.as_str(), "fixture-only"),
            _ => panic!("explicit password mode must not select agent"),
        }
    }

    #[test]
    fn explicit_identity_file_wins_and_password_env_is_only_its_passphrase() {
        let mut inventory = fixture();
        inventory.defaults.identity_file = Some("fixture-key".into());
        inventory.hosts["web"].password_env = Some("KEY_PASSPHRASE".into());
        inventory.hosts["web"].password_auth = true;
        let environment = BTreeMap::from([("KEY_PASSPHRASE".into(), "fixture-passphrase".into())]);
        match Endpoint::resolve_with_root(
            &inventory,
            "web",
            &environment,
            std::path::Path::new("/project"),
        )
        .expect("identity mode")
        .authentication
        {
            Authentication::Identity { path, passphrase } => {
                assert_eq!(path, PathBuf::from("/project/fixture-key"));
                assert_eq!(
                    passphrase.as_deref().map(String::as_str),
                    Some("fixture-passphrase")
                );
            }
            _ => panic!("identity file must take precedence"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn identity_tilde_uses_explicit_fixture_home() {
        let mut inventory = fixture();
        inventory.defaults.identity_file = Some("~/.ssh/fixture".into());
        let environment = BTreeMap::from([("HOME".into(), "/fixture-home".into())]);
        match Endpoint::resolve_with_root(
            &inventory,
            "web",
            &environment,
            std::path::Path::new("/project"),
        )
        .expect("identity mode")
        .authentication
        {
            Authentication::Identity { path, .. } => {
                assert_eq!(path, PathBuf::from("/fixture-home/.ssh/fixture"));
            }
            _ => panic!("expected identity"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn identity_paths_are_resolved_against_project_and_reject_unsupported_homes() {
        use super::resolve_identity_path;
        let env = BTreeMap::from([("HOME".into(), "/fixture-home".into())]);
        let root = std::path::Path::new("/fixture-project");
        assert_eq!(
            resolve_identity_path("keys/id", &env, root).unwrap(),
            PathBuf::from("/fixture-project/keys/id")
        );
        assert_eq!(
            resolve_identity_path("/elsewhere/id", &env, root).unwrap(),
            PathBuf::from("/elsewhere/id")
        );
        assert_eq!(
            resolve_identity_path("~", &env, root).unwrap(),
            PathBuf::from("/fixture-home")
        );
        assert!(resolve_identity_path("~other/key", &env, root).is_err());
        assert!(resolve_identity_path("~//etc/key", &env, root).is_err());
        assert!(resolve_identity_path("~/key", &BTreeMap::new(), root).is_err());
        assert!(resolve_identity_path("../key", &env, root).is_err());
        assert!(resolve_identity_path("key", &env, std::path::Path::new("relative")).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn identity_grants_bind_resolved_home_and_project_without_disclosure() {
        let mut inventory = fixture();
        inventory.defaults.identity_file = Some("~/keys/fixture".into());
        let first = BTreeMap::from([("HOME".into(), "/fixture-home-one".into())]);
        let second = BTreeMap::from([("HOME".into(), "/fixture-home-two".into())]);
        let root = std::path::Path::new("/project-one");
        let a = super::endpoint_subject_with_context(&inventory, "web", &first, root).unwrap();
        let b = super::endpoint_subject_with_context(&inventory, "web", &second, root).unwrap();
        assert_ne!(a, b);
        #[allow(deprecated)]
        let ambiguous = super::endpoint_subject(&inventory, "web");
        assert_ne!(ambiguous, a);
        assert_ne!(ambiguous, b);
        assert!(!a.contains("fixture-home"));
        let endpoint = Endpoint::resolve(&inventory, "web", &first).unwrap();
        let cwd = std::env::current_dir().unwrap();
        assert_eq!(
            endpoint.subject(),
            super::endpoint_subject_with_context(&inventory, "web", &first, &cwd).unwrap()
        );
        assert_ne!(
            endpoint.subject(),
            super::endpoint_subject_with_context(&inventory, "web", &second, &cwd).unwrap()
        );
        inventory.defaults.identity_file = Some("keys/fixture".into());
        let a = super::endpoint_subject_with_context(&inventory, "web", &first, root).unwrap();
        inventory.defaults.identity_file = Some("keys/./fixture".into());
        assert_eq!(
            a,
            super::endpoint_subject_with_context(&inventory, "web", &first, root).unwrap()
        );
        let b = super::endpoint_subject_with_context(
            &inventory,
            "web",
            &first,
            std::path::Path::new("/project-two"),
        )
        .unwrap();
        assert_ne!(a, b);
        assert!(!a.contains("project-one"));
    }

    #[cfg(unix)]
    #[test]
    fn legacy_identity_sentinel_cannot_authorize_unrelated_endpoints() {
        let mut inventory = fixture();
        inventory.hosts["web"].identity_file = Some("~/one".into());
        let mut other = inventory.hosts["web"].clone();
        other.identity_file = Some("~/two".into());
        inventory.hosts.insert("other".into(), other);
        let environment = BTreeMap::from([("HOME".into(), "/fixture-home".into())]);
        let root = std::path::Path::new("/fixture-project");
        let sentinel = neoenv_policy::RESERVED_SSH_IDENTITY_SUBJECT;
        for name in ["web", "other"] {
            #[allow(deprecated)]
            let legacy = super::endpoint_subject(&inventory, name);
            assert_eq!(legacy, sentinel);
            let endpoint =
                Endpoint::resolve_with_root(&inventory, name, &environment, root).unwrap();
            assert_ne!(endpoint.subject(), sentinel);
            assert!(
                !neoenv_policy::CapabilityGrants::default()
                    .authorizes(neoenv_policy::Capability::Connect, &legacy)
            );
        }
        let document = format!("[[grants]]\nsubject = {sentinel:?}\ncapability = 'connect'\n");
        assert!(neoenv_policy::CapabilityGrants::from_toml(&document).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn identity_files_must_be_regular_private_and_bounded() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("fixture-key");
        std::fs::write(&path, b"fixture-only").expect("fixture key");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("private mode");
        assert!(
            neotales_ssh::identity_auth_method(&path, None)
                .expect_err("invalid fixture key")
                .to_string()
                .contains("invalid")
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
            .expect("permissive mode");
        assert_eq!(
            neotales_ssh::identity_auth_method(&path, None)
                .expect_err("permissive identity")
                .to_string(),
            "identity file permissions must be private"
        );
        let linked = directory.path().join("link");
        symlink(&path, &linked).expect("fixture link");
        assert!(neotales_ssh::identity_auth_method(&linked, None).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("private mode");
        std::fs::write(&path, vec![0; 1024 * 1024 + 1]).expect("oversized fixture");
        assert!(
            neotales_ssh::identity_auth_method(&path, None)
                .expect_err("oversized identity")
                .to_string()
                .contains("no larger than one MiB")
        );
        assert!(neotales_ssh::identity_auth_method(directory.path(), None).is_err());
    }
}
