//! A real `rhypedb-server` for integration tests.
//!
//! Tests run against the same server and schema production uses, not a fake.
//! The binary comes from `RHYPEDB_SERVER_BIN`, else `rhypedb-server` on
//! `PATH`; install the pinned version with `scripts/install-rhypedb.sh`. A
//! missing binary fails the test with instructions; it never skips.

use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// A running server in its own temporary data directory.
pub struct RhypeServer {
    child: Option<Child>,
    dir: tempfile::TempDir,
    http_port: u16,
    tcp_port: u16,
}

fn binary() -> PathBuf {
    std::env::var_os("RHYPEDB_SERVER_BIN")
        .map_or_else(|| PathBuf::from("rhypedb-server"), PathBuf::from)
}

fn schema_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../schema.rhype")
}

/// Ports are drawn at random from below Linux's ephemeral range
/// (32768–60999). A port from `bind(0)` is soon handed out again, and many
/// test processes start servers at once, so two of them would often pick
/// the same one.
const PORTS: std::ops::Range<u32> = 20_000..32_000;

/// How many times to try fresh ports before giving up.
const START_ATTEMPTS: u32 = 8;

/// Where the listener's owner can't be checked (not Linux): how long a
/// server must stay up after its port accepts a connection to count as
/// ours. One that lost the port to another test's server exits with
/// "address already in use" while the other server answers.
#[cfg(not(target_os = "linux"))]
const BIND_GRACE: Duration = Duration::from_millis(150);

/// Whether process `pid` holds the socket listening on 127.0.0.1:`port`:
/// the listener's inode from `/proc/net/tcp` is among its open files.
#[cfg(target_os = "linux")]
fn listener_is_ours(pid: u32, port: u16) -> bool {
    let Ok(table) = std::fs::read_to_string("/proc/net/tcp") else {
        return false;
    };
    let local = format!("0100007F:{port:04X}");
    let sockets: Vec<String> = table
        .lines()
        .skip(1)
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            // Fields: sl, local, remote, state (0A = LISTEN), …, inode (10th).
            (f.get(1) == Some(&local.as_str()) && f.get(3) == Some(&"0A"))
                .then(|| f.get(9).map(|inode| format!("socket:[{inode}]")))
                .flatten()
        })
        .collect();
    let Ok(fds) = std::fs::read_dir(format!("/proc/{pid}/fd")) else {
        return false;
    };
    fds.flatten().any(|fd| {
        std::fs::read_link(fd.path())
            .is_ok_and(|target| sockets.iter().any(|s| target.as_os_str() == s.as_str()))
    })
}

fn free_port() -> u16 {
    loop {
        let n = getrandom::u32().expect("random source");
        let port = (PORTS.start + n % (PORTS.end - PORTS.start)) as u16;
        if TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
}

impl RhypeServer {
    /// Start a server with the repository's `schema.rhype`.
    pub fn start() -> Self {
        let mut s = Self {
            child: None,
            dir: tempfile::tempdir().expect("tempdir"),
            http_port: 0,
            tcp_port: 0,
        };
        for _ in 0..START_ATTEMPTS {
            s.http_port = free_port();
            s.tcp_port = free_port();
            if s.tcp_port == s.http_port {
                continue;
            }
            if s.spawn() {
                return s;
            }
            // Lost a port to a concurrent test; nothing was written.
            s.stop();
        }
        panic!("rhypedb-server would not start:\n{}", s.log());
    }

    /// Start the server on this instance's ports; `false` if it exited
    /// (it could not bind them).
    fn spawn(&mut self) -> bool {
        let bin = binary();
        let child = Command::new(&bin)
            .arg("--schema")
            .arg(schema_path())
            .arg("--data-dir")
            .arg(self.dir.path().join("data"))
            .arg("--listen")
            .arg(format!("127.0.0.1:{}", self.http_port))
            .arg("--tcp-listen")
            .arg(self.tcp_addr())
            .arg("--no-sync")
            .stdout(Stdio::null())
            .stderr(
                std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(self.dir.path().join("server.log"))
                    .map_or_else(|_| Stdio::null(), Stdio::from),
            )
            .spawn()
            .unwrap_or_else(|e| {
                panic!(
                    "cannot start {} ({e}). Install the pinned server with \
                     scripts/install-rhypedb.sh and put it on PATH, or set \
                     RHYPEDB_SERVER_BIN",
                    bin.display()
                )
            });
        self.child = Some(child);
        self.wait_ready()
    }

    /// Whether the child has exited.
    fn exited(&mut self) -> bool {
        self.child
            .as_mut()
            .is_none_or(|c| !matches!(c.try_wait(), Ok(None)))
    }

    /// Whether *this* server is listening on its binary-protocol port
    /// (not another test's server that took the port).
    #[cfg(target_os = "linux")]
    fn listening(&mut self) -> bool {
        self.child
            .as_ref()
            .is_some_and(|c| listener_is_ours(c.id(), self.tcp_port))
    }

    /// Whether this server is listening: its port accepts connections and
    /// it is still running [`BIND_GRACE`] later.
    #[cfg(not(target_os = "linux"))]
    fn listening(&mut self) -> bool {
        if std::net::TcpStream::connect(self.tcp_addr()).is_err() {
            return false;
        }
        std::thread::sleep(BIND_GRACE);
        !self.exited()
    }

    /// Wait until this server listens on its port; `false` if it exited
    /// first (it lost a port to another test).
    fn wait_ready(&mut self) -> bool {
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            if self.exited() {
                return false;
            }
            if self.listening() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        panic!(
            "rhypedb-server did not start listening on {}",
            self.tcp_addr()
        );
    }

    /// The binary-protocol address.
    pub fn tcp_addr(&self) -> String {
        format!("127.0.0.1:{}", self.tcp_port)
    }

    /// Stop the server (data is kept).
    pub fn stop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }

    /// Start it again on the same ports and data.
    pub fn restart(&mut self) {
        self.stop();
        assert!(
            self.spawn(),
            "rhypedb-server did not restart on its ports:\n{}",
            self.log()
        );
    }
}

impl RhypeServer {
    /// The server's stderr so far (for diagnosing a failing test).
    pub fn log(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("server.log")).unwrap_or_default()
    }
}

impl Drop for RhypeServer {
    fn drop(&mut self) {
        self.stop();
    }
}
